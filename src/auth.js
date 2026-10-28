// Vanishly - optional sign-in (AUTH_PROVIDER=entra or oidc): OpenID Connect
// login, sessions, API bearer tokens and the recipient check.
//
// Keys (below REDIS_PREFIX):
//   sess:<sha256 of the cookie>  hash  name user ids created; expires with the session
//   oidc:<state>                 hash  PKCE verifier, nonce, return path; 10 minutes
// Recipients are stored as HMAC-SHA256(AUTH_SECRET, "u:<address>" | "g:<group>"),
// so Redis holds neither the addresses nor the groups a secret is for. A
// signed-in user carries the same hashes of their addresses and groups; a
// secret opens when the two lists share one.

import { createHash, createHmac, randomBytes } from 'node:crypto';
import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

/** @typedef {NonNullable<import('./config.js').Config['auth']>} AuthConfig */
/**
 * @typedef {{ name: string, user: string, ids: string[], app?: boolean }} User
 * ids: the recipient hashes this user matches (addresses and groups)
 */

const EMAIL = /^[^\s@<>"',;]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const STATE_TTL = 600;
// Paths a login may return to: the home page, a secret, a receipt.
const RETURN = /^\/((s|r)\/[A-Za-z0-9_-]{22})?$/;

/** @param {string} v */
function sha256(v) {
  return createHash('sha256').update(v).digest('base64url');
}

/**
 * @param {unknown} v
 * @returns {string[]}
 */
function strings(v) {
  return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
}

export class Auth {
  /**
   * @param {AuthConfig} cfg
   * @param {{ redis: any, p: string }} store
   * @param {{ fetch?: typeof fetch }} [opts] fetch for Graph (tests)
   */
  constructor(cfg, store, opts = {}) {
    this.c = cfg;
    this.redis = store.redis;
    this.p = store.p;
    this.fetch = opts.fetch || fetch;
    this.secure = cfg.redirectUri.startsWith('https:');
    // __Host-: only over HTTPS, then the browser binds the cookie to this host and path /.
    this.cookie = this.secure ? '__Host-vanishly-session' : 'vanishly-session';
    /** @type {Promise<client.Configuration> | null} */
    this.discovered = null;
    /** @type {ReturnType<typeof createRemoteJWKSet> | null} */
    this.jwks = null;
    /** @type {{ token: string, until: number } | null} */
    this.graphToken = null;
    /** @type {Map<string, { ids: string[], until: number }>} groups of API callers, 5 minutes */
    this.groupCache = new Map();
    /** @type {Map<string, { people: { name: string, user: string, mail: string }[], until: number }>} people search, 1 minute */
    this.peopleCache = new Map();
  }

  /** The provider's settings, fetched once (again after a failure). */
  oidc() {
    if (!this.discovered) {
      const insecure = this.c.issuer.startsWith('http:') ? { execute: [client.allowInsecureRequests] } : undefined;
      this.discovered = client
        .discovery(new URL(this.c.issuer), this.c.clientId, this.c.clientSecret, undefined, { timeout: 10, ...insecure })
        .catch((err) => {
          this.discovered = null;
          throw err;
        });
    }
    return this.discovered;
  }

  /**
   * The hash a recipient is stored as.
   * @param {'u' | 'g'} kind
   * @param {string} value address (lower-cased here) or group
   */
  hash(kind, value) {
    const v = kind === 'u' ? value.trim().toLowerCase() : value.trim();
    return createHmac('sha256', this.c.secret).update(`${kind}:${v}`).digest('base64url').slice(0, 32);
  }

  /** @param {string} v */
  static validEmail(v) {
    return typeof v === 'string' && v.length <= 254 && EMAIL.test(v.trim().toLowerCase());
  }

  /** @param {string} email */
  domainAllowed(email) {
    if (!this.c.domains.length) return true;
    const d = email.trim().toLowerCase().split('@')[1];
    return this.c.domains.includes(d);
  }

  /** @param {string} group */
  groupAllowed(group) {
    if (this.c.groups.any) return /^[0-9a-f-]{36}$/i.test(group);
    return this.c.groups.list.some((g) => g.id === (this.c.provider === 'entra' ? group.toLowerCase() : group));
  }

  /**
   * The recipient hashes of a user from the claims of an ID or access token.
   * @param {Record<string, any>} claims
   * @returns {Promise<User>}
   */
  async identity(claims) {
    if (this.c.provider === 'entra' && String(claims.tid || '').toLowerCase() !== this.c.tenant) {
      throw new Error('token from another tenant');
    }
    // Only names the account cannot choose itself. Entra: the UPN and the
    // sign-in name are set by the tenant; "email" only when Entra verified
    // its domain (xms_edov). Other providers: "email" unless they call it
    // unverified; preferred_username is often free to pick there.
    const names =
      this.c.provider === 'entra'
        ? [claims.preferred_username, claims.upn, claims.unique_name, claims.xms_edov === true || claims.xms_edov === '1' ? claims.email : '']
        : [claims.email_verified === false || claims.email_verified === 'false' ? '' : claims.email];
    const user = names.filter((v) => typeof v === 'string' && Auth.validEmail(v)).map((v) => v.trim().toLowerCase());
    const ids = [...new Set(user)].map((u) => this.hash('u', u));
    const groups = await this.groupsOf(claims);
    for (const g of groups) ids.push(this.hash('g', g));
    const name = typeof claims.name === 'string' && claims.name.trim() ? claims.name.trim() : user[0] || '';
    return { name: name.slice(0, 100), user: user[0] || '', ids };
  }

  /**
   * The groups of a user that matter here: all with RECIPIENT_GROUPS=*,
   * otherwise only the listed ones. From the "groups" claim; with Entra and
   * ENTRA_GRAPH=true from Graph when the token has none or too many (overage).
   * @param {Record<string, any>} claims
   */
  async groupsOf(claims) {
    const { any, list } = this.c.groups;
    if (!any && !list.length) return [];
    let groups = strings(claims.groups);
    const overage = Boolean(claims._claim_names?.groups || claims.hasgroups);
    if (this.c.graph && typeof claims.oid === 'string' && (overage || !Array.isArray(claims.groups))) {
      const cached = this.groupCache.get(claims.oid);
      if (cached && cached.until > Date.now()) groups = cached.ids;
      else {
        groups = await this.graphMemberGroups(claims.oid);
        this.groupCache.set(claims.oid, { ids: groups, until: Date.now() + 300000 });
        if (this.groupCache.size > 1000) this.groupCache.delete(this.groupCache.keys().next().value || '');
      }
    }
    if (this.c.provider === 'entra') groups = groups.map((g) => g.toLowerCase());
    return any ? groups : groups.filter((g) => list.some((l) => l.id === g));
  }

  // ------------------------------------------------------------ Graph (Entra)
  /** An app-only token for Graph (client credentials: GroupMember.Read.All, with the people search also User.Read.All). */
  async graphAccess() {
    if (this.graphToken && this.graphToken.until > Date.now()) return this.graphToken.token;
    const t = await client.clientCredentialsGrant(await this.oidc(), { scope: `${this.c.graphUrl}/.default` });
    this.graphToken = { token: t.access_token, until: Date.now() + Math.max(60, (t.expires_in || 3600) - 120) * 1000 };
    return t.access_token;
  }

  /**
   * @param {string} path below /v1.0
   * @param {RequestInit} [init]
   */
  async graph(path, init = {}) {
    const res = await this.fetch(`${this.c.graphUrl}/v1.0${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${await this.graphAccess()}`, 'Content-Type': 'application/json', ...init.headers },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`Graph answered ${res.status}`);
    return /** @type {any} */ (await res.json());
  }

  /** @param {string} oid */
  async graphMemberGroups(oid) {
    if (!/^[0-9a-f-]{36}$/i.test(oid)) return [];
    const r = await this.graph(`/users/${oid}/getMemberGroups`, {
      method: 'POST',
      body: JSON.stringify({ securityEnabledOnly: false }),
    });
    return strings(r.value);
  }

  /**
   * Groups whose name starts with q (RECIPIENT_GROUPS=*), at most 10.
   * @param {string} q
   * @returns {Promise<{ id: string, name: string }[]>}
   */
  async searchGroups(q) {
    const term = q.replace(/["\\]/g, '').trim().slice(0, 64);
    if (term.length < 2) return [];
    const params = new URLSearchParams({
      $search: `"displayName:${term}"`,
      $select: 'id,displayName',
      $top: '10',
      $orderby: 'displayName',
    });
    const r = await this.graph(`/groups?${params}`, { headers: { ConsistencyLevel: 'eventual' } });
    return (Array.isArray(r.value) ? r.value : [])
      .filter((/** @type {any} */ g) => typeof g?.id === 'string' && typeof g?.displayName === 'string')
      .map((/** @type {any} */ g) => ({ id: g.id.toLowerCase(), name: g.displayName }));
  }

  /**
   * Members of RECIPIENT_USER_GROUP (also through nested groups) whose name,
   * mail or user name starts with q, at most 10. "user" is the address the
   * person signs in with, so it matches identity(): the UPN, for guests
   * (#EXT#) their mail. Answers are kept for a minute.
   * @param {string} q
   * @returns {Promise<{ name: string, user: string, mail: string }[]>}
   */
  async searchPeople(q) {
    const term = q.replace(/["\\]/g, '').trim().toLowerCase().slice(0, 64);
    if (term.length < 2 || !this.c.userGroup) return [];
    const cached = this.peopleCache.get(term);
    if (cached && cached.until > Date.now()) return cached.people;
    const params = new URLSearchParams({
      $search: ['displayName', 'mail', 'userPrincipalName'].map((f) => `"${f}:${term}"`).join(' OR '),
      $select: 'displayName,mail,userPrincipalName',
      $top: '10',
      $count: 'true',
    });
    const r = await this.graph(`/groups/${this.c.userGroup}/transitiveMembers/microsoft.graph.user?${params}`, {
      headers: { ConsistencyLevel: 'eventual' },
    });
    const people = [];
    for (const u of Array.isArray(r.value) ? r.value : []) {
      const upn = typeof u?.userPrincipalName === 'string' ? u.userPrincipalName.trim().toLowerCase() : '';
      const mail = typeof u?.mail === 'string' ? u.mail.trim().toLowerCase() : '';
      const user = upn.includes('#ext#') ? mail : upn;
      if (!Auth.validEmail(user) || people.some((p) => p.user === user)) continue;
      const name = typeof u.displayName === 'string' && u.displayName.trim() ? u.displayName.trim().slice(0, 100) : user;
      people.push({ name, user, mail: Auth.validEmail(mail) ? mail : '' });
    }
    people.sort((a, b) => a.name.localeCompare(b.name));
    this.peopleCache.set(term, { people, until: Date.now() + 60000 });
    if (this.peopleCache.size > 500) this.peopleCache.delete(this.peopleCache.keys().next().value || '');
    return people;
  }

  // ------------------------------------------------------------ login
  /**
   * Starts a login: remembers state, nonce and PKCE verifier, returns the
   * provider's address to send the browser to.
   * @param {string} returnTo
   */
  async loginUrl(returnTo) {
    const cfg = await this.oidc();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const verifier = client.randomPKCECodeVerifier();
    const key = `${this.p}oidc:${state}`;
    await this.redis
      .multi()
      .hSet(key, { v: verifier, n: nonce, r: RETURN.test(returnTo) ? returnTo : '/' })
      .expire(key, STATE_TTL)
      .exec();
    return client.buildAuthorizationUrl(cfg, {
      redirect_uri: this.c.redirectUri,
      scope: this.c.provider === 'entra' ? 'openid profile email' : this.c.scopes,
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
      response_mode: 'query',
    }).href;
  }

  /**
   * Finishes a login: checks state, code, nonce and the ID token, creates
   * the session. The state is used once.
   * @param {string} search the query string of the callback ("?code=...&state=...")
   * @returns {Promise<{ sid: string, returnTo: string }>}
   */
  async callback(search) {
    const params = new URLSearchParams(search);
    const state = params.get('state') || '';
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(state)) throw new Error('missing state');
    const key = `${this.p}oidc:${state}`;
    const [saved] = /** @type {[Record<string, string>]} */ (/** @type {unknown} */ (await this.redis.multi().hGetAll(key).del(key).exec()));
    if (!saved?.v) throw new Error('unknown or expired login');
    const cfg = await this.oidc();
    const tokens = await client.authorizationCodeGrant(cfg, new URL(`${this.c.redirectUri}${search}`), {
      pkceCodeVerifier: saved.v,
      expectedState: state,
      expectedNonce: saved.n,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error('no ID token');
    const who = await this.identity(claims);
    if (!who.ids.length) throw new Error('the account has no e-mail address or user name');
    return { sid: await this.createSession(who), returnTo: saved.r || '/' };
  }

  /** @param {User} who */
  async createSession(who) {
    const sid = randomBytes(32).toString('base64url');
    const key = `${this.p}sess:${sha256(sid)}`;
    await this.redis
      .multi()
      .hSet(key, { name: who.name, user: who.user, ids: who.ids.join(' '), created: String(Date.now()) })
      .expire(key, this.c.sessionTtl)
      .exec();
    return sid;
  }

  /** @param {import('express').Request} req */
  sid(req) {
    const m = new RegExp(`(?:^|;\\s*)${this.cookie.replace(/[-_]/g, '\\$&')}=([A-Za-z0-9_-]{43})(?:;|$)`).exec(req.headers.cookie || '');
    return m ? m[1] : '';
  }

  /** @param {import('express').Response} res @param {string} sid */
  setCookie(res, sid) {
    res.cookie(this.cookie, sid, {
      httpOnly: true,
      secure: this.secure,
      sameSite: 'lax',
      path: '/',
      maxAge: this.c.sessionTtl * 1000,
    });
  }

  /** @param {import('express').Request} req @param {import('express').Response} res */
  async logout(req, res) {
    const sid = this.sid(req);
    if (sid) await this.redis.del(`${this.p}sess:${sha256(sid)}`);
    res.clearCookie(this.cookie, { httpOnly: true, secure: this.secure, sameSite: 'lax', path: '/' });
  }

  /**
   * Who sends this request: the session cookie or, on the API with
   * AUTH_API_AUDIENCE, a bearer token. null = nobody signed in.
   * A cookie on a cross-site request does not count (CSRF).
   * @param {import('express').Request} req
   * @returns {Promise<User | null>}
   */
  async user(req) {
    const bearer = /^Bearer ([\w.~+/-]+=*)$/i.exec(req.get('authorization') || '')?.[1];
    if (bearer) return this.c.apiAudience ? this.bearer(bearer) : null;
    const sid = this.sid(req);
    if (!sid) return null;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const site = req.get('sec-fetch-site');
      const origin = req.get('origin');
      if ((site && site !== 'same-origin') || (origin && origin !== new URL(this.c.redirectUri).origin)) return null;
    }
    const h = await this.redis.hGetAll(`${this.p}sess:${sha256(sid)}`);
    if (!h?.ids) return null;
    return { name: h.name, user: h.user, ids: h.ids.split(' ').filter(Boolean) };
  }

  /**
   * Checks an access token for AUTH_API_AUDIENCE: signature (the provider's
   * keys), issuer, audience, expiry, with Entra the tenant.
   * @param {string} token
   * @returns {Promise<User | null>}
   */
  async bearer(token) {
    try {
      const cfg = await this.oidc();
      const meta = cfg.serverMetadata();
      if (!this.jwks) this.jwks = createRemoteJWKSet(new URL(String(meta.jwks_uri)));
      const issuers = [meta.issuer];
      // Entra v1 access tokens (accessTokenAcceptedVersion 1) have the old issuer.
      if (this.c.provider === 'entra') issuers.push(`https://sts.windows.net/${this.c.tenant}/`);
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: issuers,
        audience: this.c.apiAudience,
        algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'ES256'],
        clockTolerance: 60,
      });
      // An app (client credentials) has no user: it may create, not open restricted secrets.
      if (payload.idtyp === 'app' || (!payload.preferred_username && !payload.upn && !payload.email && !payload.unique_name)) {
        if (this.c.provider === 'entra' && String(payload.tid || '').toLowerCase() !== this.c.tenant) return null;
        return { name: String(payload.azp || payload.appid || 'app'), user: '', ids: [], app: true };
      }
      return await this.identity(payload);
    } catch {
      return null;
    }
  }

  /**
   * True when a signed-in user is one of the recipients.
   * @param {User | null} user
   * @param {string[]} to
   */
  static allowed(user, to) {
    return Boolean(user && user.ids.some((id) => to.includes(id)));
  }
}

export { RETURN };
