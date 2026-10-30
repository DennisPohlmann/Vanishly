// Vanishly - optional sign-in (AUTH_PROVIDER=entra, oidc or a preset such as
// keycloak, okta, google): OpenID Connect login, sessions, API bearer tokens
// and the recipient check. People and group search: src/directory/.
//
// Keys (below REDIS_PREFIX):
//   sess:<sha256 of the cookie>  hash  name user ids created, it (the ID token, only
//                                      with AUTH_LOGOUT=provider); expires with the session
//   oidc:<state>                 hash  PKCE verifier, nonce, return path; 10 minutes
// Recipients are stored as HMAC-SHA256(AUTH_SECRET, "u:<address>" | "g:<group>"),
// so Redis holds neither the addresses nor the groups a secret is for. A
// signed-in user carries the same hashes of their addresses and groups; a
// secret opens when the two lists share one.

import { createHash, createHmac, randomBytes } from 'node:crypto';
import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { groupValue } from './config.js';
import { createDirectory } from './directory/index.js';

/** @typedef {NonNullable<import('./config.js').Config['auth']>} AuthConfig */
/**
 * @typedef {{ name: string, user: string, ids: string[], app?: boolean,
 *   token?: { id: string, name: string, scopes: string[] }, service?: string }} User
 * ids: the recipient hashes this user matches (addresses and groups);
 * token: set when the request came with an API token (src/tokens.js); service: the
 * technical user it belongs to (then user is "svc:<name>")
 */

const EMAIL = /^[^\s@<>"',;]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const STATE_TTL = 600;
// Paths a login may return to: the home page, a secret, a receipt, the
// API token page, the admin page.
const RETURN = /^\/((s|r)\/[A-Za-z0-9_-]{22}|settings\/tokens|admin)?$/;

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
   * @param {{ fetch?: typeof fetch }} [opts] fetch for the directory (tests)
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
    this.directory = createDirectory(cfg, { fetch: this.fetch, oidc: () => this.oidc() });
    /** @type {string} origins of the provider for form-action (see csp()) */
    this.formOrigins = '';
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
    const v = kind === 'u' ? value.trim().toLowerCase() : this.group(value);
    return createHmac('sha256', this.c.secret).update(`${kind}:${v}`).digest('base64url').slice(0, 32);
  }

  /**
   * A group value as compared and hashed: Entra ids and Google addresses in
   * lower case, Keycloak groups as paths.
   * @param {string} g
   */
  group(g) {
    return groupValue(g, this.c.lowerGroups, this.c.groupPaths);
  }

  /**
   * The page CSP with the provider in form-action: "Sign out" and "another
   * account" are forms whose answer redirects to the provider, and browsers
   * check form-action on those redirects too.
   * @param {string} csp
   */
  csp(csp) {
    if (!this.formOrigins) {
      this.formOrigins = new URL(this.c.issuer).origin;
      this.oidc()
        .then((cfg) => {
          const end = cfg.serverMetadata().end_session_endpoint;
          const authz = cfg.serverMetadata().authorization_endpoint;
          const extra = [end, authz].filter((u) => typeof u === 'string' && /^https?:\/\//.test(u)).map((u) => new URL(String(u)).origin);
          this.formOrigins = [...new Set([this.formOrigins, ...extra])].join(' ');
        })
        .catch(() => {});
    }
    return csp.replace("form-action 'self'", `form-action 'self' ${this.formOrigins}`);
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
    if (this.c.groups.any) {
      return this.c.provider === 'entra' ? /^[0-9a-f-]{36}$/i.test(group) : group.trim().length > 0 && group.length <= 200 && !/[\x00-\x1f]/.test(group);
    }
    return this.c.groups.list.some((g) => g.id === this.group(group));
  }

  /**
   * AUTH_ALLOWED_DOMAINS: only accounts of these domains sign in. With Google
   * the Workspace domain (hd) must match too, so a private Google account
   * with an address of the domain is not enough.
   * @param {Record<string, any>} claims
   * @param {string} user the address from identity()
   */
  signInAllowed(claims, user) {
    const d = this.c.allowedDomains;
    if (!d.length) return true;
    if (!user || !d.includes(user.split('@')[1])) return false;
    return this.c.provider !== 'google' || (typeof claims.hd === 'string' && d.includes(claims.hd.toLowerCase()));
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
    if (!this.signInAllowed(claims, user[0] || '')) throw new Error('account of a domain that may not sign in');
    const ids = [...new Set(user)].map((u) => this.hash('u', u));
    const groups = await this.groupsOf(claims);
    for (const g of groups) ids.push(this.hash('g', g));
    const name = typeof claims.name === 'string' && claims.name.trim() ? claims.name.trim() : user[0] || '';
    return { name: name.slice(0, 100), user: user[0] || '', ids };
  }

  /**
   * The groups of a user that matter here: all with RECIPIENT_GROUPS=*,
   * otherwise only the listed ones. From the groups claim (OIDC_GROUPS_CLAIM);
   * from the directory where the token has none: Entra with ENTRA_GRAPH=true
   * (no claim or overage), Google with DIRECTORY_API=true.
   * @param {Record<string, any>} claims
   */
  async groupsOf(claims) {
    const { any, list } = this.c.groups;
    // Admin and token groups (ADMIN_GROUPS, API_TOKEN_GROUPS) count too.
    const extra = this.c.extraGroups || [];
    // API_TOKEN_ADMIN_POLICY: admins may set token policies for any group, so all count.
    const all = any || Boolean(this.c.tokens?.adminPolicy);
    if (!all && !list.length && !extra.length) return [];
    const claim = this.c.groupsClaim ? claims[this.c.groupsClaim] : undefined;
    let groups = typeof claim === 'string' ? [claim] : strings(claim);
    const key = String(claims.oid || claims.sub || '');
    if (this.directory && key) {
      const cached = this.groupCache.get(key);
      if (cached && cached.until > Date.now()) groups = cached.ids;
      else {
        const found = await this.directory.groupsOf(claims);
        if (found) {
          groups = found;
          this.groupCache.set(key, { ids: groups, until: Date.now() + 300000 });
          if (this.groupCache.size > 1000) this.groupCache.delete(this.groupCache.keys().next().value || '');
        }
      }
    }
    groups = groups.map((g) => this.group(g)).filter(Boolean);
    return all ? groups : groups.filter((g) => list.some((l) => l.id === g) || extra.includes(g));
  }

  /**
   * ADMIN_USERS / ADMIN_GROUPS: may read the audit log and manage all tokens.
   * Not through an API token or an app.
   * @param {User | null} user
   */
  isAdmin(user) {
    if (!user?.user || user.app || user.token) return false;
    const { users, groups } = this.c.admin;
    return users.includes(user.user) || groups.some((g) => user.ids.includes(this.hash('g', g)));
  }

  // ------------------------------------------------------------ directory
  /**
   * Groups whose name starts with q (RECIPIENT_GROUPS=*), at most 10.
   * @param {string} q
   * @returns {Promise<{ id: string, name: string }[]>}
   */
  async searchGroups(q) {
    const term = q.replace(/["\\]/g, '').trim().toLowerCase().slice(0, 64);
    if (term.length < 2 || !this.directory || !this.c.groups.any) return [];
    const found = await this.directory.searchGroups(term);
    /** @type {{ id: string, name: string }[]} */
    const out = [];
    for (const g of found) {
      if (typeof g?.id !== 'string' || typeof g?.name !== 'string' || !this.groupAllowed(g.id)) continue;
      const id = this.group(g.id);
      if (!out.some((o) => o.id === id)) out.push({ id, name: g.name.trim().slice(0, 200) || id });
    }
    return out.slice(0, 10);
  }

  /**
   * Members of RECIPIENT_USER_GROUP whose name, mail or user name starts
   * with q, at most 10. "user" is the address the person signs in with, so
   * it matches identity(). Answers are kept for a minute.
   * @param {string} q
   * @returns {Promise<{ name: string, user: string, mail: string }[]>}
   */
  async searchPeople(q) {
    const term = q.replace(/["\\]/g, '').trim().toLowerCase().slice(0, 64);
    if (term.length < 2 || !this.c.userGroup || !this.directory) return [];
    const cached = this.peopleCache.get(term);
    if (cached && cached.until > Date.now()) return cached.people;
    const people = [];
    for (const p of await this.directory.searchPeople(term)) {
      const user = typeof p?.user === 'string' ? p.user.trim().toLowerCase() : '';
      const mail = typeof p?.mail === 'string' ? p.mail.trim().toLowerCase() : '';
      if (!Auth.validEmail(user) || people.some((x) => x.user === user)) continue;
      if (this.c.domains.length && !this.domainAllowed(user)) continue;
      const name = typeof p.name === 'string' && p.name.trim() ? p.name.trim().slice(0, 100) : user;
      people.push({ name, user, mail: Auth.validEmail(mail) ? mail : '' });
      if (people.length === 10) break;
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
   * @param {boolean} [fresh] "another account": the provider asks again
   *   instead of signing in the account it remembers
   * @param {boolean} [silent] AUTH_AUTO_LOGIN: prompt=none, the provider
   *   shows nothing and answers login_required when nobody is signed in there
   */
  async loginUrl(returnTo, fresh = false, silent = false) {
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
    // Google: hd preselects the Workspace domain (only a hint; identity() checks it).
    const hd = this.c.provider === 'google' && this.c.allowedDomains.length === 1 ? { hd: this.c.allowedDomains[0] } : {};
    return client.buildAuthorizationUrl(cfg, {
      ...hd,
      redirect_uri: this.c.redirectUri,
      scope: this.c.provider === 'entra' ? 'openid profile email' : this.c.scopes,
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
      response_mode: 'query',
      // Entra and Google offer an account picker; elsewhere the login form.
      ...(fresh ? { prompt: this.c.provider === 'entra' || this.c.provider === 'google' ? 'select_account' : 'login' } : silent ? { prompt: 'none' } : {}),
    }).href;
  }

  /**
   * Finishes a login: checks state, code, nonce and the ID token, creates
   * the session. The state is used once.
   * @param {string} search the query string of the callback ("?code=...&state=...")
   * @returns {Promise<{ sid: string, returnTo: string, who: User }>}
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
    // The ID token is kept only as id_token_hint for the logout at the provider.
    const idToken = this.c.logout === 'provider' && typeof tokens.id_token === 'string' && tokens.id_token.length < 8192 ? tokens.id_token : '';
    return { sid: await this.createSession(who, idToken), returnTo: saved.r || '/', who };
  }

  /**
   * A silent sign-in the provider declined (nobody signed in there): forgets
   * the login and returns where the visitor came from; null for any other answer.
   * @param {string} search the query string of the callback
   */
  async silentDeclined(search) {
    const params = new URLSearchParams(search);
    const state = params.get('state') || '';
    const error = params.get('error') || '';
    if (!/^(login_required|interaction_required|consent_required|account_selection_required)$/.test(error)) return null;
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(state)) return null;
    const key = `${this.p}oidc:${state}`;
    const [saved] = /** @type {[Record<string, string>]} */ (/** @type {unknown} */ (await this.redis.multi().hGetAll(key).del(key).exec()));
    return saved?.v && RETURN.test(saved.r || '') ? saved.r : null;
  }

  /** @param {User} who @param {string} [idToken] */
  async createSession(who, idToken = '') {
    const sid = randomBytes(32).toString('base64url');
    const key = `${this.p}sess:${sha256(sid)}`;
    await this.redis
      .multi()
      .hSet(key, { name: who.name, user: who.user, ids: who.ids.join(' '), created: String(Date.now()), ...(idToken ? { it: idToken } : {}) })
      .expire(key, this.c.sessionTtl)
      .exec();
    return sid;
  }

  /** Ends a session at once (the audit log could not record the sign-in). @param {string} sid */
  async dropSession(sid) {
    await this.redis.del(`${this.p}sess:${sha256(sid)}`);
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

  /**
   * Ends the session here; returns its ID token (for the logout at the provider).
   * @param {import('express').Request} req @param {import('express').Response} res
   */
  async logout(req, res) {
    const sid = this.sid(req);
    let idToken = '';
    if (sid) {
      const key = `${this.p}sess:${sha256(sid)}`;
      const [it] = /** @type {[string | null]} */ (/** @type {unknown} */ (await this.redis.multi().hGet(key, 'it').del(key).exec()));
      idToken = typeof it === 'string' ? it : '';
    }
    res.clearCookie(this.cookie, { httpOnly: true, secure: this.secure, sameSite: 'lax', path: '/' });
    return idToken;
  }

  /**
   * AUTH_LOGOUT=provider: the provider's end-session address (RP-initiated
   * logout), back to <BASE_URL>/auth/logged-out. "" when the provider has
   * none (Google) or the logout stays local. state carries the return path.
   * @param {string} idToken
   * @param {string} returnTo a path that matches RETURN, or ""
   */
  async endSessionUrl(idToken, returnTo) {
    if (this.c.logout !== 'provider') return '';
    const cfg = await this.oidc();
    if (!cfg.serverMetadata().end_session_endpoint) return '';
    return client.buildEndSessionUrl(cfg, {
      post_logout_redirect_uri: `${new URL(this.c.redirectUri).origin}/auth/logged-out`,
      client_id: this.c.clientId,
      ...(idToken ? { id_token_hint: idToken } : {}),
      ...(RETURN.test(returnTo) ? { state: Buffer.from(returnTo).toString('base64url') } : {}),
    }).href;
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
      // Cognito access tokens have no "aud"; their client_id is the audience.
      const cognito = this.c.provider === 'cognito';
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: issuers,
        ...(cognito ? {} : { audience: this.c.apiAudience }),
        algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'ES256'],
        clockTolerance: 60,
      });
      if (cognito && (payload.token_use !== 'access' || payload.client_id !== this.c.apiAudience)) return null;
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
