// Vanishly - sign-in of MCP clients through the browser (MCP_OAUTH): the
// MCP authorization of OAuth 2.1 with the authorization code flow, PKCE
// (S256) and a loopback redirect (RFC 8252), as Claude Code, VS Code and
// other MCP clients do it. Vanishly is the authorization server; the person
// signs in with the sign-in of this server (AUTH_PROVIDER: Entra ID, OIDC,
// the presets or local accounts), confirms on a consent page, and the
// client gets a personal API token (src/tokens.js) of that person: same
// scopes, policy, lifetime, IP binding, audit and revocation as one made on
// the "API tokens" page.
//
//   /.well-known/oauth-protected-resource[/mcp]   RFC 9728: /mcp and its authorization server
//   /.well-known/oauth-authorization-server       RFC 8414: the endpoints below
//   POST /oauth/register                          RFC 7591: clients register themselves
//   GET  /oauth/authorize                         the client's browser starts here
//   GET  /oauth/<request>                         sign-in (if needed), then the consent page
//   POST /oauth/<request>                         allow or deny; back to the client with a code
//   POST /oauth/token                             code + PKCE verifier -> access token
//
// Registered clients are not stored: the client_id carries its name and
// redirect URIs, signed with a key derived from AUTH_SECRET.
//
// Keys (below REDIS_PREFIX):
//   oauth:req:<id>          hash  a started authorization (client, redirect, challenge, state, scope); 10 minutes
//   oauth:code:<sha256>     hash  an issued code (the person, client, redirect, challenge, scopes); 1 minute, used once

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { escapeHtml } from './theme.js';
import { plainIp, SCOPES } from './tokens.js';

const REQ_TTL = 600;
const CODE_TTL = 60;
const RID = /^[A-Za-z0-9_-]{22}$/;
// RFC 7636: 43 to 128 characters of [A-Za-z0-9-._~]; an S256 challenge is 43.
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const LOOPBACK = new Set(['127.0.0.1', '[::1]', 'localhost']);

/**
 * A redirect URI a client may register: http on a loopback address (any
 * port), no fragment, no user info (RFC 8252 section 7.3).
 * shortcut: loopback only, so web clients (claude.ai connectors) cannot sign in; add an allow list of https hosts if needed.
 * @param {unknown} v
 */
export function loopbackUri(v) {
  if (typeof v !== 'string' || v.length > 200) return null;
  try {
    const u = new URL(v);
    if (u.protocol !== 'http:' || !LOOPBACK.has(u.hostname) || u.username || u.password || u.hash || v.includes('#')) return null;
    return u;
  } catch {
    return null;
  }
}

/**
 * Does the redirect_uri of a request match a registered one? On loopback
 * the port may differ (RFC 8252 section 7.3), all else must be the same.
 * @param {string} asked @param {string[]} registered
 */
export function redirectMatches(asked, registered) {
  const a = loopbackUri(asked);
  if (!a) return false;
  return registered.some((r) => {
    const u = loopbackUri(r);
    return Boolean(u && u.hostname === a.hostname && u.pathname === a.pathname && u.search === a.search);
  });
}

/** base64url(SHA-256(verifier)) as in RFC 7636 S256. @param {string} verifier */
export const s256 = (verifier) => createHash('sha256').update(verifier).digest('base64url');

/**
 * @param {{
 *   auth: import('./auth.js').Auth,
 *   tokens: import('./tokens.js').Tokens,
 *   store: { redis: any, p: string },
 *   origin: (req: import('express').Request) => string,
 *   userOf: (res: import('express').Response) => import('./auth.js').User | null,
 *   ev: (req: import('express').Request, res: import('express').Response, type: string, e?: any, critical?: boolean) => Promise<void>,
 *   page: (view: string, req: import('express').Request, res: import('express').Response, ctx: Record<string, any>) => string,
 *   errorPage: (req: import('express').Request, res: import('express').Response, status: number, text: string) => void,
 *   strings: (res: import('express').Response) => Record<string, string>,
 *   limit: import('express').RequestHandler,
 *   csp: (req: import('express').Request) => string,
 * }} o
 */
export function oauthRouter({ auth, tokens, store, origin, userOf, ev, page, errorPage, strings, limit, csp }) {
  const { redis, p } = store;
  const key = createHmac('sha256', auth.c.secret).update('vanishly oauth clients v1').digest();
  const sign = (/** @type {string} */ body) => createHmac('sha256', key).update(body).digest('base64url').slice(0, 22);
  const issuer = (/** @type {import('express').Request} */ req) => origin(req);
  const resource = (/** @type {import('express').Request} */ req) => `${origin(req)}/mcp`;

  /** A client_id: its name and redirect URIs, signed. @param {string} name @param {string[]} uris */
  const clientId = (name, uris) => {
    const body = Buffer.from(JSON.stringify({ n: name, r: uris })).toString('base64url');
    return `${body}.${sign(body)}`;
  };
  /** @param {unknown} id @returns {{ name: string, uris: string[] } | null} */
  const client = (id) => {
    if (typeof id !== 'string' || id.length > 2000) return null;
    const [body, mac] = id.split('.');
    if (!body || !RID.test(mac || '') || !timingSafeEqual(Buffer.from(sign(body)), Buffer.from(mac))) return null;
    try {
      const c = JSON.parse(Buffer.from(body, 'base64url').toString());
      return typeof c?.n === 'string' && Array.isArray(c.r) ? { name: c.n, uris: c.r } : null;
    } catch {
      return null;
    }
  };

  /** The scopes of a request ("create status"), within the known ones. @param {unknown} v */
  const scopesOf = (v) => (typeof v === 'string' ? v.split(' ').filter((s) => SCOPES.includes(s)) : []);

  /** Back to the client with an error (RFC 6749 section 4.1.2.1). @param {string} uri @param {Record<string, string>} q */
  const back = (uri, q) => {
    const u = new URL(uri);
    for (const [k, v] of Object.entries(q)) if (v) u.searchParams.set(k, v);
    return u.toString();
  };

  /** An OAuth error as JSON (token and registration endpoints). @param {import('express').Response} res @param {number} status @param {string} error @param {string} text */
  const fail = (res, status, error, text) => void res.status(status).json({ error, error_description: text });

  const router = express.Router();

  // ---------------------------------------------------------------- discovery
  /** @param {import('express').Request} req */
  const prm = (req) => ({
    resource: resource(req),
    authorization_servers: [issuer(req)],
    bearer_methods_supported: ['header'],
    scopes_supported: SCOPES,
    resource_name: 'Vanishly',
  });
  router.get('/.well-known/oauth-protected-resource', (req, res) => void res.json(prm(req)));
  router.get('/.well-known/oauth-protected-resource/mcp', (req, res) => void res.json(prm(req)));
  router.get('/.well-known/oauth-authorization-server', (req, res) => {
    const i = issuer(req);
    res.json({
      issuer: i,
      authorization_endpoint: `${i}/oauth/authorize`,
      token_endpoint: `${i}/oauth/token`,
      registration_endpoint: `${i}/oauth/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: SCOPES,
      authorization_response_iss_parameter_supported: true,
    });
  });

  // ---------------------------------------------------------------- registration
  router.post('/oauth/register', limit, express.json({ limit: '8kb' }), (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris : [];
    if (!uris.length || uris.length > 5 || !uris.every((u) => loopbackUri(u))) {
      return fail(res, 400, 'invalid_redirect_uri', 'redirect_uris: 1 to 5 loopback URIs (http://127.0.0.1:<port>/..., http://localhost:<port>/...)');
    }
    if (b.token_endpoint_auth_method !== undefined && b.token_endpoint_auth_method !== 'none') {
      return fail(res, 400, 'invalid_client_metadata', 'token_endpoint_auth_method: only "none" (public clients with PKCE)');
    }
    const grants = b.grant_types ?? ['authorization_code'];
    if (!Array.isArray(grants) || !grants.includes('authorization_code')) {
      return fail(res, 400, 'invalid_client_metadata', 'grant_types must contain "authorization_code"');
    }
    const raw = typeof b.client_name === 'string' ? b.client_name : 'MCP client';
    const name = raw.normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 50) || 'MCP client';
    res.status(201).json({
      client_id: clientId(name, uris),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: uris,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
  });

  // ---------------------------------------------------------------- token (before /oauth/:rid)
  router.post('/oauth/token', limit, express.urlencoded({ extended: false, limit: '8kb' }), async (req, res) => {
    res.set('Pragma', 'no-cache');
    const b = req.body || {};
    if (b.grant_type !== 'authorization_code') return fail(res, 400, 'unsupported_grant_type', 'only authorization_code');
    if (typeof b.code !== 'string' || b.code.length > 100) return fail(res, 400, 'invalid_request', 'code is missing');
    const ck = `${p}oauth:code:${s256(b.code)}`;
    const [h] = await redis.multi().hGetAll(ck).del(ck).exec();
    if (!h?.u) return fail(res, 400, 'invalid_grant', 'The code is unknown, used or expired');
    if (b.client_id !== h.c) return fail(res, 400, 'invalid_grant', 'The code belongs to another client');
    if (b.redirect_uri !== h.r) return fail(res, 400, 'invalid_grant', 'redirect_uri does not match');
    if (typeof b.code_verifier !== 'string' || !VERIFIER.test(b.code_verifier) || s256(b.code_verifier) !== h.ch) {
      return fail(res, 400, 'invalid_grant', 'code_verifier does not match the code_challenge');
    }
    const c = client(h.c);
    const who = { user: h.u, name: h.n, ids: (h.ids || '').split(' ').filter(Boolean) };
    if (!c || !tokens.mayCreate(who)) return fail(res, 400, 'invalid_grant', 'This account may not create API tokens');
    // API_TOKEN_IP_BINDING=required: the address the client asks from (it calls /mcp from there too).
    const ips = tokens.c.ipBinding === 'required' ? [plainIp(req.ip || '')] : [];
    const r = await tokens.create(who, { name: `MCP: ${c.name}`.slice(0, 64), scopes: h.sc.split(' ').filter(Boolean), ips });
    const actor = { type: 'user', user: who.user, name: who.name };
    if ('error' in r) {
      await ev(req, res, 'api.token_create_denied', { outcome: 'denied', actor, reason: r.error === 'too_many_tokens' ? 'limit_reached' : r.error, details: { via: 'oauth', client: c.name } });
      return fail(res, 400, 'invalid_grant', r.message);
    }
    const tk = r.record;
    try {
      await ev(req, res, 'api.token_created', { actor, details: { token: { id: tk.id, name: tk.name }, expires: tk.expires ? new Date(tk.expires).toISOString() : 'never', networks: tk.ips, scopes: tk.scopes, via: 'oauth', client: c.name } }, true);
    } catch {
      await tokens.revoke(tk.id, '', 'audit failure');
      return fail(res, 503, 'temporarily_unavailable', 'The audit log cannot be written right now');
    }
    res.json({
      access_token: r.token,
      token_type: 'Bearer',
      ...(tk.expires ? { expires_in: Math.max(1, Math.floor((tk.expires - Date.now()) / 1000)) } : {}),
      scope: tk.scopes.join(' '),
    });
  });

  // ---------------------------------------------------------------- authorization
  router.get('/oauth/authorize', limit, async (req, res) => {
    const t = strings(res);
    const q = /** @type {Record<string, unknown>} */ (req.query);
    const c = client(q.client_id);
    const uri = typeof q.redirect_uri === 'string' ? q.redirect_uri : '';
    // Without a known client and its redirect URI there is nobody to send the error to.
    if (!c || !redirectMatches(uri, c.uris)) return errorPage(req, res, 400, t['oauth.badClient']);
    const state = typeof q.state === 'string' ? q.state.slice(0, 500) : '';
    const err = (/** @type {string} */ e, /** @type {string} */ d) => res.redirect(303, back(uri, { error: e, error_description: d, state, iss: issuer(req) }));
    if (q.response_type !== 'code') return err('unsupported_response_type', 'response_type must be code');
    if (q.code_challenge_method !== 'S256' || typeof q.code_challenge !== 'string' || !CHALLENGE.test(q.code_challenge)) {
      return err('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    }
    // RFC 8707: a token only for this server's MCP endpoint.
    if (q.resource !== undefined && q.resource !== resource(req) && q.resource !== `${resource(req)}/`) return err('invalid_target', 'unknown resource');
    const rid = randomBytes(16).toString('base64url');
    const k = `${p}oauth:req:${rid}`;
    await redis
      .multi()
      .hSet(k, { c: String(q.client_id), r: uri, ch: q.code_challenge, st: state, sc: scopesOf(q.scope).join(' ') })
      .expire(k, REQ_TTL)
      .exec();
    res.redirect(303, `/oauth/${rid}`);
  });

  /**
   * The person for a request: signed in with a session (not a token) and
   * allowed to make tokens; else why not.
   * @param {import('express').Response} res
   */
  const person = async (res) => {
    const u = userOf(res);
    if (!u || u.token || u.app) return { u: null, why: 'login' };
    if (!tokens.mayCreate(u)) return { u, why: 'oauth.notAllowed' };
    const policy = await tokens.policy(u.user, u.ids);
    if (!policy.scopes.length) return { u, why: 'oauth.notAllowed' };
    if (policy.max && (await tokens.active(u.user)) >= policy.max) return { u, why: 'oauth.limit' };
    return { u, why: '', policy };
  };

  /** What this request would grant: the asked scopes within the policy, else the defaults. @param {string} asked @param {import('./tokens.js').Policy} policy */
  const grant = (asked, policy) => {
    const want = asked.split(' ').filter((s) => policy.scopes.includes(s));
    return want.length ? want : tokens.defaultScopes(policy);
  };

  router.get('/oauth/:rid', limit, async (req, res) => {
    const t = strings(res);
    const rid = String(req.params.rid);
    const r = RID.test(rid) ? await redis.hGetAll(`${p}oauth:req:${rid}`) : null;
    const c = r?.c ? client(r.c) : null;
    if (!r?.c || !c) return errorPage(req, res, 400, t['oauth.expired']);
    const who = await person(res);
    if (who.why === 'login') return res.redirect(303, `/auth/login?return=${encodeURIComponent(`/oauth/${rid}`)}`);
    if (!who.policy) return errorPage(req, res, 403, t[who.why].replace('{max}', String((await tokens.policy(who.u.user, who.u.ids)).max)));
    const scopes = grant(r.sc || '', who.policy);
    // The form posts here and is then sent on to the client's loopback address.
    const to = new URL(r.r).origin;
    res.set('Content-Security-Policy', csp(req).replace("form-action 'self'", `form-action 'self' ${to}`));
    res.type('html').send(
      page('oauth', req, res, {
        page: 'oauth',
        title: t['oauth.title'],
        heading: t['oauth.title'],
        text: t['oauth.text'].replace('{client}', c.name).replace('{user}', who.u.name || who.u.user),
        scopeList: scopes.map((s) => `<li>${escapeHtml(t[`tokens.scope.${s}`] || s)}</li>`).join(''),
        target: t['oauth.target'].replace('{target}', to),
        rid,
      }),
    );
  });

  router.post('/oauth/:rid', limit, express.urlencoded({ extended: false, limit: '1kb' }), async (req, res) => {
    const t = strings(res);
    if (!auth.sameOrigin(req)) return errorPage(req, res, 403, t['error.generic']);
    const rid = String(req.params.rid);
    if (!RID.test(rid)) return errorPage(req, res, 400, t['oauth.expired']);
    const who = await person(res);
    if (who.why === 'login') return res.redirect(303, `/auth/login?return=${encodeURIComponent(`/oauth/${rid}`)}`);
    // Used once: a second post (double click, back button) finds nothing.
    const k = `${p}oauth:req:${rid}`;
    const [r] = await redis.multi().hGetAll(k).del(k).exec();
    const c = r?.c ? client(r.c) : null;
    if (!r?.c || !c) return errorPage(req, res, 400, t['oauth.expired']);
    const iss = issuer(req);
    if (req.body?.decision !== 'allow') return res.redirect(303, back(r.r, { error: 'access_denied', state: r.st, iss }));
    if (!who.policy) return errorPage(req, res, 403, t[who.why].replace('{max}', String((await tokens.policy(who.u.user, who.u.ids)).max)));
    const code = randomBytes(32).toString('base64url');
    const ck = `${p}oauth:code:${s256(code)}`;
    const u = who.u;
    await redis
      .multi()
      .hSet(ck, { u: u.user, n: u.name || u.user, ids: u.ids.join(' '), c: r.c, r: r.r, ch: r.ch, sc: grant(r.sc || '', who.policy).join(' ') })
      .expire(ck, CODE_TTL)
      .exec();
    res.redirect(303, back(r.r, { code, state: r.st, iss }));
  });

  // body-parser errors as OAuth errors, not the HTML error page
  router.use((/** @type {any} */ err, /** @type {any} */ req, /** @type {any} */ res, /** @type {any} */ next) => {
    if (res.headersSent || !err?.type || !req.path.startsWith('/oauth/')) return next(err);
    fail(res, 400, 'invalid_request', 'The body could not be read');
  });
  return router;
}
