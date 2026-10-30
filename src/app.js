// Vanishly - HTTP app: pages, JSON API (openapi/openapi.json), static files.

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import express from 'express';
import { Audit, normalize, parseTraceparent, sanitizeText, sizeBucket, verifyText } from './audit.js';
import { ADMIN_SCOPE, Tokens, SCOPES } from './tokens.js';
import { decryptSecret, encryptSecret, PBKDF2_ITERATIONS, unlockKey, verifierFor } from '../public/js/vanishly-crypto.js';
import { validId } from './store.js';
import { Auth, RETURN } from './auth.js';
import { missingClasses } from '../public/js/rules.js';
import { escapeHtml, ROOT } from './theme.js';

/**
 * "3 days", "2 Wochen": the largest unit that divides the seconds evenly.
 * @param {number} s
 * @param {Record<string, string>} t
 */
export function duration(s, t) {
  for (const [u, n] of /** @type {const} */ ([['w', 604800], ['d', 86400], ['h', 3600], ['m', 60], ['s', 1]])) {
    if (s % n === 0) {
      const v = s / n;
      return (t[`unit.${u}.${v === 1 ? 1 : 'n'}`] || `{n}${u}`).replace('{n}', String(v));
    }
  }
  return `${s}s`;
}

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "manifest-src 'self'",
].join('; ');
// The API docs (Scalar) set inline styles; only that page allows them.
const CSP_DOCS = CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'");

class ApiError extends Error {
  /** @param {number} status @param {string} code @param {string} message @param {Record<string, any>} [extra] */
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/**
 * The OpenAPI document as this server serves it: its version, the index
 * paths and only the endpoints switched on; schemas and tags no remaining
 * operation uses are left out. openapi/openapi.json itself stays complete.
 * @param {any} spec
 * @param {[string, string][]} on [method, path] pairs
 * @param {string} version
 * @param {boolean} [index] GET /api and /api/v1 (ENABLE_API_INDEX)
 */
export function servedSpec(spec, on, version, index = true) {
  const out = structuredClone(spec);
  out.info.version = version;
  const keep = new Set(on.map(([m, p]) => `${m.toLowerCase()} ${p}`));
  /** @type {Record<string, any>} */
  const paths = {};
  for (const [p, item] of Object.entries(out.paths)) {
    const ops = Object.fromEntries(Object.entries(item).filter(([m]) => ((p === '/' || p === '/v1') && index) || keep.has(`${m} ${p}`)));
    if (Object.keys(ops).length) paths[p] = ops;
  }
  out.paths = paths;
  // Components still referenced from the remaining paths (also through each other).
  const used = new Set();
  /** @param {any} v */
  const walk = (v) => {
    if (Array.isArray(v)) return v.forEach(walk);
    if (!v || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      if (k === '$ref' && typeof x === 'string' && x.startsWith('#/components/') && !used.has(x)) {
        used.add(x);
        const [, , kind, name] = x.split('/');
        walk(out.components?.[kind]?.[name]);
      } else walk(x);
    }
  };
  walk(out.paths);
  for (const kind of ['schemas', 'responses', 'parameters', 'requestBodies', 'examples']) {
    const all = out.components?.[kind];
    if (!all) continue;
    for (const name of Object.keys(all)) if (!used.has(`#/components/${kind}/${name}`)) delete all[name];
  }
  const tags = new Set(Object.values(paths).flatMap((item) => Object.values(item).flatMap((op) => op.tags || [])));
  if (Array.isArray(out.tags)) out.tags = out.tags.filter((/** @type {any} */ t) => tags.has(t.name));
  return out;
}

/**
 * A CSV cell: quoted, and text that a spreadsheet would run as a formula
 * (=, +, -, @, tab, CR at the start) gets a ' in front.
 * @param {unknown} v
 */
export function csvCell(v) {
  const s = Array.isArray(v) ? v.join('; ') : String(v ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

/** Text for a log line: line breaks out, so it cannot forge further lines. @param {string} s */
const oneLine = (s) => String(s).replace(/[\r\n\u2028\u2029]+/g, ' ');

/** A file served from memory, with its ETag. @param {string | Buffer} body */
const cached = (body) => ({ body, etag: `"${createHash('sha256').update(body).digest('base64url').slice(0, 27)}"` });

/**
 * @param {{ config: import('./config.js').Config, store: import('./store.js').Store,
 *   theme: import('./theme.js').Theme, version: string, auth?: Auth | null, audit?: Audit | null }} deps
 */
export function createApp({ config, store, theme, version, auth: authIn, audit: auditIn }) {
  const app = express();
  // Sign-in (AUTH_PROVIDER); null = off, Vanishly works without any login.
  const auth = authIn === undefined ? (config.auth ? new Auth(config.auth, store) : null) : authIn;
  // AUDIT_LOG (src/audit.js); null = off.
  const audit = auditIn === undefined ? (config.audit ? new Audit(config.audit, { redis: store.redis, p: store.p, version }) : null) : auditIn;
  // API_TOKENS (src/tokens.js): personal API tokens; needs sign-in.
  const tokens = auth?.c.tokens ? new Tokens(auth.c.tokens, store, auth.c, (k, v) => auth.hash(k, v)) : null;
  app.locals.audit = audit;
  app.locals.tokens = tokens;
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.set('etag', false);

  const maxCtLen = Math.ceil(((config.maxSecretChars * 4 + 16) * 4) / 3);
  const ttlOptions = config.ttlOptions;

  // Security headers on everything; no caching of pages or API answers.
  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': req.path.startsWith('/api/docs') ? CSP_DOCS : auth ? auth.csp(CSP) : CSP,
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
      'X-Robots-Tag': 'noindex, nofollow',
    });
    if (config.hsts) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    if (!req.path.startsWith('/static/') && !req.path.startsWith('/theme/') && !req.path.startsWith('/api/docs')) {
      res.set('Cache-Control', 'no-store');
    }
    next();
  });

  // AUDIT_LOG: a run id per request (X-Run-Id or X-Request-Id from the
  // caller, else new) and the W3C trace context; both go into the events
  // and back in the answer.
  if (audit) {
    app.use((req, res, next) => {
      const tp = parseTraceparent(req.get('traceparent'));
      const given = [req.get('x-run-id'), req.get('x-request-id')].find((v) => typeof v === 'string' && /^[\w.:@/+=-]{1,128}$/.test(v));
      const runId = given || randomUUID();
      const spanId = randomBytes(8).toString('hex');
      res.locals.run = { runId, traceId: tp?.traceId || '', spanId: tp ? spanId : '' };
      res.set({ 'X-Run-Id': runId, 'X-Request-Id': runId });
      if (tp) res.set('traceparent', `00-${tp.traceId}-${spanId}-${tp.flags}`);
      next();
    });
  }

  // Access log without IPs, user agents or the ids of secrets and receipts.
  if (config.accessLog) {
    app.use((req, res, next) => {
      const start = process.hrtime.bigint();
      res.on('finish', () => {
        const ms = Number(process.hrtime.bigint() - start) / 1e6;
        const path = req.originalUrl.split('?')[0].replace(/[A-Za-z0-9_-]{22}/g, ':id');
        console.log(`${req.method} ${oneLine(path)} ${res.statusCode} ${ms.toFixed(1)}ms`);
      });
      next();
    });
  }

  // Language, only among the served ones (LANGUAGES): while visitors may
  // switch, ?lang= (remembered in a cookie) and the cookie; then the
  // browser's Accept-Language; then DEFAULT_LANG.
  const langs = theme.languages;
  app.use((req, res, next) => {
    const q = theme.langSwitch && typeof req.query.lang === 'string' ? req.query.lang : '';
    const c = theme.langSwitch ? /(?:^|;\s*)lang=(\w+)/.exec(req.headers.cookie || '')?.[1] || '' : '';
    /** @type {string} */
    let lang = '';
    if (langs.includes(q)) {
      lang = q;
      res.cookie('lang', q, { maxAge: 365 * 86400 * 1000, sameSite: 'lax', httpOnly: true, path: '/' });
    } else if (langs.includes(c)) {
      lang = c;
    } else {
      // The browser decides only when it names a served language ("*" or
      // nothing: DEFAULT_LANG).
      const pick = req.acceptsLanguages(...langs);
      const asked = String(req.headers['accept-language'] || '').toLowerCase();
      lang = pick && new RegExp(`(^|,)\\s*${pick}(-|;|,|$)`).test(asked) ? pick : theme.defaultLang;
    }
    res.locals.lang = lang;
    next();
  });

  // Who is signed in (session cookie, or a bearer token on the API).
  /** @param {import('express').Response} res @returns {import('./auth.js').User | null} */
  const userOf = (res) => res.locals.user || null;
  if (auth) {
    app.use(async (req, res, next) => {
      if (req.path.startsWith('/static/') || req.path.startsWith('/theme/') || req.path === '/healthz') return next();
      try {
        const bearer = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') || '')?.[1] || '';
        if (tokens && bearer.startsWith('vnly_')) {
          // A personal API token: acts as its owner (src/tokens.js).
          const r = await tokens.verify(bearer, req.ip || '');
          if (r.ok) {
            const t = r.record;
            // scopes: what the token may do under the owner's policy of today.
            res.locals.user = { name: t.ownerName, user: t.owner, ids: t.ids, token: { id: t.id, name: t.name, scopes: r.scopes }, ...(t.svc ? { service: t.svc } : {}) };
            res.locals.tokenGranted = t.scopes;
          } else {
            res.locals.user = null;
            res.locals.tokenDenied = r;
          }
        } else if (tokens?.c.required && bearer && req.path.startsWith('/api/')) {
          // API_TOKEN_REQUIRED: no other bearer tokens (AUTH_API_AUDIENCE).
          res.locals.user = null;
          res.locals.tokenDenied = { ok: false, reason: 'token_required' };
        } else {
          res.locals.user = await auth.user(req);
        }
      } catch (err) {
        console.error(`auth: ${/** @type {Error} */ (err).message}`);
        res.locals.user = null;
      }
      next();
    });
  }

  // Static files: the app's own (public/) and the active template.
  const staticOpts = { dotfiles: /** @type {const} */ ('deny'), index: false, maxAge: '1h', fallthrough: true };
  app.use('/static', express.static(join(ROOT, 'public'), staticOpts));
  // theme.css from memory (read with the views at start), no file access per request.
  const themeCss = cached(theme.css);
  app.get('/theme/theme.css', (_req, res) => {
    res.set({ 'Cache-Control': 'public, max-age=3600', ETag: themeCss.etag }).type('css').send(themeCss.body);
  });
  app.use('/theme/assets', express.static(join(theme.dir, 'assets'), staticOpts));

  app.get('/healthz', async (_req, res) => {
    // Redis must accept writes, not only answer: else nothing can be viewed or burned.
    const ok = await store.writable().catch(() => false);
    res.status(ok ? 200 : 503).type('text/plain').send(ok ? 'ok' : 'unavailable');
  });

  // ---------------------------------------------------------------- API
  const api = express.Router();
  // A switched-off endpoint (ENABLE_*): 404, but told apart from a wrong path.
  const disabled = () => new ApiError(404, 'endpoint_disabled', 'This endpoint is disabled on this server');
  // The endpoints switched on (ENABLE_*, sign-in features): the /api index
  // and the served OpenAPI document both list exactly these.
  const f = config.features;
  /** @type {[boolean | undefined, string, string][]} */
  const endpointTable = [
    [f.configApi, 'GET', '/v1/config'],
    [f.createApi, 'POST', '/v1/secrets'],
    [f.shareApi, 'POST', '/v1/share'],
    [f.secretMetaApi, 'GET', '/v1/secrets/{id}'],
    [f.revealApi, 'POST', '/v1/secrets/{id}/reveal'],
    [f.openApi, 'POST', '/v1/open'],
    [f.receipts && f.receiptApi, 'GET', '/v1/receipts/{id}'],
    [f.receipts && f.burn && f.receiptApi, 'POST', '/v1/receipts/{id}/burn'],
    [Boolean(auth) && f.meApi, 'GET', '/v1/me'],
    [Boolean(auth?.c.groups.any), 'GET', '/v1/groups'],
    [Boolean(auth?.c.userGroup), 'GET', '/v1/people'],
    [Boolean(tokens), 'GET', '/v1/tokens'],
    [Boolean(tokens), 'POST', '/v1/tokens'],
    [Boolean(tokens), 'POST', '/v1/tokens/{id}/revoke'],
    [Boolean(tokens && (auth?.c.admin.users.length || auth?.c.admin.groups.length)), 'GET', '/v1/admin/tokens'],
    [Boolean(tokens && (auth?.c.admin.users.length || auth?.c.admin.groups.length)), 'POST', '/v1/admin/tokens/{id}/revoke'],
    [Boolean(auth?.c.admin.auditView), 'GET', '/v1/admin/audit'],
    [Boolean(tokens?.c.adminPolicy), 'GET', '/v1/admin/token-policies'],
    [Boolean(auth?.c.admin.ui && (auth.c.admin.users.length || auth.c.admin.groups.length)), 'GET', '/v1/admin/status'],
    [Boolean(auth?.c.admin.ui && audit?.c.redis && (auth.c.admin.users.length || auth.c.admin.groups.length)), 'GET', '/v1/admin/secrets'],
    [Boolean(tokens?.c.services), 'GET', '/v1/admin/service-accounts'],
    [Boolean(tokens?.c.services), 'POST', '/v1/admin/service-accounts'],
    [Boolean(tokens?.c.services), 'POST', '/v1/admin/service-accounts/{name}'],
    [Boolean(tokens?.c.services), 'POST', '/v1/admin/service-accounts/{name}/delete'],
    [Boolean(tokens?.c.services), 'GET', '/v1/admin/service-accounts/{name}/tokens'],
    [Boolean(tokens?.c.services), 'POST', '/v1/admin/service-accounts/{name}/tokens'],
    [Boolean(tokens?.c.services), 'POST', '/v1/admin/service-accounts/{name}/tokens/{id}/rotate'],
    [Boolean(tokens?.c.adminPolicy), 'POST', '/v1/admin/token-policies'],
    [Boolean(auth?.c.admin.auditView && audit?.c.file), 'GET', '/v1/admin/audit/verify'],
  ];
  const endpointsOn = endpointTable.filter(([on]) => on).map(([, method, path]) => /** @type {[string, string]} */ ([method, path]));
  api.use(express.json({ limit: Math.max(64 * 1024, maxCtLen * 2) }));

  // ---------------------------------------------------------------- audit
  /** The route of a request without ids ("/api/v1/secrets/:id/reveal"). @param {import('express').Request} req */
  const routeOf = (req) => (req.route?.path ? `${req.baseUrl}${req.route.path}` : req.originalUrl.split('?')[0].replace(/[A-Za-z0-9_-]{22}/g, ':id').replace(/vnly_[0-9a-f]{16}/g, ':token').slice(0, 200));
  /**
   * A header with free text (X-Audit-Comment, X-On-Behalf-Of): percent-encoded
   * or raw UTF-8, cleaned like any comment.
   * @param {import('express').Request} req @param {string} name @param {number} max
   */
  const headerText = (req, name, max) => {
    const raw = req.get(name);
    if (typeof raw !== 'string' || !raw) return '';
    let v = raw;
    try {
      v = /%[0-9a-f]{2}/i.test(raw) ? decodeURIComponent(raw) : Buffer.from(raw, 'latin1').toString('utf8');
    } catch {}
    return sanitizeText(v, max);
  };
  /** Who acts: the signed-in user, an API token (with its owner), an app or nobody. @param {import('express').Request} req @param {import('express').Response} res */
  const actorOf = (req, res) => {
    const u = userOf(res);
    if (!u) return /** @type {import('./audit.js').Actor} */ ({ type: 'anonymous' });
    if (u.token && u.service) return /** @type {import('./audit.js').Actor} */ ({ type: 'service_account', user: u.user, name: u.name, token: { id: u.token.id, name: u.token.name }, onBehalfOf: headerText(req, 'x-on-behalf-of', 200) });
    if (u.token) return /** @type {import('./audit.js').Actor} */ ({ type: 'api_token', user: u.user, name: u.name, token: { id: u.token.id, name: u.token.name }, onBehalfOf: headerText(req, 'x-on-behalf-of', 200) });
    if (u.app) return /** @type {import('./audit.js').Actor} */ ({ type: 'app', name: u.name, onBehalfOf: headerText(req, 'x-on-behalf-of', 200) });
    return /** @type {import('./audit.js').Actor} */ ({ type: 'user', user: u.user, name: u.name });
  };
  /**
   * Writes an audit event for this request. critical: with AUDIT_LOG_FAIL=closed
   * a failed write throws (503), so the caller refuses or undoes the action.
   * @param {import('express').Request} req @param {import('express').Response} res @param {string} type
   * @param {Partial<import('./audit.js').AuditEvent>} [e] @param {boolean} [critical]
   */
  const ev = async (req, res, type, e = {}, critical = false) => {
    if (!audit) return;
    res.locals.audited = true;
    const run = res.locals.run || {};
    try {
      await audit.log({
        type,
        outcome: 'success',
        actor: actorOf(req, res),
        runId: run.runId,
        traceId: run.traceId,
        spanId: run.spanId,
        source: { ip: audit.ip(req.ip || ''), userAgent: audit.c.userAgent ? sanitizeText(req.get('user-agent') || '', 300) : '' },
        http: { method: req.method, route: routeOf(req) },
        ...e,
      });
    } catch {
      if (critical) throw new ApiError(503, 'audit_unavailable', 'The audit log cannot be written right now; nothing was done');
    }
  };
  /** AUDIT_LOG_FAIL=closed: refuse before anything changes while the log fails. */
  const auditReady = () => {
    if (audit && !audit.ready()) throw new ApiError(503, 'audit_unavailable', 'The audit log cannot be written right now; nothing was done');
  };
  /** The comment of a request: the "comment" field, else X-Audit-Comment. @param {import('express').Request} req @param {any} b */
  const commentOf = (req, b) => (b && typeof b.comment === 'string' ? sanitizeText(b.comment, config.comment.max) : headerText(req, 'x-audit-comment', config.comment.max));
  /**
   * AUDIT_COMMENT for a new secret: checked and returned (cleaned).
   * @param {import('express').Request} req @param {import('express').Response} res @param {any} b
   */
  const secretComment = (req, res, b) => {
    if (b.comment !== undefined && b.comment !== null && (typeof b.comment !== 'string' || b.comment.length > config.comment.max * 2)) {
      throw new ApiError(400, 'invalid_comment', `comment must be a string of at most ${config.comment.max} characters`);
    }
    const c = commentOf(req, b);
    if (config.comment.mode === 'off') {
      if (typeof b.comment === 'string' && b.comment.trim()) throw new ApiError(400, 'comment_disabled', 'Comments are switched off on this server');
      return userOf(res)?.token ? c : '';
    }
    if (config.comment.mode === 'required' && !c) throw new ApiError(400, 'comment_required', 'This server requires a comment (what the secret is for)');
    return c;
  };
  /** The people of a secret, as names for the log. @param {{ users: string[], groups: string[] }} p */
  const people = (p) => ({ users: p.users, groups: p.groups });

  // API_TOKENS: refused tokens, API_TOKEN_REQUIRED, scopes, the token's rate
  // limit, API_TOKEN_COMMENT; and every token call is logged.
  if (tokens) {
    api.use(async (req, res, next) => {
      try {
        const d = res.locals.tokenDenied;
        if (d) {
          const type = d.reason === 'expired' ? 'api.token_expired' : d.reason === 'ip_denied' ? 'api.ip_denied' : 'api.token_denied';
          const r = d.record;
          await ev(req, res, type, {
            outcome: 'denied',
            reason: d.reason,
            ...(r ? { actor: { type: 'api_token', user: r.owner, name: r.ownerName, token: { id: r.id, name: r.name } } } : {}),
            details: r && d.reason === 'ip_denied' ? { allowed_networks: r.ips } : undefined,
          });
          if (d.reason === 'ip_denied') throw new ApiError(403, 'ip_not_allowed', 'This token may not be used from this address');
          if (d.reason === 'token_required') throw new ApiError(401, 'token_required', 'This server takes only its own API tokens (vnly_...)');
          throw new ApiError(401, d.reason === 'expired' ? 'token_expired' : 'invalid_token', d.reason === 'expired' ? 'The token has expired' : 'The token is unknown, revoked or malformed');
        }
        const u = userOf(res);
        if (u?.token) {
          // Every call with a token, with its answer: "api.token_used".
          res.on('finish', () => {
            const st = res.statusCode;
            ev(req, res, 'api.token_used', {
              outcome: st < 400 ? 'success' : st >= 500 ? 'error' : 'denied',
              reason: res.locals.errorCode,
              comment: commentOf(req, req.body),
              http: { method: req.method, route: routeOf(req), status: st },
            });
          });
          if (tokens.c.rateLimit) {
            const r = await store.rateLimit('tok', u.token.id, tokens.c.rateLimit, config.rateWindow);
            if (!r.ok) {
              res.set('Retry-After', String(r.retryAfter));
              throw new ApiError(429, 'rate_limited', 'Too many requests with this token');
            }
          }
          if (tokens.c.comment === 'required' && req.method === 'POST' && !commentOf(req, req.body)) {
            throw new ApiError(400, 'comment_required', 'This server requires a comment on every API call (X-Audit-Comment or "comment")');
          }
          return next();
        }
        // API_TOKEN_REQUIRED: without a token only this server's own pages.
        if (tokens.c.required && /^\/v1\//.test(req.path) && !fromPage(req)) {
          await ev(req, res, 'api.denied', { outcome: 'denied', reason: 'token_required' });
          throw new ApiError(401, 'token_required', 'This server requires an API token (Authorization: Bearer vnly_...); create one on the API tokens page');
        }
        next();
      } catch (err) {
        next(err);
      }
    });
  }
  /**
   * A token needs the scope for this call (create, read, status); a refusal
   * is logged as "api.scope_denied" (the token lacks it, or the owner's
   * policy took it away since).
   * @param {import('express').Request} req @param {import('express').Response} res @param {string} scope
   */
  const needScope = async (req, res, scope) => {
    const t = userOf(res)?.token;
    if (!t || t.scopes.includes(scope)) return;
    const granted = /** @type {string[]} */ (res.locals.tokenGranted || []);
    const reason = granted.includes(scope) ? 'policy' : 'not_granted';
    await ev(req, res, 'api.scope_denied', { outcome: 'denied', reason, details: { scope, token_scopes: granted, allowed_now: t.scopes } });
    throw new ApiError(403, 'insufficient_scope', reason === 'policy' ? `The scope "${scope}" of this token is no longer allowed for its owner` : `This token lacks the scope "${scope}"`, { scope });
  };

  /** @param {'create' | 'read'} bucket */
  const limit = (bucket) => /** @type {import('express').RequestHandler} */ (async (req, res, next) => {
    try {
      const max = bucket === 'create' ? config.rateCreate : config.rateRead;
      const r = await store.rateLimit(bucket, req.ip || '', max, config.rateWindow);
      if (!r.ok) {
        res.set('Retry-After', String(r.retryAfter));
        throw new ApiError(429, 'rate_limited', 'Too many requests');
      }
      next();
    } catch (err) {
      next(err);
    }
  });

  /** @param {any} body */
  const options = (body) => {
    const ttl = body.ttl ?? config.defaultTtl;
    if (!Number.isInteger(ttl) || ttl < 60 || ttl > config.maxTtl) {
      throw new ApiError(400, 'invalid_ttl', `ttl must be an integer from 60 to ${config.maxTtl}`);
    }
    const views = body.views ?? 1;
    if (!Number.isInteger(views) || views < 1 || views > config.maxViews) {
      throw new ApiError(400, 'invalid_views', `views must be an integer from 1 to ${config.maxViews}`);
    }
    return { ttl, views };
  };

  /** @param {import('express').Request} req */
  const origin = (req) => config.baseUrl || `${req.protocol}://${req.get('host')}`;

  /** @param {Awaited<ReturnType<typeof store.create>>} s */
  const created = (s) => ({
    id: s.id,
    receiptId: s.receiptId,
    secretPath: `/s/${s.id}`,
    receiptPath: s.receiptId ? `/r/${s.receiptId}` : null,
    expires: new Date(s.expires).toISOString(),
    views: s.views,
    passphrase: s.passphrase,
    restricted: s.restricted,
  });

  /** @param {any} v @param {RegExp} re */
  const check = (v, re) => typeof v === 'string' && re.test(v);

  // AUTH_CREATE=signed-in: only signed-in users (or API tokens) create secrets.
  /** @param {import('express').Response} res */
  const mayCreate = (res) => {
    if (auth?.c.createNeedsLogin && !userOf(res)) throw new ApiError(401, 'login_required', 'Sign in first: this server lets only signed-in users create secrets');
  };

  /**
   * "recipients" (addresses) and "recipientGroups" of a new secret, as hashes.
   * @param {any} b
   * @param {import('express').Response} res
   */
  /**
   * REQUIRE_PASSPHRASE: is a passphrase needed for a secret with these
   * recipients? The error says why.
   * @param {unknown[]} to
   */
  const passphraseNeeded = (to) => {
    if (config.passphraseRule === 'always') return new ApiError(400, 'passphrase_required', 'This server requires a passphrase');
    if (config.passphraseRule === 'unless-recipients' && !to.length) {
      return new ApiError(400, 'passphrase_required', 'A passphrase is required when no recipients are given');
    }
    return null;
  };
  /**
   * People and groups of a new secret (recipients or responsible), checked
   * the same way and returned as hashes, with what the status page shows.
   * @param {unknown} usersIn @param {unknown} groupsIn @param {import('express').Response} res
   * @param {{ field: string, groupField: string, mode: string, code: string, what: string, required: string }} k
   */
  const peopleOf = (usersIn, groupsIn, res, k) => {
    const users = usersIn ?? [];
    const groups = groupsIn ?? [];
    if (!Array.isArray(users) || !Array.isArray(groups)) {
      throw new ApiError(400, `invalid_${k.code}s`, `${k.field} and ${k.groupField} must be arrays`);
    }
    if (!users.length && !groups.length) {
      if (k.mode === 'required') throw new ApiError(400, `${k.code}s_required`, k.required);
      return { ids: [], users: [], groups: [] };
    }
    if (!auth || k.mode === 'off') throw new ApiError(400, `${k.code}s_disabled`, `${k.what[0].toUpperCase()}${k.what.slice(1)}s are switched off on this server`);
    if (!userOf(res)) throw new ApiError(401, 'login_required', `Sign in to choose ${k.what}s`);
    if (users.length + groups.length > auth.c.recipientsMax) {
      throw new ApiError(400, `too_many_${k.code}s`, `At most ${auth.c.recipientsMax} ${k.what}s`, { max: auth.c.recipientsMax });
    }
    const ids = new Set();
    /** @type {string[]} */ const names = [];
    for (const u of users) {
      if (!Auth.validEmail(u)) throw new ApiError(400, `invalid_${k.code}`, `A ${k.what} is not a valid e-mail address`, { [k.code]: String(u).slice(0, 254) });
      if (!auth.domainAllowed(u)) {
        throw new ApiError(400, `${k.code}_domain`, `${k.what[0].toUpperCase()}${k.what.slice(1)}s must have an address of ${auth.c.domains.join(', ')}`, { [k.code]: u, domains: auth.c.domains });
      }
      ids.add(auth.hash('u', u));
      names.push(String(u).trim().toLowerCase());
    }
    if (groups.length && !auth.c.groups.any && !auth.c.groups.list.length) {
      throw new ApiError(400, 'groups_disabled', `Groups as ${k.what}s are switched off on this server`);
    }
    /** @type {string[]} */ const groupNames = [];
    for (const g of groups) {
      if (typeof g !== 'string' || !auth.groupAllowed(g)) throw new ApiError(400, 'invalid_group', 'A group is unknown or not allowed', { group: String(g).slice(0, 200) });
      ids.add(auth.hash('g', auth.c.provider === 'entra' ? g.toLowerCase() : g));
      groupNames.push(auth.c.groups.list.find((x) => x.id === g)?.name || g);
    }
    return { ids: [...ids], users: names, groups: groupNames };
  };
  /** "recipients" (addresses) and "recipientGroups": who may open it. @param {any} b @param {import('express').Response} res */
  const recipientsOf = (b, res) =>
    peopleOf(b.recipients, b.recipientGroups, res, { field: 'recipients', groupField: 'recipientGroups', mode: auth?.c.recipients || 'optional', code: 'recipient', what: 'recipient', required: 'This server requires at least one recipient' });
  /**
   * "responsible" and "responsibleGroups" (RESPONSIBLE): who looks after it:
   * may see the status and burn it (STATUS_ACCESS=signed-in).
   * @param {any} b @param {import('express').Response} res
   */
  const responsibleOf = (b, res) => peopleOf(b.responsible, b.responsibleGroups, res, { field: 'responsible', groupField: 'responsibleGroups', mode: config.responsible, code: 'responsible', what: 'responsible person', required: 'This server requires at least one responsible person or group (responsible or responsibleGroups): who may see the status and burn the secret' });
  /**
   * What the receipt keeps for the status page (STATUS_ACCESS=signed-in):
   * the creator, the responsible people and their names to show.
   * @param {import('express').Response} res @param {{ ids: string[], users: string[], groups: string[] }} resp
   */
  const statusOf = (res, resp) => {
    const user = userOf(res);
    const creator = user?.user && !user.app ? auth?.hash('u', user.user) || '' : '';
    const show = config.statusAccess === 'signed-in';
    return {
      creator,
      responsible: resp.ids,
      who: show && (creator || resp.ids.length) ? { creator: creator ? { name: user?.name || '', user: user?.user || '' } : null, responsible: { users: resp.users, groups: resp.groups } } : null,
    };
  };

  /**
   * Restricted secrets: only a signed-in recipient gets the ciphertext. Checked
   * before the passphrase, so others cannot burn it with wrong attempts.
   * @param {string} id
   * @param {import('express').Response} res
   */
  const mayOpen = async (id, res) => {
    const to = validId(id) ? await store.recipients(id) : null;
    if (!to?.length) return;
    const user = userOf(res);
    if (!user) throw new ApiError(401, 'login_required', 'This secret is only for certain people: sign in first');
    if (!Auth.allowed(user, to)) throw new ApiError(403, 'not_recipient', 'This secret was not shared with your account');
  };
  /**
   * mayOpen() with the refusal in the audit log ("secret.reveal_denied").
   * @param {import('express').Request} req @param {import('express').Response} res @param {string} id
   */
  const mayOpenLogged = async (req, res, id) => {
    try {
      await mayOpen(id, res);
    } catch (err) {
      await ev(req, res, 'secret.reveal_denied', { outcome: 'denied', reason: /** @type {ApiError} */ (err).code, secret: { ref: audit?.ref('s', id) } });
      throw err;
    }
  };
  /**
   * The outcome of a reveal (page or /v1/open) in the audit log. A handed-out
   * secret is logged before the answer (critical): without the event no
   * ciphertext leaves the server.
   * @param {import('express').Request} req @param {import('express').Response} res @param {string} id @param {any} r from store.reveal()
   * @param {string} via
   */
  const revealLogged = async (req, res, id, r, via) => {
    const secret = validId(id) ? { ref: audit?.ref('s', id) } : undefined;
    if (r.status === 'ok') return ev(req, res, 'secret.revealed', { secret, details: { views_left: r.viewsLeft, via } }, true);
    if (r.status === 'badpass') return ev(req, res, 'secret.reveal_denied', { outcome: 'denied', reason: 'bad_passphrase', secret, details: { attempts_left: r.attemptsLeft, via } });
    if (r.status === 'burned') return ev(req, res, 'secret.burned', { reason: 'passphrase_attempts', secret, details: { via } });
    return ev(req, res, 'secret.reveal_denied', { outcome: 'denied', reason: 'not_found', secret, details: { via } });
  };
  /**
   * "secret.created" (critical): when it cannot be written (AUDIT_LOG_FAIL=closed)
   * the new secret is deleted again and the request fails.
   * @param {import('express').Request} req @param {import('express').Response} res
   * @param {Awaited<ReturnType<typeof store.create>>} s @param {any} e
   */
  const createdLogged = async (req, res, s, e) => {
    try {
      await ev(req, res, 'secret.created', { secret: { ref: audit?.ref('s', s.id), receiptRef: s.receiptId ? audit?.ref('r', s.receiptId) : undefined }, ...e }, true);
    } catch (err) {
      await store.discard(s.id, s.rid);
      throw err;
    }
  };
  /** RECEIPT_SHOW_VIEWER: "name<TAB>address" for the view log. @param {import('express').Response} res */
  const viewerName = (res) => {
    const u = userOf(res);
    if (!auth?.c.showViewer || !u) return '';
    /** @param {string} v */ const clean = (v) => String(v || '').replace(/[\t\r\n]/g, ' ');
    return `${clean(u.name || u.user)}\t${clean(u.user)}`;
  };
  /** STATUS_ACCESS=signed-in: who opened it may see the status. @param {import('express').Response} res */
  const openerOf = (res) => {
    const u = userOf(res);
    return config.statusAccess === 'signed-in' && u?.user && !u.app ? auth?.hash('u', u.user) || '' : '';
  };
  /**
   * STATUS_ACCESS=signed-in: may this user see the status of the receipt
   * (creator, responsible, opened it) or burn it (creator, responsible)?
   * Receipts without creator and responsible (anonymous, older) keep link access.
   * @param {any} r from store.receipt() @param {import('express').Response} res @param {'view' | 'burn'} action
   */
  const statusAccessOf = (r, res, action) => {
    if (config.statusAccess !== 'signed-in' || (!r.creator && !r.responsible.length)) return { view: true, burn: true };
    const user = userOf(res);
    if (!user) throw new ApiError(401, 'login_required', 'Sign in to see the status of this secret');
    // The creator: by the hashes of the user, or (technical users have none) by their name.
    const self = user.user && !user.app ? auth?.hash('u', user.user) : '';
    const burn = user.ids.includes(r.creator) || Boolean(self && self === r.creator) || Auth.allowed(user, r.responsible);
    const view = burn || (Boolean(user.user) && r.openers.includes(auth?.hash('u', user.user)));
    if (action === 'burn' ? !burn : !view) {
      throw new ApiError(403, 'not_allowed', action === 'burn' ? 'Only the creator and the responsible people may burn this secret' : 'This status is only for the creator, the responsible people and who opened the secret');
    }
    return { view, burn };
  };

  // ENABLE_API=false: the API only answers the pages of this server. Browsers
  // mark their own fetches with Sec-Fetch-Site; scripts could fake that
  // header, so this hides the API from casual use but is no access control.
  /** @param {import('express').Request} req */
  const fromPage = (req) => req.get('sec-fetch-site') === 'same-origin';
  if (!config.api) {
    api.use((req, _res, next) => {
      const own = fromPage(req) && /^\/v1\/(secrets|receipts|me|groups|people|tokens|admin)(\/|$)/.test(req.path);
      // Known paths: switched off; anything else falls through to not_found.
      const known = /^\/(v1(\/(config|secrets|share|open|receipts|me|groups|people|tokens|admin)(\/.*)?)?\/?|openapi\.json|docs(\/.*)?)?$/.test(req.path);
      next(own ? undefined : known ? disabled() : undefined);
    });
  }


  /**
   * The confirmation the sender must give (CONFIRM_CHECKBOX): the same text
   * as the checkbox label of the form, in that language.
   * @param {string} l
   */
  const confirmRule = (l) =>
    /** @type {Record<string, string>} */ (config.confirmText)[l] || config.confirmText.any || (theme.strings[l] || theme.strings[theme.defaultLang])['home.confirm'];
  /**
   * The API error without "confirmed": true; the message states the rule.
   * @param {import('express').Response} res
   */
  const confirmationRequired = (res) => {
    const l = /** @type {string} */ (res.locals.lang);
    const rule = confirmRule(l);
    const hint = (theme.strings[l] || theme.strings[theme.defaultLang])['api.confirmHint'];
    return new ApiError(400, 'confirmation_required', `${rule} ${hint}`, { rule });
  };

  // ENABLE_CONFIG_API / ENABLE_ME_API / ENABLE_SECRET_META_API=false: 404,
  // the web pages do not use these endpoints.
  /** @param {boolean} on */
  const switchedOff = (on) => {
    if (!on) throw disabled();
  };
  // ENABLE_CREATE_API / ENABLE_REVEAL_API / ENABLE_RECEIPT_API=false: the
  // web pages need these, so they still answer this server's own pages
  // (Sec-Fetch-Site; a guard against casual use, no access control).
  /** @param {boolean} on @param {import('express').Request} req */
  const pagesOnly = (on, req) => switchedOff(on || fromPage(req));

  api.get('/v1/config', (_req, res) => {
    switchedOff(config.features.configApi);
    res.json({
      ttlOptions,
      languages: theme.languages,
      defaultLang: theme.defaultLang,
      defaultTtl: config.defaultTtl,
      maxTtl: config.maxTtl,
      maxViews: config.maxViews,
      maxSecretChars: config.maxSecretChars,
      minSecretChars: config.minSecretChars,
      minPassphraseLength: config.minPassphraseLength,
      passphraseComplexity: config.passphraseClasses,
      requirePassphrase: config.requirePassphrase,
      passphraseRule: config.passphraseRule,
      confirmation: config.confirmCheckbox
        ? Object.fromEntries(
            theme.languages.map((l) => [l, confirmRule(l)]),
          )
        : null,
      passphraseAttempts: config.passphraseAttempts,
      iterations: PBKDF2_ITERATIONS,
      features: { ...config.features, langSwitch: theme.langSwitch },
      auth: auth
        ? {
            provider: auth.c.provider,
            createNeedsLogin: auth.c.createNeedsLogin,
            recipients: auth.c.recipients,
            recipientsMax: auth.c.recipientsMax,
            recipientDomains: auth.c.domains,
            groups: auth.c.groups.any ? 'search' : auth.c.groups.list.length ? 'list' : 'off',
            // The group list only for signed-in users.
            groupList: userOf(res) ? auth.c.groups.list : [],
            peopleSearch: Boolean(auth.c.userGroup),
          }
        : null,
    });
  });

  api.get('/v1/me', (_req, res) => {
    switchedOff(config.features.meApi);
    const u = userOf(res);
    res.json(u ? { signedIn: true, name: u.name, user: u.user, app: Boolean(u.app) } : { signedIn: false });
  });

  // RECIPIENT_GROUPS=*: group search for the form (Microsoft Graph).
  api.get('/v1/groups', limit('read'), async (req, res) => {
    if (!auth?.c.groups.any) throw disabled();
    if (!userOf(res)) throw new ApiError(401, 'login_required', 'Sign in first');
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    try {
      res.json({ groups: await auth.searchGroups(q) });
    } catch (err) {
      console.error(`auth: group search failed: ${/** @type {Error} */ (err).message}`);
      throw new ApiError(502, 'directory_unavailable', 'The group search is not available right now');
    }
  });

  // RECIPIENT_USER_GROUP: people search for the form (Microsoft Graph).
  api.get('/v1/people', limit('read'), async (req, res) => {
    if (!auth?.c.userGroup) throw disabled();
    if (!userOf(res) || userOf(res)?.app) throw new ApiError(401, 'login_required', 'Sign in first');
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    try {
      res.json({ people: await auth.searchPeople(q) });
    } catch (err) {
      console.error(`auth: people search failed: ${/** @type {Error} */ (err).message}`);
      throw new ApiError(502, 'directory_unavailable', 'The people search is not available right now');
    }
  });

  // Stores a secret the client has encrypted itself (the browser does this).
  api.post('/v1/secrets', limit('create'), async (req, res) => {
    pagesOnly(config.features.createApi, req);
    mayCreate(res);
    await needScope(req, res, 'create');
    auditReady();
    const b = req.body || {};
    if (b.v !== undefined && b.v !== 1) throw new ApiError(400, 'invalid_version', 'Only format v1 is known');
    if (!check(b.ciphertext, /^[A-Za-z0-9_-]{22,}$/)) {
      throw new ApiError(400, 'invalid_ciphertext', 'ciphertext must be base64url');
    }
    if (b.ciphertext.length > maxCtLen) throw new ApiError(413, 'too_large', 'The secret is too long');
    // The server cannot see the plaintext, only its size: UTF-8 bytes minus
    // the 16-byte GCM tag. A string has at least as many UTF-8 bytes as
    // characters, so this never refuses a long enough secret.
    if (Math.floor((b.ciphertext.length * 3) / 4) - 16 < config.minSecretChars) {
      throw new ApiError(400, 'too_short', `The secret must be at least ${config.minSecretChars} characters long`);
    }
    if (!check(b.iv, /^[A-Za-z0-9_-]{16}$/)) throw new ApiError(400, 'invalid_iv', 'iv must be 12 bytes, base64url');
    if (!check(b.salt, /^[A-Za-z0-9_-]{22}$/)) throw new ApiError(400, 'invalid_salt', 'salt must be 16 bytes, base64url');
    if (!Number.isInteger(b.iterations) || b.iterations < 100000 || b.iterations > 2000000) {
      throw new ApiError(400, 'invalid_iterations', 'iterations must be from 100000 to 2000000');
    }
    if (b.verifier !== undefined && b.verifier !== null && !check(b.verifier, /^[A-Za-z0-9_-]{43}$/)) {
      throw new ApiError(400, 'invalid_verifier', 'verifier must be 32 bytes, base64url');
    }
    if (b.verifier && !config.features.passphrase) {
      throw new ApiError(400, 'passphrase_disabled', 'Passphrases are switched off on this server');
    }
    // MIN_PASSPHRASE_LENGTH cannot be checked here: the passphrase never
    // leaves the browser. The form enforces it; /v1/share checks it.
    if (config.confirmCheckbox && b.confirmed !== true) throw confirmationRequired(res);
    const comment = secretComment(req, res, b);
    const rcp = recipientsOf(b, res);
    const to = rcp.ids;
    const resp = responsibleOf(b, res);
    const noPass = b.verifier ? null : passphraseNeeded(to);
    if (noPass) throw noPass;
    const { ttl, views } = options(b);
    const s = await store.create(
      { ciphertext: b.ciphertext, iv: b.iv, salt: b.salt, iterations: b.iterations, verifier: b.verifier || undefined },
      ttl,
      views,
      to,
      { ...statusOf(res, resp), comment: config.comment.mode !== 'off' ? comment : '' },
    );
    await createdLogged(req, res, s, {
      recipients: people(rcp),
      responsible: people(resp),
      comment,
      details: { encrypted: 'browser', ttl_s: ttl, expires: new Date(s.expires).toISOString(), max_views: views, passphrase: s.passphrase, restricted: s.restricted, size: sizeBucket(Math.floor((b.ciphertext.length * 3) / 4) - 16) },
    });
    res.status(201).json({ ...created(s), ...(comment && config.comment.mode !== 'off' ? { comment } : {}) });
  });

  // Encrypts on the server for scripts without crypto (curl): the key is
  // returned in the links and forgotten right away.
  api.post('/v1/share', limit('create'), async (req, res) => {
    if (!config.features.shareApi) throw disabled();
    mayCreate(res);
    await needScope(req, res, 'create');
    auditReady();
    const b = req.body || {};
    if (typeof b.secret !== 'string' || b.secret.length === 0) {
      throw new ApiError(400, 'invalid_secret', 'secret must be a non-empty string');
    }
    if (b.secret.length > config.maxSecretChars) throw new ApiError(413, 'too_large', 'The secret is too long');
    if (b.secret.length < config.minSecretChars) {
      throw new ApiError(400, 'too_short', `The secret must be at least ${config.minSecretChars} characters long`);
    }
    if (b.passphrase !== undefined && (typeof b.passphrase !== 'string' || b.passphrase.length > 1000)) {
      throw new ApiError(400, 'invalid_passphrase', 'passphrase must be a string of at most 1000 characters');
    }
    if (config.confirmCheckbox && b.confirmed !== true) throw confirmationRequired(res);
    const pass = b.passphrase || '';
    if (pass && !config.features.passphrase) {
      throw new ApiError(400, 'passphrase_disabled', 'Passphrases are switched off on this server');
    }
    const comment = secretComment(req, res, b);
    const rcp = recipientsOf(b, res);
    const to = rcp.ids;
    const resp = responsibleOf(b, res);
    const noPass = pass ? null : passphraseNeeded(to);
    if (noPass) throw noPass;
    if (pass && pass.length < config.minPassphraseLength) {
      throw new ApiError(400, 'passphrase_too_short', `The passphrase must be at least ${config.minPassphraseLength} characters long`);
    }
    const missing = pass ? missingClasses(pass, config.passphraseClasses) : [];
    if (missing.length) {
      throw new ApiError(400, 'passphrase_too_weak', `The passphrase must also contain: ${missing.join(', ')}`, { missing });
    }
    const { ttl, views } = options(b);
    const { key, payload } = await encryptSecret(b.secret, pass);
    const s = await store.create(payload, ttl, views, to, { ...statusOf(res, resp), comment: config.comment.mode !== 'off' ? comment : '' });
    await createdLogged(req, res, s, {
      recipients: people(rcp),
      responsible: people(resp),
      comment,
      details: { encrypted: 'server', ttl_s: ttl, expires: new Date(s.expires).toISOString(), max_views: views, passphrase: s.passphrase, restricted: s.restricted, size: sizeBucket(Buffer.byteLength(b.secret)) },
    });
    const o = origin(req);
    res.status(201).json({
      ...created(s),
      ...(comment && config.comment.mode !== 'off' ? { comment } : {}),
      shareUrl: `${o}/s/${s.id}#${key}`,
      receiptUrl: s.receiptId ? `${o}/r/${s.receiptId}${config.features.receiptShareLink ? `#${key}` : ''}` : null,
    });
  });

  api.get('/v1/secrets/:id', limit('read'), async (req, res) => {
    switchedOff(config.features.secretMetaApi);
    await needScope(req, res, 'read');
    const id = String(req.params.id);
    // Restricted: the salt and the views only for a recipient.
    await mayOpenLogged(req, res, id);
    const m = validId(id) ? await store.meta(id) : null;
    if (!m) throw new ApiError(404, 'not_found', 'Unknown, viewed, burned or expired');
    res.json({ ...m, expires: new Date(m.expires).toISOString() });
  });

  api.post('/v1/secrets/:id/reveal', limit('read'), async (req, res) => {
    pagesOnly(config.features.revealApi, req);
    const id = String(req.params.id);
    const verifier = req.body?.verifier;
    if (verifier !== undefined && verifier !== null && !check(verifier, /^[A-Za-z0-9_-]{43}$/)) {
      throw new ApiError(400, 'invalid_verifier', 'verifier must be 32 bytes, base64url');
    }
    await needScope(req, res, 'read');
    auditReady();
    await mayOpenLogged(req, res, id);
    const r = validId(id) ? await store.reveal(id, verifier || undefined, viewerName(res), openerOf(res)) : /** @type {const} */ ({ status: 'notfound' });
    await revealLogged(req, res, id, r, 'browser');
    if (r.status === 'ok') return void res.json({ ...r.payload, viewsLeft: r.viewsLeft });
    if (r.status === 'badpass') {
      throw new ApiError(403, 'bad_passphrase', 'Wrong passphrase', { attemptsLeft: r.attemptsLeft });
    }
    if (r.status === 'burned') throw new ApiError(410, 'burned', 'Too many wrong passphrases, the secret was destroyed');
    throw new ApiError(404, 'not_found', 'Unknown, viewed, burned or expired');
  });

  // ENABLE_RECEIPTS=false / ENABLE_BURN=false: these endpoints answer 404.
  /** @type {import('express').RequestHandler} */
  const receiptsOn = (_req, _res, next) => next(config.features.receipts ? undefined : disabled());

  // Opens a secret for scripts: the link (with the key after #) and, if the
  // secret has one, its passphrase go to the server, which decrypts and
  // forgets both. Same trust as /v1/share; browsers decrypt themselves.
  api.post('/v1/open', limit('read'), async (req, res) => {
    if (!config.features.openApi) throw disabled();
    await needScope(req, res, 'read');
    auditReady();
    const b = req.body || {};
    const m = typeof b.link === 'string' ? /\/s\/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$/.exec(b.link.trim()) : null;
    if (!m) throw new ApiError(400, 'invalid_link', 'link must be a full secret link: https://.../s/<id>#<key>');
    if (b.passphrase !== undefined && (typeof b.passphrase !== 'string' || b.passphrase.length > 1000)) {
      throw new ApiError(400, 'invalid_passphrase', 'passphrase must be a string of at most 1000 characters');
    }
    const [, id, key] = m;
    await mayOpenLogged(req, res, id);
    const meta = await store.meta(id);
    if (!meta) throw new ApiError(404, 'not_found', 'Unknown, viewed, burned or expired');
    /** @type {Uint8Array | undefined} */
    let pk;
    let verifier;
    if (meta.passphrase) {
      if (!b.passphrase) throw new ApiError(400, 'passphrase_required', 'This secret needs its passphrase');
      pk = await unlockKey(b.passphrase, meta);
      verifier = await verifierFor(pk, meta);
    }
    const r = await store.reveal(id, verifier, viewerName(res), openerOf(res));
    await revealLogged(req, res, id, r, 'server');
    if (r.status === 'badpass') {
      throw new ApiError(403, 'bad_passphrase', 'Wrong passphrase', { attemptsLeft: r.attemptsLeft });
    }
    if (r.status === 'burned') throw new ApiError(410, 'burned', 'Too many wrong passphrases, the secret was destroyed');
    if (r.status !== 'ok') throw new ApiError(404, 'not_found', 'Unknown, viewed, burned or expired');
    let secret;
    try {
      secret = await decryptSecret(r.payload, key, pk);
    } catch {
      // The view is used up: the server cannot tell a wrong key before decrypting.
      throw new ApiError(422, 'bad_key', 'The key in the link does not fit; the view was used');
    }
    res.json({ secret, viewsLeft: r.viewsLeft });
  });

  api.get('/v1/receipts/:id', receiptsOn, limit('read'), async (req, res) => {
    pagesOnly(config.features.receiptApi, req);
    await needScope(req, res, 'status');
    const id = String(req.params.id);
    const r = validId(id) ? await store.receipt(id) : null;
    if (!r) throw new ApiError(404, 'not_found', 'Unknown or too old');
    const refs = { ref: audit?.ref('s', r.secretId), receiptRef: audit?.ref('r', id) };
    let may;
    try {
      may = statusAccessOf(r, res, 'view');
    } catch (err) {
      await ev(req, res, 'receipt.denied', { outcome: 'denied', reason: /** @type {ApiError} */ (err).code, secret: refs });
      throw err;
    }
    await ev(req, res, 'receipt.viewed', { secret: refs, details: { state: r.state } });
    const signedIn = config.statusAccess === 'signed-in';
    res.json({
      state: r.state,
      secretPath: config.features.receiptShareLink && (r.state === 'new' || r.state === 'viewed') ? `/s/${r.secretId}` : null,
      created: new Date(r.created).toISOString(),
      expires: new Date(r.expires).toISOString(),
      maxViews: r.maxViews,
      viewsLeft: r.viewsLeft,
      passphrase: r.passphrase,
      burned: r.burned ? new Date(r.burned).toISOString() : null,
      recipients: r.recipients,
      views: config.features.viewLog ? r.views.map((t) => new Date(t).toISOString()) : [],
      // RECEIPT_SHOW_VIEWER: who opened it (signed-in viewers), else null per view.
      viewedBy: config.features.viewLog ? r.viewers.map((n) => (auth?.c.showViewer && n) || null) : [],
      // With RECEIPT_SHOW_VIEWER also the address of each signed-in viewer.
      viewedByUser: config.features.viewLog ? r.viewerUsers.map((u) => (auth?.c.showViewer && u) || null) : [],
      // STATUS_ACCESS=signed-in: who created it and who is responsible.
      creator: signedIn ? r.who?.creator || null : null,
      responsible: signedIn && r.who ? r.who.responsible : { users: [], groups: [] },
      mayBurn: config.features.burn && may.burn,
      ...(config.comment.mode !== 'off' && r.comment ? { comment: r.comment } : {}),
    });
  });

  api.post('/v1/receipts/:id/burn', receiptsOn, limit('read'), async (req, res) => {
    pagesOnly(config.features.receiptApi, req);
    if (!config.features.burn) throw disabled();
    await needScope(req, res, 'status');
    const id = String(req.params.id);
    const rec = validId(id) ? await store.receipt(id) : null;
    if (!rec) throw new ApiError(404, 'not_found', 'Unknown or too old');
    const refs = { ref: audit?.ref('s', rec.secretId), receiptRef: audit?.ref('r', id) };
    try {
      statusAccessOf(rec, res, 'burn');
    } catch (err) {
      await ev(req, res, 'secret.burn_denied', { outcome: 'denied', reason: /** @type {ApiError} */ (err).code, secret: refs });
      throw err;
    }
    const r = await store.burn(id);
    if (r === null) throw new ApiError(404, 'not_found', 'Unknown or too old');
    if (!r) throw new ApiError(409, 'gone', 'The secret is already gone');
    await ev(req, res, 'secret.burned', { reason: 'manual', secret: refs, comment: commentOf(req, req.body) });
    res.json({ state: 'burned' });
  });

  // ------------------------------------------------------------ API tokens
  // Only with a session (the token page), never with a token: a token cannot
  // make, list or revoke tokens.
  /** @param {import('express').Response} res */
  const sessionUser = (res) => {
    const u = userOf(res);
    if (!u || u.app || !u.user) throw new ApiError(401, 'login_required', 'Sign in first');
    if (u.token) throw new ApiError(403, 'session_required', 'API tokens are managed on the API tokens page, not with a token');
    return u;
  };
  /**
   * Who may use the admin API: a signed-in admin (ADMIN_USERS, ADMIN_GROUPS),
   * or a technical user's token with the scope "admin" (API_ADMIN_TOKENS),
   * which must carry a comment (API_ADMIN_COMMENT=required). Refusals of
   * tokens are logged as "api.scope_denied".
   * @param {import('express').Request} req @param {import('express').Response} res
   * @returns {Promise<{ user: string, name: string, token: boolean }>}
   */
  const adminActor = async (req, res) => {
    if (!auth?.c.admin.ui) throw disabled();
    const u = userOf(res);
    if (u?.token) {
      if (!u.service || !u.token.scopes.includes(ADMIN_SCOPE)) {
        await ev(req, res, 'api.scope_denied', { outcome: 'denied', reason: u.service ? 'not_granted' : 'personal_token', details: { scope: ADMIN_SCOPE } });
        throw new ApiError(403, 'insufficient_scope', 'The admin API takes only tokens of technical users with the scope "admin"', { scope: ADMIN_SCOPE });
      }
      if (tokens?.c.adminTokens.comment === 'required' && !commentOf(req, req.body)) {
        throw new ApiError(400, 'comment_required', 'Admin API calls need a comment (X-Audit-Comment)');
      }
      return { user: u.user, name: u.name, token: true };
    }
    const s = sessionUser(res);
    if (!auth.isAdmin(s)) throw new ApiError(403, 'not_admin', 'Only admins (ADMIN_USERS, ADMIN_GROUPS)');
    return { user: s.user, name: s.name, token: false };
  };
  /** @param {import('express').Request} req */
  /** @param {import('express').Request} req @param {import('./tokens.js').Policy} policy */
  const tokenOptions = (req, policy) =>
    tokens && {
      expiry: tokens.c.expiryOptions,
      defaultExpiry: tokens.c.defaultExpiry,
      maxExpiry: tokens.c.maxExpiry,
      ipBinding: tokens.c.ipBinding,
      scopes: SCOPES,
      // This user's policy: the scopes a token may get, the preselected ones, the limit.
      allowedScopes: policy.scopes,
      defaultScopes: tokens.defaultScopes(policy),
      policy: policy.source,
      maxPerUser: policy.max,
      comment: tokens.c.comment,
      // The caller's own address as this server sees it (TRUST_PROXY), to bind a token to it.
      yourIp: String(req.ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1'),
    };
  /** @param {import('./tokens.js').TokenRecord} r */
  const tokenRef = (r) => ({ id: r.id, name: r.name });

  api.get('/v1/tokens', limit('read'), async (req, res) => {
    if (!tokens) throw disabled();
    const u = sessionUser(res);
    const [list, policy] = await Promise.all([tokens.list(u.user), tokens.policy(u.user, u.ids)]);
    // active: the tokens that count against the limit (options.maxPerUser, 0 = no limit).
    // allowedNow per token: its scopes within today's policy.
    res.json({
      mayCreate: tokens.mayCreate(u) && policy.scopes.length > 0,
      options: tokenOptions(req, policy),
      active: list.filter((t) => Tokens.active(t)).length,
      tokens: list.map((t) => ({ ...Tokens.view(t), allowedNow: t.scopes.filter((sc) => policy.scopes.includes(sc)) })),
    });
  });

  api.post('/v1/tokens', limit('create'), async (req, res) => {
    if (!tokens) throw disabled();
    const u = sessionUser(res);
    auditReady();
    if (!tokens.mayCreate(u)) {
      await ev(req, res, 'api.token_create_denied', { outcome: 'denied', reason: 'not_enabled' });
      throw new ApiError(403, 'tokens_not_allowed', 'Your account may not create API tokens; ask an admin to enable it');
    }
    const r = await tokens.create(u, req.body || {});
    if ('error' in r) {
      if (r.error === 'too_many_tokens') {
        await ev(req, res, 'api.token_create_denied', { outcome: 'denied', reason: 'limit_reached', details: { active: r.active, max: r.max } });
        throw new ApiError(400, r.error, r.message, { active: r.active, max: r.max });
      }
      if (r.error === 'scope_not_allowed') {
        await ev(req, res, 'api.token_create_denied', { outcome: 'denied', reason: 'scope_not_allowed', details: { requested: req.body?.scopes, allowed: r.allowed } });
        throw new ApiError(400, r.error, r.message, { allowed: r.allowed });
      }
      throw new ApiError(400, r.error, r.message);
    }
    const t = r.record;
    try {
      await ev(req, res, 'api.token_created', { details: { token: tokenRef(t), expires: t.expires ? new Date(t.expires).toISOString() : 'never', networks: t.ips, scopes: t.scopes } }, true);
    } catch (err) {
      await tokens.revoke(t.id, '', 'audit failure');
      throw err;
    }
    // The token itself only in this one answer.
    res.status(201).json({ token: r.token, ...Tokens.view(t) });
  });

  api.post('/v1/tokens/:id/revoke', limit('create'), async (req, res) => {
    if (!tokens) throw disabled();
    const u = sessionUser(res);
    const t = await tokens.revoke(String(req.params.id), u.user, u.user);
    if (!t) throw new ApiError(404, 'not_found', 'No such token');
    await ev(req, res, 'api.token_revoked', { details: { token: tokenRef(t), owner: t.owner } });
    res.json(Tokens.view(t));
  });

  // API_TOKEN_ADMIN_POLICY: per user and per group, which scopes tokens may
  // have and how many; set by admins on /admin.
  api.get('/v1/admin/token-policies', limit('read'), async (req, res) => {
    if (!tokens?.c.adminPolicy) throw disabled();
    await adminActor(req, res);
    res.json({
      scopes: SCOPES,
      defaults: { allowedScopes: tokens.c.allowedScopes, defaultScopes: tokens.c.defaultScopes, maxPerUser: tokens.c.maxPerUser, scopesByGroup: tokens.c.scopesByGroup },
      // Groups to pick from (RECIPIENT_GROUPS list); otherwise typed, or searched (RECIPIENT_GROUPS=*).
      groups: auth?.c.groups.list || [],
      groupSearch: Boolean(auth?.c.groups.any),
      peopleSearch: Boolean(auth?.c.userGroup),
      policies: (await tokens.policies()).map(({ key, ...p }) => ({ ...p, at: p.at ? new Date(p.at).toISOString() : null })),
    });
  });

  api.post('/v1/admin/token-policies', limit('create'), async (req, res) => {
    if (!tokens?.c.adminPolicy || !auth) throw disabled();
    const admin = await adminActor(req, res);
    auditReady();
    const b = req.body || {};
    if (b.type !== 'user' && b.type !== 'group') throw new ApiError(400, 'invalid_type', 'type: user or group');
    let subject = typeof b.subject === 'string' ? b.subject.trim() : '';
    if (b.type === 'user') {
      if (!Auth.validEmail(subject)) throw new ApiError(400, 'invalid_subject', 'subject: the e-mail address the user signs in with');
      subject = subject.toLowerCase();
    } else {
      if (!subject || subject.length > 200 || /[\x00-\x1f]/.test(subject) || (auth.c.provider === 'entra' && !/^[0-9a-f-]{36}$/i.test(subject))) {
        throw new ApiError(400, 'invalid_subject', auth.c.provider === 'entra' ? 'subject: the object id of the group' : 'subject: the group as in the groups claim');
      }
      subject = auth.group(subject);
    }
    const r = await tokens.setPolicy({ type: b.type, subject, scopes: b.scopes, max: b.max, remove: b.remove === true }, admin.user);
    if ('error' in r) throw new ApiError(400, r.error, r.message);
    /** @param {import('./tokens.js').StoredPolicy | null} p */
    const brief = (p) => (p ? { scopes: p.scopes, max: p.max } : null);
    await ev(req, res, b.remove === true ? 'admin.token_policy_deleted' : 'admin.token_policy_changed', { details: { subject_type: b.type, subject, old: brief(r.old), new: brief(r.new) }, comment: commentOf(req, b) }, true);
    // Optional: revoke at once what the new policy no longer allows (otherwise
    // such tokens just lose those scopes while the policy stands).
    let revoked = [];
    if (b.revokeExceeding === true) {
      revoked = await tokens.revokeExceeding(admin.user);
      for (const t of revoked) await ev(req, res, 'admin.token_revoked', { reason: 'policy', details: { token: tokenRef(t), owner: t.owner, scopes: t.scopes } });
    }
    res.json({ policy: r.new && { ...r.new, at: new Date(r.new.at).toISOString() }, revoked: revoked.map((t) => ({ ...tokenRef(t), owner: t.owner })) });
  });

  // ------------------------------------------------------------ admin
  /** What the admin pages need to know, and what is missing (warnings). */
  const adminStatus = async () => {
    const persistence = await store.persistence().catch(() => ({ aof: false, rdb: null }));
    const auditRedis = Boolean(audit?.c.redis);
    /** @type {string[]} */
    const warnings = [];
    if (!auditRedis) warnings.push('audit_not_in_redis');
    if (!persistence.aof && persistence.rdb !== true) warnings.push(persistence.rdb === null ? 'persistence_unknown' : 'no_persistence');
    return {
      audit: Boolean(audit),
      auditRedis,
      auditFile: Boolean(audit?.c.file),
      persistence,
      tokens: Boolean(tokens),
      services: Boolean(tokens?.c.services),
      adminTokens: Boolean(tokens?.c.adminTokens.enabled),
      policies: Boolean(tokens?.c.adminPolicy),
      warnings,
    };
  };

  api.get('/v1/admin/status', limit('read'), async (req, res) => {
    await adminActor(req, res);
    res.json(await adminStatus());
  });

  // The secrets as the audit log in Redis knows them: metadata only.
  api.get('/v1/admin/secrets', limit('read'), async (req, res) => {
    if (!audit?.c.redis) throw disabled();
    await adminActor(req, res);
    const f = auditFilter(req);
    const status = typeof req.query.status === 'string' ? req.query.status : '';
    if (status && !/^(open|partly_opened|opened|expired|burned)$/.test(status)) throw new ApiError(400, 'invalid_status', 'status: open, partly_opened, opened, expired or burned');
    await ev(req, res, 'admin.secrets_viewed', { details: { filter: { creator: f.actor, recipient: f.recipient, status } } }, true);
    const list = await audit.secrets({ creator: f.actor || (typeof req.query.creator === 'string' ? sanitizeText(req.query.creator, 200) : ''), recipient: f.recipient, status, from: f.from, to: f.to, limit: f.limit });
    res.json({ count: list.length, secrets: list });
  });

  // ------------------------------------------------------------ technical users
  /** @param {import('express').Request} req */
  const svcOf = async (req) => {
    const svc = tokens ? await tokens.service(String(req.params.name)) : null;
    if (!svc) throw new ApiError(404, 'not_found', 'No such technical user');
    return svc;
  };
  /** @param {import('./tokens.js').Service} s */
  const svcView = (s) => ({ ...s, created: new Date(s.created).toISOString(), updated: s.updated ? new Date(s.updated).toISOString() : null });

  api.get('/v1/admin/service-accounts', limit('read'), async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    await adminActor(req, res);
    const list = await tokens.services();
    const all = await tokens.list('');
    res.json({
      adminScope: tokens.c.adminTokens.enabled,
      expiry: tokens.c.expiryOptions,
      defaultExpiry: tokens.c.defaultExpiry,
      services: list.map((s) => ({ ...svcView(s), activeTokens: all.filter((t) => t.svc === s.name && Tokens.active(t)).length })),
    });
  });

  /** @param {boolean} create */
  const saveSvc = (create) => /** @type {import('express').RequestHandler} */ (async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    const admin = await adminActor(req, res);
    auditReady();
    const b = { ...(req.body || {}), ...(create ? {} : { name: String(req.params.name) }) };
    const r = await tokens.saveService(b, admin.user, create);
    if ('error' in r) throw new ApiError(r.error === 'not_found' ? 404 : r.error === 'exists' ? 409 : 400, r.error, r.message);
    await ev(req, res, create ? 'admin.service_created' : 'admin.service_changed', { details: { service: r.new.name, old: r.old && svcView(r.old), new: svcView(r.new) }, comment: commentOf(req, req.body) }, true);
    // Disabled: its tokens are revoked.
    let revoked = /** @type {import('./tokens.js').TokenRecord[]} */ ([]);
    if (!r.new.enabled && (create || r.old?.enabled)) {
      revoked = await tokens.revokeService(r.new.name, admin.user);
      for (const t of revoked) await ev(req, res, 'admin.token_revoked', { reason: 'service_disabled', details: { token: tokenRef(t), owner: t.owner } });
    }
    res.status(create ? 201 : 200).json({ service: svcView(r.new), revoked: revoked.map(tokenRef) });
  });
  api.post('/v1/admin/service-accounts', limit('create'), saveSvc(true));
  api.post('/v1/admin/service-accounts/:name', limit('create'), saveSvc(false));

  api.post('/v1/admin/service-accounts/:name/delete', limit('create'), async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    const admin = await adminActor(req, res);
    auditReady();
    const svc = await svcOf(req);
    const revoked = await tokens.revokeService(svc.name, admin.user);
    await tokens.deleteService(svc.name);
    await ev(req, res, 'admin.service_deleted', { details: { service: svc.name, revoked: revoked.map(tokenRef) }, comment: commentOf(req, req.body) }, true);
    res.json({ deleted: svc.name, revoked: revoked.map(tokenRef) });
  });

  api.get('/v1/admin/service-accounts/:name/tokens', limit('read'), async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    await adminActor(req, res);
    const svc = await svcOf(req);
    res.json({ service: svc.name, tokens: (await tokens.serviceTokens(svc.name)).map((t) => Tokens.view(t)) });
  });

  /**
   * Issues a token for a technical user ("admin" only from a person, or with
   * API_ADMIN_TOKEN_CAN_ISSUE_ADMIN from an admin token).
   * @param {import('express').Request} req @param {import('express').Response} res @param {import('./tokens.js').Service} svc
   * @param {any} b @param {{ user: string, token: boolean }} admin
   */
  const issueSvc = async (req, res, svc, b, admin) => {
    if (!svc.enabled) throw new ApiError(409, 'disabled', 'The technical user is disabled');
    const wantsAdmin = Array.isArray(b.scopes) && b.scopes.includes(ADMIN_SCOPE);
    if (wantsAdmin && admin.token && !tokens?.c.adminTokens.canIssueAdmin) {
      await ev(req, res, 'api.scope_denied', { outcome: 'denied', reason: 'admin_issues_admin', details: { scope: ADMIN_SCOPE, service: svc.name } });
      throw new ApiError(403, 'admin_scope_not_allowed', 'An admin token may not issue admin tokens (API_ADMIN_TOKEN_CAN_ISSUE_ADMIN)');
    }
    const r = await /** @type {Tokens} */ (tokens).issueService(svc, b, true);
    if ('error' in r) throw new ApiError(400, r.error, r.message, r.allowed ? { allowed: r.allowed } : {});
    return r;
  };

  api.post('/v1/admin/service-accounts/:name/tokens', limit('create'), async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    const admin = await adminActor(req, res);
    auditReady();
    const svc = await svcOf(req);
    const r = await issueSvc(req, res, svc, req.body || {}, admin);
    const t = r.record;
    try {
      await ev(req, res, 'admin.service_token_issued', { details: { service: svc.name, token: tokenRef(t), scopes: t.scopes, networks: t.ips, expires: t.expires ? new Date(t.expires).toISOString() : 'never' }, comment: commentOf(req, req.body) }, true);
    } catch (err) {
      await tokens.revoke(t.id, '', 'audit failure');
      throw err;
    }
    res.status(201).json({ token: r.token, ...Tokens.view(t) });
  });

  // Rotate: a new token with the same name, scopes and networks; the old one
  // is revoked at once, or (graceSeconds, up to 7 days) expires a bit later.
  api.post('/v1/admin/service-accounts/:name/tokens/:id/rotate', limit('create'), async (req, res) => {
    if (!tokens?.c.services) throw disabled();
    const admin = await adminActor(req, res);
    auditReady();
    const svc = await svcOf(req);
    const old = await tokens.get(String(req.params.id));
    if (!old || old.svc !== svc.name || !Tokens.active(old)) throw new ApiError(404, 'not_found', 'No such active token of this technical user');
    const grace = req.body?.graceSeconds ?? 0;
    if (!Number.isInteger(grace) || grace < 0 || grace > 7 * 86400) throw new ApiError(400, 'invalid_grace', 'graceSeconds: 0 to 604800');
    const r = await issueSvc(req, res, svc, { name: old.name, scopes: old.scopes, ips: old.ips, expires: req.body?.expires }, admin);
    if (grace) await tokens.shorten(old.id, Date.now() + grace * 1000);
    else await tokens.revoke(old.id, '', admin.user);
    await ev(req, res, 'admin.service_token_rotated', { details: { service: svc.name, old: tokenRef(old), new: tokenRef(r.record), grace_s: grace }, comment: commentOf(req, req.body) }, true);
    res.status(201).json({ token: r.token, ...Tokens.view(r.record), replaced: { id: old.id, until: grace ? new Date(Date.now() + grace * 1000).toISOString() : 'now' } });
  });

  api.get('/v1/admin/tokens', limit('read'), async (req, res) => {
    if (!tokens || !auth?.c.admin.users.length && !auth?.c.admin.groups.length) throw disabled();
    await adminActor(req, res);
    await ev(req, res, 'admin.tokens_listed');
    res.json({ tokens: (await tokens.list('')).map((t) => Tokens.view(t)) });
  });

  api.post('/v1/admin/tokens/:id/revoke', limit('create'), async (req, res) => {
    if (!tokens || !auth?.c.admin.users.length && !auth?.c.admin.groups.length) throw disabled();
    const u = await adminActor(req, res);
    const t = await tokens.revoke(String(req.params.id), '', u.user);
    if (!t) throw new ApiError(404, 'not_found', 'No such token');
    await ev(req, res, 'admin.token_revoked', { details: { token: tokenRef(t), owner: t.owner }, comment: commentOf(req, req.body) });
    res.json(Tokens.view(t));
  });

  /**
   * The filter of the audit view from the query string.
   * @param {import('express').Request} req
   */
  const auditFilter = (req) => {
    /** @param {string} k @param {number} [max] */
    const q = (k, max = 200) => (typeof req.query[k] === 'string' ? sanitizeText(req.query[k], max) : '');
    /** @param {string} k */
    const time = (k) => {
      const v = q(k, 40);
      if (!v) return undefined;
      const t = Date.parse(v);
      if (Number.isNaN(t)) throw new ApiError(400, 'invalid_time', `${k}: an ISO 8601 time, e.g. 2026-10-29T12:00:00Z`);
      return t;
    };
    const limitN = q('limit', 6) ? Number(q('limit', 6)) : 200;
    if (!Number.isInteger(limitN) || limitN < 1 || limitN > 5000) throw new ApiError(400, 'invalid_limit', 'limit: 1 to 5000');
    const outcome = q('outcome', 10);
    if (outcome && !/^(success|denied|error)$/.test(outcome)) throw new ApiError(400, 'invalid_outcome', 'outcome: success, denied or error');
    return { type: q('type', 64), actor: q('actor'), recipient: q('recipient'), runId: q('runId', 128), outcome, q: q('q'), from: time('from'), to: time('to'), limit: limitN };
  };

  api.get('/v1/admin/audit', limit('read'), async (req, res) => {
    if (!auth?.c.admin.auditView || !audit) throw disabled();
    await adminActor(req, res);
    auditReady();
    const f = auditFilter(req);
    const format = req.query.format === 'csv' ? 'csv' : req.query.format === 'jsonl' ? 'jsonl' : 'json';
    // Reading the log is logged too (critical: no unlogged look).
    await ev(req, res, format === 'json' ? 'admin.audit_viewed' : 'admin.audit_exported', { details: { filter: { ...f, from: f.from ? new Date(f.from).toISOString() : undefined, to: f.to ? new Date(f.to).toISOString() : undefined }, format } }, true);
    const { records, source } = await audit.query(f);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    if (format === 'jsonl') {
      res.set('Content-Disposition', `attachment; filename="vanishly-audit-${stamp}.jsonl"`).type('application/x-ndjson');
      return void res.send(records.map((r) => JSON.stringify(r)).join('\n') + (records.length ? '\n' : ''));
    }
    if (format === 'csv') {
      const cols = ['ts', 'type', 'outcome', 'reason', 'actor_type', 'actor', 'actor_name', 'token', 'on_behalf_of', 'recipients', 'comment', 'run_id', 'ip', 'route', 'secret_ref', 'instance', 'seq'];
      const rows = records.map((r) => {
        const n = normalize(r);
        return [n.ts, n.type, n.outcome, n.reason, n.actor.type, n.actor.user, n.actor.name, n.actor.token, n.actor.onBehalfOf, n.recipients, n.comment, n.runId, n.ip, n.route, n.secretRef, n.instance, n.seq].map(csvCell).join(',');
      });
      res.set('Content-Disposition', `attachment; filename="vanishly-audit-${stamp}.csv"`).type('text/csv; charset=utf-8');
      return void res.send([cols.join(','), ...rows].join('\r\n') + '\r\n');
    }
    res.json({ source, format: audit.c.format, count: records.length, events: records.map((r) => ({ ...normalize(r), raw: r })) });
  });

  api.get('/v1/admin/audit/verify', limit('read'), async (req, res) => {
    if (!auth?.c.admin.auditView || !audit?.c.file) throw disabled();
    await adminActor(req, res);
    const result = await audit.verifyFile();
    await ev(req, res, 'admin.audit_verified', { outcome: result?.ok ? 'success' : 'error', reason: result?.ok ? '' : 'chain_broken', details: { entries: result?.entries, errors: result?.errors.length } });
    res.json(result);
  });

  api.get('/openapi.json', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').type('application/json').send(openapi);
  });

  if (config.apiDocs) {
    api.get('/docs', (_req, res) => {
      res.set('Cache-Control', 'public, max-age=300').type('html').send(docsHtml);
    });
    api.get('/docs/assets/scalar.js', (_req, res, next) => {
      if (!scalarJs) return next();
      res.set({ 'Cache-Control': 'public, max-age=3600', ETag: scalarJs.etag }).type('js').send(scalarJs.body);
    });
  }

  // GET /api and /api/v1: a small index instead of 404, with the endpoints
  // that are switched on. A browser goes to the docs page if there is one.
  /** @type {import('express').RequestHandler} */
  const index = (req, res) => {
    switchedOff(config.features.apiIndex);
    if (config.apiDocs && req.accepts(['json', 'html']) === 'html') return void res.redirect(302, '/api/docs');
    res.json({
      name: 'Vanishly API',
      version,
      api: 'v1',
      ...(config.apiDocs ? { docs: '/api/docs' } : {}),
      openapi: '/api/openapi.json',
      endpoints: endpointsOn.map(([method, path]) => `${method} /api${path}`),
    });
  };
  api.get(['/', '/v1', '/v1/'], index);

  api.use((_req, _res, next) => next(new ApiError(404, 'not_found', 'No such endpoint')));
  api.use(
    /** @type {import('express').ErrorRequestHandler} */ ((err, req, res, _next) => {
      if (err instanceof ApiError) {
        res.locals.errorCode = err.code;
        // Refusals (401, 403, 429) not logged yet: "api.request_denied". Token
        // calls are in "api.token_used" with the reason anyway.
        if (audit && !res.locals.audited && !userOf(res)?.token && [401, 403, 429].includes(err.status)) {
          ev(req, res, 'api.request_denied', { outcome: 'denied', reason: err.code });
        }
        return void res.status(err.status).json({ error: err.code, message: err.message, ...err.extra });
      }
      if (err?.type === 'entity.too.large') {
        return void res.status(413).json({ error: 'too_large', message: 'The request is too large' });
      }
      if (err?.type === 'entity.parse.failed' || err?.status === 400) {
        return void res.status(400).json({ error: 'invalid_json', message: 'The body is not valid JSON' });
      }
      console.error(`api error: ${err?.message || err}`);
      res.status(500).json({ error: 'internal', message: 'Internal error' });
    }),
  );
  app.use('/api', api);

  const openapi = JSON.stringify(servedSpec(JSON.parse(readFileSync(join(ROOT, 'openapi', 'openapi.json'), 'utf8')), endpointsOn, version, config.features.apiIndex), null, 2);
  const docsHtml = readFileSync(join(ROOT, 'views', 'api-docs.html'), 'utf8');
  // vendor/scalar.js: built by `npm run vendor` (also in the image and the
  // tar.gz), without the external web fonts of the npm package.
  // Read once at start, served from memory.
  const scalarFile = join(ROOT, 'vendor', 'scalar.js');
  const scalarJs = config.apiDocs && existsSync(scalarFile) ? cached(readFileSync(scalarFile)) : null;
  if (config.apiDocs && !scalarJs) console.error('Vanishly: API docs page without vendor/scalar.js (run npm run vendor)');

  // ---------------------------------------------------------------- pages
  /** @param {import('express').Response} res */
  const lang = (res) => /** @type {string} */ (res.locals.lang);

  const COMMON = ['theme', 'created', 'error', 'reveal', 'receipt', 'gone', 'views', 'rule', 'home', 'a11y', 'auth', 'tokens', 'admin', 'policy', 'secrets', 'svc'];

  /**
   * "Sign in" or the signed-in user with "Sign out" in the header.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  const authNav = (req, res) => {
    if (!auth) return '';
    const t = theme.strings[lang(res)];
    const u = userOf(res);
    if (!u) {
      const back = RETURN.test(req.path) ? req.path : '/';
      return `<a class="nav-login" data-login href="/auth/login?return=${encodeURIComponent(back)}">${escapeHtml(t['nav.signIn'])}</a>`;
    }
    // A menu under the user's name (<details>: works with keyboard and without
    // script): the full name and address, "Sign out" and "another account".
    const name = u.name || u.user;
    const back = RETURN.test(req.path) ? req.path : '/';
    return (
      // Name and address always in full: they wrap and get smaller instead of being cut.
      `<details class="nav-menu"><summary class="nav-user">` +
      `<span class="nav-user-who"><span class="nav-user-name">${escapeHtml(name)}</span>` +
      // <wbr>: a long address breaks before "@" and after "." and "-", not in a word.
      (u.user && u.user !== name ? `<span class="nav-user-mail">${escapeHtml(u.user).replace(/@/g, '<wbr>@').replace(/([.-])/g, '$1<wbr>')}</span>` : '') +
      `</span><span class="nav-caret" aria-hidden="true"></span></summary>` +
      `<div class="nav-menu-panel">` +
      // API_TOKENS: the user's own tokens; admins: the audit log and all tokens.
      (tokens?.mayCreate(u) ? `<a class="nav-menu-item" href="/settings/tokens">${escapeHtml(t['nav.tokens'])}</a>` : '') +
      (auth.c.admin.ui && auth.isAdmin(u) ? `<a class="nav-menu-item" href="/admin">${escapeHtml(t['nav.admin'])}</a>` : '') +
      `<form class="nav-logout" method="post" action="/auth/logout"><button type="submit" class="nav-menu-item">${escapeHtml(t['nav.signOut'])}</button></form>` +
      `<form class="nav-switch" method="post" action="/auth/logout" data-login><input type="hidden" name="return" value="${escapeHtml(back)}">` +
      `<button type="submit" class="nav-menu-item">${escapeHtml(t['reveal.switchAccount'])}</button></form>` +
      `</div></details>`
    );
  };

  /**
   * @param {string} view
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {Record<string, any>} ctx
   */
  const page = (view, req, res, ctx) => {
    const signedOut = Boolean(auth) && !userOf(res);
    const bodyClasses = [
      // "New secret" in the header only for those who may create one.
      signedOut && auth?.c.createNeedsLogin ? 'no-new-link' : '',
      // AUTH_AUTO_LOGIN: the page script tries a silent sign-in once per tab.
      signedOut && auth?.c.autoLogin ? 'auto-login' : '',
    ].filter(Boolean);
    return theme.page(view, lang(res), { authNav: authNav(req, res), bodyClasses, ...ctx }, COMMON);
  };

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {number} status
   * @param {string} text
   */
  const errorPage = (req, res, status, text) => {
    const t = theme.strings[lang(res)];
    res.status(status).type('html').send(page('error', req, res, { page: 'error', title: t['error.title'], heading: t['error.title'], text }));
  };

  // ---------------------------------------------------------------- sign-in
  if (auth) {
    /** @param {import('express').Request} req */
    const authLimit = async (req) => (await store.rateLimit('auth', req.ip || '', config.rateRead, config.rateWindow)).ok;

    app.get('/auth/login', async (req, res) => {
      if (!(await authLimit(req))) return errorPage(req, res, 429, theme.strings[lang(res)]['error.ratelimit']);
      const back = typeof req.query.return === 'string' ? req.query.return : '/';
      try {
        res.redirect(303, await auth.loginUrl(back, req.query.fresh === '1', auth.c.autoLogin && req.query.silent === '1'));
      } catch (err) {
        console.error(`auth: sign-in provider not reachable: ${/** @type {Error} */ (err).message}`);
        errorPage(req, res, 502, theme.strings[lang(res)]['auth.unavailable']);
      }
    });

    app.get('/auth/callback', async (req, res) => {
      if (!(await authLimit(req))) return errorPage(req, res, 429, theme.strings[lang(res)]['error.ratelimit']);
      const i = req.originalUrl.indexOf('?');
      const search = i < 0 ? '' : req.originalUrl.slice(i);
      const providerError = typeof req.query.error === 'string' ? req.query.error.replace(/[^\w.-]/g, '').slice(0, 40) : '';
      try {
        // AUTH_AUTO_LOGIN: nobody signed in at the provider, so back to the page, no error.
        const declined = providerError ? await auth.silentDeclined(search) : null;
        if (declined) return res.redirect(303, declined);
        if (providerError) throw new Error(`the provider answered ${providerError}`);
        const { sid, returnTo, who } = await auth.callback(search);
        try {
          await ev(req, res, 'auth.login', { actor: { type: 'user', user: who.user, name: who.name } }, true);
        } catch {
          // AUDIT_LOG_FAIL=closed: no sign-in the audit log does not know of.
          await auth.dropSession(sid);
          return errorPage(req, res, 503, theme.strings[lang(res)]['auth.unavailable']);
        }
        // The user's API tokens act with the groups of this sign-in.
        await tokens?.refresh(who).catch(() => {});
        auth.setCookie(res, sid);
        res.redirect(303, returnTo);
      } catch (err) {
        console.error(`auth: sign-in failed: ${oneLine(/** @type {Error} */ (err).message)}`);
        await ev(req, res, 'auth.failed', { outcome: 'denied', reason: providerError || 'sign_in_failed' });
        errorPage(req, res, 400, theme.strings[lang(res)]['auth.failed']);
      }
    });

    // "Sign out", or "another account" on a secret that is not for this one.
    app.post('/auth/logout', express.urlencoded({ extended: false, limit: '1kb' }), async (req, res) => {
      const site = req.get('sec-fetch-site');
      if (site && site !== 'same-origin') return errorPage(req, res, 403, theme.strings[lang(res)]['error.generic']);
      if (userOf(res)) await ev(req, res, 'auth.logout');
      const idToken = await auth.logout(req, res);
      const back = typeof req.body?.return === 'string' && RETURN.test(req.body.return) ? req.body.return : '';
      // AUTH_LOGOUT=provider: end the provider's session too, or it signs the same account in again.
      try {
        const out = await auth.endSessionUrl(idToken, back);
        if (out) return res.redirect(303, out);
      } catch (err) {
        console.error(`auth: sign-out at the provider not possible: ${/** @type {Error} */ (err).message}`);
      }
      res.redirect(303, back ? `/auth/login?fresh=1&return=${encodeURIComponent(back)}` : '/');
    });

    // Back from the provider's logout; "another account" goes on to the sign-in.
    app.get('/auth/logged-out', (req, res) => {
      let back = '';
      try {
        back = typeof req.query.state === 'string' ? Buffer.from(req.query.state.slice(0, 200), 'base64url').toString() : '';
      } catch {
        back = '';
      }
      res.redirect(303, RETURN.test(back) && back !== '/' ? `/auth/login?fresh=1&return=${encodeURIComponent(back)}` : '/');
    });
  }

  /**
   * The "Only for" field of the form: addresses, and groups from
   * RECIPIENT_GROUPS (a dropdown, or a search with "*").
   * @param {import('express').Response} res
   */
  /** @param {import('express').Response} res can this sender choose recipients? */
  const recipientsOn = (res) => Boolean(auth && auth.c.recipients !== 'off' && userOf(res));
  /** The element ids of a picker (recipients keep theirs, responsible get a prefix). @param {'recipients' | 'responsible'} kind */
  const pickerIds = (kind) => {
    const p = kind === 'recipients' ? '' : 'responsible-';
    return {
      wrap: kind === 'recipients' ? 'recipients-wrap' : 'responsible-wrap',
      email: kind === 'recipients' ? 'recipient-email' : 'responsible-email',
      add: kind === 'recipients' ? 'recipient-add' : 'responsible-add',
      results: `${p}people-results`,
      status: `${p}people-status`,
      peopleHint: `${p}people-hint`,
      hint: kind === 'recipients' ? 'recipients-hint' : 'responsible-hint',
      list: kind === 'recipients' ? 'recipient-list' : 'responsible-list',
      group: kind === 'recipients' ? 'recipient-group' : 'responsible-group',
      groupAdd: kind === 'recipients' ? 'recipient-group-add' : 'responsible-group-add',
      groupSearch: `${p}group-search`,
      groupSearchHint: `${p}group-search-hint`,
      groupResults: `${p}group-results`,
      opt: kind === 'recipients' ? 'people-opt' : 'responsible-opt',
    };
  };
  /**
   * The picker for people and groups: "Only for these people" (recipients)
   * or "Responsible" (RESPONSIBLE), with the same people and group search.
   * @param {import('express').Response} res @param {'recipients' | 'responsible'} kind
   */
  const pickerBlock = (res, kind) => {
    if (!recipientsOn(res) && kind === 'recipients') return '';
    if (kind === 'responsible' && (config.responsible === 'off' || !auth || !userOf(res))) return '';
    const t = theme.strings[lang(res)];
    const ids = pickerIds(kind);
    const required = kind === 'recipients' ? auth.c.recipients === 'required' : config.responsible === 'required';
    const g = auth.c.groups;
    const people = Boolean(auth.c.userGroup);
    let groups = '';
    if (g.list.length) {
      const opts = g.list.map((x) => `<option value="${escapeHtml(x.id)}">${escapeHtml(x.name)}</option>`).join('');
      groups =
        `<label for="${ids.group}">${escapeHtml(t['home.recipientGroup'])}</label>` +
        `<div class="copy-row"><select id="${ids.group}"><option value="">${escapeHtml(t['home.recipientGroupPick'])}</option>${opts}</select>` +
        `<button type="button" class="btn" id="${ids.groupAdd}">${escapeHtml(t['home.recipientAdd'])}</button></div>`;
    } else if (g.any) {
      groups =
        `<label for="${ids.groupSearch}">${escapeHtml(t['home.groupSearch'])}</label>` +
        `<input type="search" id="${ids.groupSearch}" maxlength="64" autocomplete="off" aria-describedby="${ids.groupSearchHint}" aria-controls="${ids.groupResults}">` +
        `<div class="hint" id="${ids.groupSearchHint}">${escapeHtml(t['home.groupSearchHint'])}</div>` +
        `<ul class="plain group-results" id="${ids.groupResults}"></ul>`;
    }
    const domains = auth.c.domains.length ? ` ${t['home.recipientDomains'].replace('{list}', auth.c.domains.join(', '))}` : '';
    const legend = kind === 'recipients' ? (required ? t['home.recipientsRequired'] : t['home.recipients']) : required ? t['home.responsibleRequired'] : t['home.responsible'];
    const hint = kind === 'recipients' ? t['home.recipientsHint'] : t['home.responsibleHint'];
    const fieldset =
      `<fieldset class="field recipients${kind === 'responsible' ? ' responsible' : ''}" id="${ids.wrap}" data-kind="${kind}" data-max="${auth.c.recipientsMax}" data-required="${required ? '1' : '0'}"${people ? ' data-people="1"' : ''}>` +
      `<legend>${escapeHtml(legend)}</legend>` +
      (people
        ? // RECIPIENT_USER_GROUP: the same field searches people (ARIA combobox); an address typed in full still works.
          `<label for="${ids.email}">${escapeHtml(t['home.recipientPerson'])}</label>` +
          `<div class="copy-row combo"><input type="text" id="${ids.email}" maxlength="254" autocomplete="off" spellcheck="false" ` +
          `role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="${ids.results}" aria-describedby="${ids.peopleHint} ${ids.hint}">` +
          `<button type="button" class="btn" id="${ids.add}">${escapeHtml(t['home.recipientAdd'])}</button>` +
          `<ul class="suggestions" id="${ids.results}" role="listbox" aria-label="${escapeHtml(t['home.peopleResults'])}" hidden></ul></div>` +
          `<div class="hint" id="${ids.peopleHint}">${escapeHtml(t['home.peopleHint'])}</div>` +
          `<div class="suggestion-status" id="${ids.status}" role="status"></div>`
        : `<label for="${ids.email}">${escapeHtml(t['home.recipientEmail'])}</label>` +
          `<div class="copy-row"><input type="email" id="${ids.email}" maxlength="254" autocomplete="off" spellcheck="false" aria-describedby="${ids.hint}">` +
          `<button type="button" class="btn" id="${ids.add}">${escapeHtml(t['home.recipientAdd'])}</button></div>`) +
      groups +
      `<ul class="chips" id="${ids.list}" aria-label="${escapeHtml(t['home.recipientList'])}"></ul>` +
      `<div class="hint" id="${ids.hint}">${escapeHtml(hint + domains)}</div>` +
      `</fieldset>`;
    if (kind === 'recipients') return fieldset;
    // Responsible: folded away unless required.
    return `<details class="field responsible-box"${required ? ' open' : ''}><summary>${escapeHtml(legend)}</summary>${fieldset}</details>`;
  };
  /** @param {import('express').Response} res */
  const recipientsBlock = (res) => pickerBlock(res, 'recipients') + pickerBlock(res, 'responsible');

  app.get('/', (req, res) => {
    const t = theme.strings[lang(res)];
    const user = userOf(res);
    if (auth?.c.createNeedsLogin && !user) {
      return void res.type('html').send(
        page('login', req, res, { page: 'login', title: t['auth.title'], heading: t['auth.title'], text: t['auth.createText'], returnTo: '/' }),
      );
    }
    const ttlSelect = ttlOptions
      .map((s) => `<option value="${s}"${s === config.defaultTtl ? ' selected' : ''}>${escapeHtml(duration(s, t))}</option>`)
      .join('');
    const confirmText = confirmRule(lang(res));
    const confirmBlock = config.confirmCheckbox
      ? `<div class="field check"><input type="checkbox" id="confirm" name="confirm" required><label for="confirm">${escapeHtml(confirmText)}</label></div>`
      : '';
    const viewsSelect = Array.from({ length: config.maxViews }, (_, i) => i + 1)
      .filter((n) => n <= 5 || n % 5 === 0 || n === config.maxViews)
      .map((n) => {
        const t = theme.strings[lang(res)];
        const label = n === 1 ? t['views.1'] : t['views.n'].replace('{n}', String(n));
        return `<option value="${n}">${label}</option>`;
      })
      .join('');
    // AUDIT_COMMENT: what the secret is for; into the audit log, not the secret.
    const cm = config.comment;
    const commentBlock =
      cm.mode === 'off'
        ? ''
        : `<div class="field" id="comment-wrap"><label for="comment">${escapeHtml(t[cm.mode === 'required' ? 'home.commentRequired' : 'home.comment'])}</label>` +
          `<input type="text" id="comment" name="comment" maxlength="${cm.max}" autocomplete="off" aria-describedby="comment-hint"${cm.mode === 'required' ? ' aria-required="true" data-required="1"' : ''}>` +
          `<div class="hint" id="comment-hint">${escapeHtml(t['home.commentHint'])}</div></div>`;
    res.type('html').send(
      page('home', req, res, {
          page: 'home',
          recipientsBlock: recipientsBlock(res) + commentBlock,
          ttlSelect,
          viewsSelect,
          maxChars: config.maxSecretChars,
          minChars: config.minSecretChars,
          minPass: config.minPassphraseLength,
          // unless-recipients: required until a recipient is chosen (the
          // page script switches it); without the recipients field always.
          passRequired: config.passphraseRule === 'always' || (config.passphraseRule === 'unless-recipients' && !recipientsOn(res)) ? '1' : config.passphraseRule === 'unless-recipients' ? 'unless-recipients' : '0',
          passLabel: config.passphraseRule === 'off' ? t['home.passphrase'] : t['home.passphraseRequired'],
          passLabelRequired: t['home.passphraseRequired'],
          passLabelOptional: t['home.passphrase'],
          secretRule: config.minSecretChars > 1 ? t['home.minChars'].replace('{n}', String(config.minSecretChars)) : '',
          confirmBlock,
          passClasses: config.passphraseClasses.join(','),
          genLength: config.generatorLength,
          genSets: config.generatorClasses.join(','),
          passRule: [
            config.minPassphraseLength > 0 ? t['home.minChars'].replace('{n}', String(config.minPassphraseLength)) : '',
            config.passphraseClasses.length
              ? t['home.passNeeds'].replace('{list}', config.passphraseClasses.map((c) => t[`rule.${c}`]).join(', '))
              : '',
          ]
            .filter(Boolean)
            .join(' '),
        }),
    );
  });

  app.get('/s/:id', async (req, res) => {
    const id = String(req.params.id);
    const m = validId(id) ? await store.meta(id) : null;
    const t = theme.strings[lang(res)];
    if (!m) {
      return void res
        .status(404)
        .type('html')
        .send(page('error', req, res, { page: 'gone', title: t['gone.title'], heading: t['gone.title'], text: t['gone.text'] }));
    }
    // A restricted secret: "sign in" or "not for this account", checked
    // without using a view.
    let locked = '';
    const user = userOf(res);
    if (m.restricted) {
      if (!user) locked = 'login';
      else if (!Auth.allowed(user, (await store.recipients(id)) || [])) locked = 'denied';
    }
    res.type('html').send(
      page('secret', req, res, {
          page: 'secret',
          locked,
          lockedText: locked === 'login' ? t['reveal.lockedLogin'] : locked === 'denied' ? t['reveal.lockedDenied'].replace('{name}', user?.user || user?.name || '') : '',
          title: t['reveal.title'],
          id,
          // Locked: nothing about the secret (passphrase, views) for others.
          passphrase: m.passphrase && !locked ? '1' : '0',
          // What the browser needs to derive the passphrase verifier, so the
          // reveal works without GET /v1/secrets/{id} (ENABLE_SECRET_META_API).
          salt: m.passphrase && !locked ? m.salt : '',
          iterations: m.passphrase && !locked ? String(m.iterations) : '',
          viewsLeft: locked ? '' : m.viewsLeft,
          // One view (the default): no counter, just "only once".
          intro: locked
            ? t['reveal.introRestricted']
            : m.viewsLeft === 1
              ? t['reveal.introOnce']
              : t['reveal.intro'].replace('{n}', String(m.viewsLeft)),
        }),
    );
  });

  // API_TOKENS: the user's own tokens ("API tokens" in the user menu).
  app.get('/settings/tokens', async (req, res, next) => {
    if (!tokens) return next();
    const t = theme.strings[lang(res)];
    const u = userOf(res);
    if (!u) return void res.type('html').send(page('login', req, res, { page: 'login', title: t['tokens.title'], heading: t['tokens.title'], text: t['tokens.loginText'], returnTo: '/settings/tokens' }));
    const c = tokens.c;
    const expirySelect = c.expiryOptions
      .map((o) => `<option value="${escapeHtml(o)}"${o === c.defaultExpiry ? ' selected' : ''}>${escapeHtml(o === 'never' ? t['tokens.never'] : (t[`tokens.unit.${o.slice(-1)}.${o.slice(0, -1) === '1' ? 1 : 'n'}`] || o).replace('{n}', o.slice(0, -1)))}</option>`)
      .join('');
    // What this user may give a token: "only create", "only read (pull)",
    // "both" as far as the policy allows, and "status" as a box of its own.
    const policy = await tokens.policy(u.user, u.ids);
    const def = tokens.defaultScopes(policy);
    const may = (/** @type {string} */ sc) => policy.scopes.includes(sc);
    const access = /** @type {[string, boolean][]} */ ([
      ['create', may('create')],
      ['read', may('read')],
      ['both', may('create') && may('read')],
    ]).filter(([, on]) => on).map(([v]) => v);
    const preset = def.includes('create') && def.includes('read') ? 'both' : def.includes('read') ? 'read' : access[0];
    const scopeBoxes =
      access.map((v) => `<div class="check"><input type="radio" id="access-${v}" name="access" value="${v}"${v === preset ? ' checked' : ''}><label for="access-${v}">${escapeHtml(t[`tokens.access.${v}`])}</label></div>`).join('') +
      (may('status') ? `<div class="check"><input type="checkbox" id="scope-status" name="scopes" value="status"${def.includes('status') ? ' checked' : ''}><label for="scope-status">${escapeHtml(t['tokens.scope.status'])}</label></div>` : '');
    res.type('html').send(
      page('tokens', req, res, {
        page: 'tokens',
        title: t['tokens.title'],
        allowed: tokens.mayCreate(u) && policy.scopes.length ? '1' : '0',
        maxPerUser: String(policy.max),
        expirySelect,
        scopeBoxes,
        ipsLabel: t[c.ipBinding === 'required' ? 'tokens.ipsRequired' : 'tokens.ips'],
        ipsRequired: c.ipBinding === 'required' ? '1' : '0',
        ipsHint: t['tokens.ipsHint'].replace('{ip}', String(req.ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1')),
        commentNote: c.comment === 'required' ? t['tokens.commentRequired'] : '',
        origin: config.baseUrl || `${req.protocol}://${req.get('host')}`,
      }),
    );
  });

  // Admins: the audit log (filter, export, chain check) and all API tokens.
  app.get('/admin', async (req, res, next) => {
    if (!auth?.c.admin.ui || (!auth.c.admin.users.length && !auth.c.admin.groups.length)) return next();
    const t = theme.strings[lang(res)];
    const u = userOf(res);
    if (!u) return void res.type('html').send(page('login', req, res, { page: 'login', title: t['admin.title'], heading: t['admin.title'], text: t['admin.loginText'], returnTo: '/admin' }));
    if (!auth.isAdmin(u)) {
      await ev(req, res, 'admin.denied', { outcome: 'denied', reason: 'not_admin' });
      return errorPage(req, res, 403, t['admin.notAllowed']);
    }
    // The tabs that are switched on; ?tab= picks one.
    const st = await adminStatus();
    const tabs = /** @type {[string, boolean][]} */ ([
      ['audit', auth.c.admin.auditView],
      ['secrets', st.auditRedis],
      ['tokens', st.tokens],
      ['services', st.services],
      ['policies', st.policies],
    ]).filter(([, on]) => on).map(([k]) => k);
    const tab = tabs.includes(String(req.query.tab)) ? String(req.query.tab) : tabs[0] || '';
    const adminTabs = tabs.map((k) => `<a href="/admin?tab=${k}"${k === tab ? ' aria-current="page"' : ''}>${escapeHtml(t[`admin.tab.${k}`])}</a>`).join('');
    // Redis must keep the audit stream and the tokens: say when it does not.
    const adminWarnings = st.warnings.map((w) => `<p class="notice notice-error">${escapeHtml(t[`admin.warn.${w}`])}</p>`).join('');
    res.type('html').send(
      page('admin', req, res, {
        page: 'admin',
        title: t['admin.heading'],
        tab,
        adminTabs,
        adminWarnings,
        services: st.services ? '1' : '0',
        adminScope: st.adminTokens ? '1' : '0',
        audit: auth.c.admin.auditView ? '1' : '0',
        verify: auth.c.admin.auditView && audit?.c.file ? '1' : '0',
        tokens: tokens ? '1' : '0',
        policies: tokens?.c.adminPolicy ? '1' : '0',
      }),
    );
  });

  app.get('/r/:id', (req, res, next) => {
    if (!config.features.receipts) return next();
    const id = String(req.params.id);
    const t = theme.strings[lang(res)];
    if (!validId(id)) return errorPage(req, res, 404, t['receipt.notfound']);
    res.type('html').send(page('receipt', req, res, { page: 'receipt', title: t['receipt.title'], id }));
  });

  app.use((req, res) => errorPage(req, res, 404, theme.strings[lang(res)]['error.notfound']));

  app.use(
    /** @type {import('express').ErrorRequestHandler} */ ((err, _req, res, _next) => {
      console.error(`error: ${err?.message || err}`);
      const t = theme.strings[lang(res)] || theme.strings.en;
      res
        .status(500)
        .type('html')
        .send(theme.page('error', lang(res) || 'en', { page: 'error', title: t['error.title'], heading: t['error.title'], text: t['error.generic'] }, COMMON));
    }),
  );

  return app;
}
