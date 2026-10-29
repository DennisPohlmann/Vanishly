// Vanishly - HTTP app: pages, JSON API (openapi/openapi.json), static files.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import express from 'express';
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
 * @param {{ config: import('./config.js').Config, store: import('./store.js').Store,
 *   theme: import('./theme.js').Theme, version: string, auth?: Auth | null }} deps
 */
export function createApp({ config, store, theme, version, auth: authIn }) {
  const app = express();
  // Sign-in (AUTH_PROVIDER); null = off, Vanishly works without any login.
  const auth = authIn === undefined ? (config.auth ? new Auth(config.auth, store) : null) : authIn;
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

  // Access log without IPs, user agents or the ids of secrets and receipts.
  if (config.accessLog) {
    app.use((req, res, next) => {
      const start = process.hrtime.bigint();
      res.on('finish', () => {
        const ms = Number(process.hrtime.bigint() - start) / 1e6;
        const path = req.originalUrl.split('?')[0].replace(/[A-Za-z0-9_-]{22}/g, ':id');
        console.log(`${req.method} ${path} ${res.statusCode} ${ms.toFixed(1)}ms`);
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
        res.locals.user = await auth.user(req);
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
  app.get('/theme/theme.css', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=3600');
    res.sendFile(join(theme.dir, 'theme.css'));
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
  ];
  const endpointsOn = endpointTable.filter(([on]) => on).map(([, method, path]) => /** @type {[string, string]} */ ([method, path]));
  api.use(express.json({ limit: Math.max(64 * 1024, maxCtLen * 2) }));

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
  /** @param {any} b @param {import('express').Response} res */
  const recipientsOf = (b, res) => {
    const users = b.recipients ?? [];
    const groups = b.recipientGroups ?? [];
    if (!Array.isArray(users) || !Array.isArray(groups)) {
      throw new ApiError(400, 'invalid_recipients', 'recipients and recipientGroups must be arrays');
    }
    if (!users.length && !groups.length) {
      if (auth?.c.recipients === 'required') throw new ApiError(400, 'recipients_required', 'This server requires at least one recipient');
      return [];
    }
    if (!auth || auth.c.recipients === 'off') throw new ApiError(400, 'recipients_disabled', 'Recipients are switched off on this server');
    if (!userOf(res)) throw new ApiError(401, 'login_required', 'Sign in to choose recipients');
    if (users.length + groups.length > auth.c.recipientsMax) {
      throw new ApiError(400, 'too_many_recipients', `At most ${auth.c.recipientsMax} recipients`, { max: auth.c.recipientsMax });
    }
    const ids = new Set();
    for (const u of users) {
      if (!Auth.validEmail(u)) throw new ApiError(400, 'invalid_recipient', 'A recipient is not a valid e-mail address', { recipient: String(u).slice(0, 254) });
      if (!auth.domainAllowed(u)) {
        throw new ApiError(400, 'recipient_domain', `Recipients must have an address of ${auth.c.domains.join(', ')}`, { recipient: u, domains: auth.c.domains });
      }
      ids.add(auth.hash('u', u));
    }
    if (groups.length && !auth.c.groups.any && !auth.c.groups.list.length) {
      throw new ApiError(400, 'groups_disabled', 'Groups as recipients are switched off on this server');
    }
    for (const g of groups) {
      if (typeof g !== 'string' || !auth.groupAllowed(g)) throw new ApiError(400, 'invalid_group', 'A group is unknown or not allowed', { group: String(g).slice(0, 200) });
      ids.add(auth.hash('g', auth.c.provider === 'entra' ? g.toLowerCase() : g));
    }
    return [...ids];
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
  /** @param {import('express').Response} res */
  const viewerName = (res) => (auth?.c.showViewer ? userOf(res)?.name || userOf(res)?.user || '' : '');

  // ENABLE_API=false: the API only answers the pages of this server. Browsers
  // mark their own fetches with Sec-Fetch-Site; scripts could fake that
  // header, so this hides the API from casual use but is no access control.
  /** @param {import('express').Request} req */
  const fromPage = (req) => req.get('sec-fetch-site') === 'same-origin';
  if (!config.api) {
    api.use((req, _res, next) => {
      const own = fromPage(req) && /^\/v1\/(secrets|receipts|me|groups|people)(\/|$)/.test(req.path);
      // Known paths: switched off; anything else falls through to not_found.
      const known = /^\/(v1(\/(config|secrets|share|open|receipts|me|groups|people)(\/.*)?)?\/?|openapi\.json|docs(\/.*)?)?$/.test(req.path);
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
    const to = recipientsOf(b, res);
    const noPass = b.verifier ? null : passphraseNeeded(to);
    if (noPass) throw noPass;
    const { ttl, views } = options(b);
    const s = await store.create(
      { ciphertext: b.ciphertext, iv: b.iv, salt: b.salt, iterations: b.iterations, verifier: b.verifier || undefined },
      ttl,
      views,
      to,
    );
    res.status(201).json(created(s));
  });

  // Encrypts on the server for scripts without crypto (curl): the key is
  // returned in the links and forgotten right away.
  api.post('/v1/share', limit('create'), async (req, res) => {
    if (!config.features.shareApi) throw disabled();
    mayCreate(res);
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
    const to = recipientsOf(b, res);
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
    const s = await store.create(payload, ttl, views, to);
    const o = origin(req);
    res.status(201).json({
      ...created(s),
      shareUrl: `${o}/s/${s.id}#${key}`,
      receiptUrl: s.receiptId ? `${o}/r/${s.receiptId}${config.features.receiptShareLink ? `#${key}` : ''}` : null,
    });
  });

  api.get('/v1/secrets/:id', limit('read'), async (req, res) => {
    switchedOff(config.features.secretMetaApi);
    const id = String(req.params.id);
    // Restricted: the salt and the views only for a recipient.
    await mayOpen(id, res);
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
    await mayOpen(id, res);
    const r = validId(id) ? await store.reveal(id, verifier || undefined, viewerName(res)) : /** @type {const} */ ({ status: 'notfound' });
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
    const b = req.body || {};
    const m = typeof b.link === 'string' ? /\/s\/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$/.exec(b.link.trim()) : null;
    if (!m) throw new ApiError(400, 'invalid_link', 'link must be a full secret link: https://.../s/<id>#<key>');
    if (b.passphrase !== undefined && (typeof b.passphrase !== 'string' || b.passphrase.length > 1000)) {
      throw new ApiError(400, 'invalid_passphrase', 'passphrase must be a string of at most 1000 characters');
    }
    const [, id, key] = m;
    await mayOpen(id, res);
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
    const r = await store.reveal(id, verifier, viewerName(res));
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
    const id = String(req.params.id);
    const r = validId(id) ? await store.receipt(id) : null;
    if (!r) throw new ApiError(404, 'not_found', 'Unknown or too old');
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
    });
  });

  api.post('/v1/receipts/:id/burn', receiptsOn, limit('read'), async (req, res) => {
    pagesOnly(config.features.receiptApi, req);
    if (!config.features.burn) throw disabled();
    const id = String(req.params.id);
    const r = validId(id) ? await store.burn(id) : null;
    if (r === null) throw new ApiError(404, 'not_found', 'Unknown or too old');
    if (!r) throw new ApiError(409, 'gone', 'The secret is already gone');
    res.json({ state: 'burned' });
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
      res.set('Cache-Control', 'public, max-age=3600');
      res.sendFile(scalarJs);
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
    /** @type {import('express').ErrorRequestHandler} */ ((err, _req, res, _next) => {
      if (err instanceof ApiError) {
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
  const scalarJs = existsSync(join(ROOT, 'vendor', 'scalar.js')) ? join(ROOT, 'vendor', 'scalar.js') : null;
  if (config.apiDocs && !scalarJs) console.error('Vanishly: API docs page without vendor/scalar.js (run npm run vendor)');

  // ---------------------------------------------------------------- pages
  /** @param {import('express').Response} res */
  const lang = (res) => /** @type {string} */ (res.locals.lang);

  const COMMON = ['theme', 'created', 'error', 'reveal', 'receipt', 'gone', 'views', 'rule', 'home', 'a11y', 'auth'];

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
    return (
      `<span class="nav-user" title="${escapeHtml(u.user)}">${escapeHtml(u.name || u.user)}</span>` +
      `<form class="nav-logout" method="post" action="/auth/logout"><button type="submit" class="btn btn-small btn-ghost">${escapeHtml(t['nav.signOut'])}</button></form>`
    );
  };

  /**
   * @param {string} view
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {Record<string, any>} ctx
   */
  const page = (view, req, res, ctx) => theme.page(view, lang(res), { authNav: authNav(req, res), ...ctx }, COMMON);

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
        res.redirect(303, await auth.loginUrl(back, req.query.fresh === '1'));
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
        if (providerError) throw new Error(`the provider answered ${providerError}`);
        const { sid, returnTo } = await auth.callback(search);
        auth.setCookie(res, sid);
        res.redirect(303, returnTo);
      } catch (err) {
        console.error(`auth: sign-in failed: ${/** @type {Error} */ (err).message}`);
        errorPage(req, res, 400, theme.strings[lang(res)]['auth.failed']);
      }
    });

    // "Sign out", or "another account" on a secret that is not for this one.
    app.post('/auth/logout', express.urlencoded({ extended: false, limit: '1kb' }), async (req, res) => {
      const site = req.get('sec-fetch-site');
      if (site && site !== 'same-origin') return errorPage(req, res, 403, theme.strings[lang(res)]['error.generic']);
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
  const recipientsBlock = (res) => {
    if (!recipientsOn(res)) return '';
    const t = theme.strings[lang(res)];
    const required = auth.c.recipients === 'required';
    const g = auth.c.groups;
    const people = Boolean(auth.c.userGroup);
    let groups = '';
    if (g.list.length) {
      const opts = g.list.map((x) => `<option value="${escapeHtml(x.id)}">${escapeHtml(x.name)}</option>`).join('');
      groups =
        `<label for="recipient-group">${escapeHtml(t['home.recipientGroup'])}</label>` +
        `<div class="copy-row"><select id="recipient-group"><option value="">${escapeHtml(t['home.recipientGroupPick'])}</option>${opts}</select>` +
        `<button type="button" class="btn" id="recipient-group-add">${escapeHtml(t['home.recipientAdd'])}</button></div>`;
    } else if (g.any) {
      groups =
        `<label for="group-search">${escapeHtml(t['home.groupSearch'])}</label>` +
        `<input type="search" id="group-search" maxlength="64" autocomplete="off" aria-describedby="group-search-hint" aria-controls="group-results">` +
        `<div class="hint" id="group-search-hint">${escapeHtml(t['home.groupSearchHint'])}</div>` +
        `<ul class="plain group-results" id="group-results"></ul>`;
    }
    const domains = auth.c.domains.length ? ` ${t['home.recipientDomains'].replace('{list}', auth.c.domains.join(', '))}` : '';
    return (
      `<fieldset class="field recipients" id="recipients-wrap" data-max="${auth.c.recipientsMax}" data-required="${required ? '1' : '0'}"${people ? ' data-people="1"' : ''}>` +
      `<legend>${escapeHtml(required ? t['home.recipientsRequired'] : t['home.recipients'])}</legend>` +
      (people
        ? // RECIPIENT_USER_GROUP: the same field searches people (ARIA combobox); an address typed in full still works.
          `<label for="recipient-email">${escapeHtml(t['home.recipientPerson'])}</label>` +
          `<div class="copy-row combo"><input type="text" id="recipient-email" maxlength="254" autocomplete="off" spellcheck="false" ` +
          `role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="people-results" aria-describedby="people-hint recipients-hint">` +
          `<button type="button" class="btn" id="recipient-add">${escapeHtml(t['home.recipientAdd'])}</button>` +
          `<ul class="suggestions" id="people-results" role="listbox" aria-label="${escapeHtml(t['home.peopleResults'])}" hidden></ul></div>` +
          `<div class="hint" id="people-hint">${escapeHtml(t['home.peopleHint'])}</div>` +
          `<div class="suggestion-status" id="people-status" role="status"></div>`
        : `<label for="recipient-email">${escapeHtml(t['home.recipientEmail'])}</label>` +
          `<div class="copy-row"><input type="email" id="recipient-email" maxlength="254" autocomplete="off" spellcheck="false" aria-describedby="recipients-hint">` +
          `<button type="button" class="btn" id="recipient-add">${escapeHtml(t['home.recipientAdd'])}</button></div>`) +
      groups +
      `<ul class="chips" id="recipient-list" aria-label="${escapeHtml(t['home.recipientList'])}"></ul>` +
      `<div class="hint" id="recipients-hint">${escapeHtml(t['home.recipientsHint'] + domains)}</div>` +
      `</fieldset>`
    );
  };

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
    res.type('html').send(
      page('home', req, res, {
          page: 'home',
          recipientsBlock: recipientsBlock(res),
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
