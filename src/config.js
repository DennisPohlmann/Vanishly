// Vanishly - settings from the environment (see .env.example and docs/CONFIG.md).

import { readFileSync } from 'node:fs';

/**
 * @param {string | undefined} v
 * @param {number} def
 * @param {number} min
 * @param {number} max
 */
function int(v, def, min, max) {
  if (v === undefined || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`invalid number ${JSON.stringify(v)} (allowed ${min}..${max})`);
  }
  return n;
}

/**
 * A switch: true/false (also 1/0, yes/no, on/off); empty = the default.
 * @param {string | undefined} v
 * @param {boolean} def
 */
function flag(v, def) {
  if (v === undefined || v === '') return def;
  if (/^(1|true|yes|on)$/i.test(v)) return true;
  if (/^(0|false|no|off)$/i.test(v)) return false;
  throw new Error(`invalid switch ${JSON.stringify(v)} (true or false)`);
}

/** @param {string | undefined} v */
function trustProxy(v) {
  if (!v || /^(0|false|no|off)$/i.test(v)) return false;
  if (/^\d+$/.test(v)) return Number(v);
  if (/^(1|true|yes|on)$/i.test(v)) return 1;
  // "loopback", "10.0.0.0/8, fd00::/8", passed to express
  for (const part of v.split(/\s*,\s*/)) {
    if (!/^(loopback|linklocal|uniquelocal|[0-9a-f.:]+(\/\d{1,3})?)$/i.test(part)) {
      throw new Error(`"${part}" is no number, IP address, network or loopback/linklocal/uniquelocal`);
    }
  }
  return v;
}

const UNITS = /** @type {Record<string, number>} */ ({ s: 1, m: 60, h: 3600, d: 86400, w: 604800 });

/**
 * "5m,1h,1d,7d" (or seconds) to sorted seconds.
 * @param {string} v
 */
export function parseDurations(v) {
  const out = new Set();
  for (const part of v.split(/[\s,;]+/).filter(Boolean)) {
    const m = /^(\d+)([smhdw]?)$/i.exec(part);
    if (!m) throw new Error(`"${part}" is not a duration like 30m, 12h, 7d or 2w`);
    const s = Number(m[1]) * UNITS[(m[2] || 's').toLowerCase()];
    if (s < 60 || s > 365 * 86400) throw new Error(`"${part}" must be from 1 minute to 1 year`);
    out.add(s);
  }
  if (!out.size) throw new Error('empty');
  return [...out].sort((a, b) => a - b);
}

/**
 * @template T
 * @param {string} name
 * @param {() => T} fn
 */
function named(name, fn) {
  try {
    return fn();
  } catch (err) {
    throw new Error(`${name}: ${/** @type {Error} */ (err).message}`);
  }
}

/**
 * "upper,lower,digit,symbol" (any subset) to a list; "all" = all four.
 * @param {string} v
 */
function classes(v) {
  const all = ['upper', 'lower', 'digit', 'symbol'];
  const list = v.toLowerCase().split(/[\s,;]+/).filter(Boolean);
  if (list.includes('all')) return all;
  for (const c of list) if (!all.includes(c)) throw new Error(`"${c}" is not one of ${all.join(', ')}, all`);
  return all.filter((c) => list.includes(c));
}

// Every setting this app reads. A name one or two letters off one of these
// is a typo (ENABLE_VEIWS) and stops the start, like any invalid value.
export const SETTINGS = [
  'PORT', 'HOST', 'BASE_URL', 'REDIS_URL', 'REDIS_URL_FILE', 'REDIS_TLS_CA_FILE', 'REDIS_PREFIX', 'TRUST_PROXY', 'HSTS',
  'TEMPLATE', 'TEMPLATES_DIR', 'TRANSLATIONS_DIR', 'LANGUAGES', 'DEFAULT_LANG', 'DEFAULT_MODE',
  'TTL_OPTIONS', 'DEFAULT_TTL', 'MAX_TTL', 'MAX_VIEWS', 'MAX_SECRET_CHARS', 'MIN_SECRET_CHARS',
  'MIN_PASSPHRASE_LENGTH', 'PASSPHRASE_COMPLEXITY', 'REQUIRE_PASSPHRASE', 'PASSPHRASE_ATTEMPTS',
  'CONFIRM_CHECKBOX', 'CONFIRM_TEXT', 'CONFIRM_TEXT_EN', 'CONFIRM_TEXT_DE',
  'GENERATOR_LENGTH', 'GENERATOR_COMPLEXITY', 'RECEIPT_KEEP',
  'RATE_LIMIT_CREATE', 'RATE_LIMIT_READ', 'RATE_LIMIT_WINDOW',
  'API_DOCS', 'ACCESS_LOG',
  'ENABLE_API', 'ENABLE_API_DOCS', 'ENABLE_API_LINK', 'ENABLE_SHARE_API', 'ENABLE_OPEN_API',
  'ENABLE_SECRET_META_API', 'ENABLE_CONFIG_API', 'ENABLE_ME_API',
  'ENABLE_CREATE_API', 'ENABLE_REVEAL_API', 'ENABLE_RECEIPT_API', 'ENABLE_API_INDEX',
  'ENABLE_PASSPHRASE', 'ENABLE_VIEWS', 'ENABLE_RECEIPTS', 'ENABLE_BURN', 'ENABLE_VIEW_LOG',
  'ENABLE_RECEIPT_SHARE_LINK', 'ENABLE_GENERATOR', 'ENABLE_LANG_SWITCH', 'ENABLE_THEME_TOGGLE',
  'ENABLE_GITHUB_LINK', 'VANISHLY_VERSION',
  'AUTH_PROVIDER', 'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET', 'ENTRA_CLIENT_SECRET_FILE',
  'ENTRA_AUTHORITY', 'ENTRA_GRAPH', 'ENTRA_GRAPH_URL', 'OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET',
  'OIDC_CLIENT_SECRET_FILE', 'OIDC_SCOPES', 'AUTH_SECRET', 'AUTH_SECRET_FILE', 'AUTH_SESSION_TTL', 'AUTH_CREATE', 'AUTH_API_AUDIENCE', 'RECIPIENTS', 'RECIPIENTS_MAX', 'RECIPIENT_GROUPS',
  'RECIPIENT_USER_GROUP', 'RECIPIENT_DOMAINS', 'RECEIPT_SHOW_VIEWER',
];
const AUTH_SETTINGS = SETTINGS.slice(SETTINGS.indexOf('ENTRA_TENANT_ID'));
/**
 * Edit distance (insert, delete, replace, swap of two neighbours).
 * @param {string} a
 * @param {string} b
 */
function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A secret value: NAME, or the first line of the file in NAME_FILE (Docker secrets).
 * @param {NodeJS.ProcessEnv} env
 * @param {string} name
 */
function secretValue(env, name) {
  const file = env[`${name}_FILE`];
  if (env[name] && file) throw new Error(`${name} and ${name}_FILE are both set; use one`);
  if (!file) return env[name] || '';
  try {
    return readFileSync(file, 'utf8').split(/\r?\n/)[0].trim();
  } catch (err) {
    throw new Error(`${name}_FILE: cannot read ${file} (${/** @type {NodeJS.ErrnoException} */ (err).code || 'error'})`);
  }
}

/**
 * RECIPIENT_GROUPS: empty (no groups), "*" (search the tenant via Graph) or
 * "Name=<group>,..." (the groups a sender may pick from): with Entra the
 * group object id, otherwise the value in the "groups" claim.
 * @param {string} v
 * @param {boolean} entra
 * @returns {{ any: boolean, list: { name: string, id: string }[] }}
 */
function recipientGroups(v, entra) {
  if (!v.trim()) return { any: false, list: [] };
  if (v.trim() === '*') return { any: true, list: [] };
  const list = [];
  for (const part of v.split(',').map((p) => p.trim()).filter(Boolean)) {
    const m = /^([^=]{1,64})=([^=\s]{1,200})$/.exec(part);
    if (!m || (entra && !GUID.test(m[2]))) {
      throw new Error(`"${part}" is not Name=${entra ? '<group object id> (a GUID)' : '<value of the groups claim>'}`);
    }
    list.push({ name: m[1].trim(), id: entra ? m[2].toLowerCase() : m[2] });
  }
  if (!list.length) throw new Error('empty');
  return { any: false, list };
}

/**
 * Optional sign-in (AUTH_PROVIDER=entra or oidc); null = off.
 * @param {NodeJS.ProcessEnv} env
 * @param {string} baseUrl
 */
function authConfig(env, baseUrl) {
  const provider = env.AUTH_PROVIDER || 'none';
  if (!/^(none|entra|oidc)$/.test(provider)) throw new Error('AUTH_PROVIDER: none, entra or oidc');
  if (provider === 'none') {
    const set = AUTH_SETTINGS.find((k) => env[k]);
    if (set) throw new Error(`${set} needs AUTH_PROVIDER=entra or oidc`);
    return null;
  }
  const entra = provider === 'entra';
  const other = AUTH_SETTINGS.find((k) => env[k] && k.startsWith(entra ? 'OIDC_' : 'ENTRA_'));
  if (other) throw new Error(`${other} does not apply to AUTH_PROVIDER=${provider}`);
  /** @param {string} name */
  const need = (name) => {
    if (!env[name]) throw new Error(`${name} is required with AUTH_PROVIDER=${provider}`);
    return env[name] || '';
  };
  if (!baseUrl) throw new Error(`BASE_URL is required with AUTH_PROVIDER=${provider} (it gives the redirect URI)`);
  // https only; plain http just for a test server on this machine.
  /** @param {string} name @param {string} def @param {boolean} [path] */
  const url = (name, def, path = false) => {
    const v = (env[name] || def).replace(/\/+$/, '');
    const re = path ? /^https:\/\/[^/\s]+(\/\S*)?$/ : /^https:\/\/[^/\s]+$/;
    const local = path ? /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/\S*)?$/ : /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
    if (!re.test(v) && !local.test(v)) throw new Error(`${name}: an https:// address${path ? '' : ' without a path'}, e.g. ${def}`);
    return v;
  };
  const prefix = entra ? 'ENTRA' : 'OIDC';
  let tenant = '';
  let issuer;
  let authority = '';
  if (entra) {
    tenant = need('ENTRA_TENANT_ID').toLowerCase();
    if (!GUID.test(tenant)) throw new Error('ENTRA_TENANT_ID: the directory (tenant) id, a GUID');
    authority = url('ENTRA_AUTHORITY', 'https://login.microsoftonline.com');
    issuer = `${authority}/${tenant}/v2.0`;
  } else {
    need('OIDC_ISSUER');
    issuer = url('OIDC_ISSUER', 'https://login.example.com/realms/main', true);
  }
  const clientId = need(`${prefix}_CLIENT_ID`);
  if (entra && !GUID.test(clientId)) throw new Error('ENTRA_CLIENT_ID: the application (client) id, a GUID');
  if (!/^[\w.:@/-]{1,200}$/.test(clientId)) throw new Error(`${prefix}_CLIENT_ID: letters, digits and _ . : @ / -`);
  const clientSecret = named(`${prefix}_CLIENT_SECRET`, () => secretValue(env, `${prefix}_CLIENT_SECRET`));
  if (!clientSecret) throw new Error(`${prefix}_CLIENT_SECRET (or ${prefix}_CLIENT_SECRET_FILE) is required with AUTH_PROVIDER=${provider}`);
  const secret = named('AUTH_SECRET', () => secretValue(env, 'AUTH_SECRET'));
  if (secret.length < 32) throw new Error('AUTH_SECRET: at least 32 characters (e.g. openssl rand -base64 48)');
  if (secret === clientSecret) throw new Error(`AUTH_SECRET must differ from ${prefix}_CLIENT_SECRET`);
  const graph = entra && named('ENTRA_GRAPH', () => flag(env.ENTRA_GRAPH, false));
  const groups = named('RECIPIENT_GROUPS', () => recipientGroups(env.RECIPIENT_GROUPS || '', entra));
  if (groups.any && !graph) {
    throw new Error(entra ? 'RECIPIENT_GROUPS=* needs ENTRA_GRAPH=true (the group search uses Microsoft Graph)' : 'RECIPIENT_GROUPS=* needs AUTH_PROVIDER=entra');
  }
  const recipients = env.RECIPIENTS || 'optional';
  if (!/^(off|optional|required)$/.test(recipients)) throw new Error('RECIPIENTS: off, optional or required');
  if (recipients === 'off' && (groups.any || groups.list.length)) throw new Error('RECIPIENT_GROUPS needs RECIPIENTS=optional or required');
  // The people search of the form: the members of one group (Microsoft Graph).
  const userGroup = (env.RECIPIENT_USER_GROUP || '').trim().toLowerCase();
  if (userGroup) {
    if (!entra) throw new Error('RECIPIENT_USER_GROUP needs AUTH_PROVIDER=entra');
    if (!GUID.test(userGroup)) throw new Error('RECIPIENT_USER_GROUP: the object id of a group, a GUID');
    if (!graph) throw new Error('RECIPIENT_USER_GROUP needs ENTRA_GRAPH=true (the people search uses Microsoft Graph)');
    if (recipients === 'off') throw new Error('RECIPIENT_USER_GROUP needs RECIPIENTS=optional or required');
  }
  const create = env.AUTH_CREATE || 'signed-in';
  if (!/^(signed-in|anyone)$/.test(create)) throw new Error('AUTH_CREATE: signed-in or anyone');
  const domains = (env.RECIPIENT_DOMAINS || '').toLowerCase().split(/[\s,;]+/).filter(Boolean);
  for (const d of domains) if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) throw new Error(`RECIPIENT_DOMAINS: "${d}" is no domain`);
  const audience = env.AUTH_API_AUDIENCE || '';
  if (audience && !/^[\w.:@/-]{1,200}$/.test(audience)) throw new Error('AUTH_API_AUDIENCE: the audience of API tokens, e.g. api://<client id>');
  const scopes = env.OIDC_SCOPES || 'openid profile email';
  if (!/^[\w.:/-]+( [\w.:/-]+)*$/.test(scopes) || !scopes.split(' ').includes('openid')) {
    throw new Error('OIDC_SCOPES: space-separated scopes including openid');
  }
  /** @param {string} name @param {number} def @param {number} min @param {number} max */
  const num = (name, def, min, max) => named(name, () => int(env[name], def, min, max));
  return {
    provider: /** @type {'entra' | 'oidc'} */ (provider),
    tenant,
    issuer,
    clientId,
    clientSecret,
    secret,
    scopes,
    redirectUri: `${baseUrl}/auth/callback`,
    graph,
    graphUrl: entra ? url('ENTRA_GRAPH_URL', 'https://graph.microsoft.com') : '',
    sessionTtl: num('AUTH_SESSION_TTL', 8 * 3600, 300, 7 * 86400),
    createNeedsLogin: create === 'signed-in',
    apiAudience: audience,
    recipients: /** @type {'off' | 'optional' | 'required'} */ (recipients),
    recipientsMax: num('RECIPIENTS_MAX', 10, 1, 50),
    groups,
    userGroup,
    domains,
    showViewer: named('RECEIPT_SHOW_VIEWER', () => flag(env.RECEIPT_SHOW_VIEWER, false)),
  };
}

/** @param {NodeJS.ProcessEnv} env */
export function loadConfig(env = process.env) {
  for (const name of Object.keys(env)) {
    if (SETTINGS.includes(name) || name.length < 6) continue;
    const near = SETTINGS.find((k) => distance(name.toUpperCase(), k) <= 2);
    if (near) throw new Error(`${name}: unknown setting, did you mean ${near}?`);
  }
  /** @param {string} name @param {number} def @param {number} min @param {number} max */
  const num = (name, def, min, max) => named(name, () => int(env[name], def, min, max));
  /** @param {string} name @param {boolean} def */
  const sw = (name, def) => named(name, () => flag(env[name], def));
  /** @param {string} name @param {RegExp} re @param {string} def @param {string} what */
  const str = (name, re, def, what) => {
    const v = env[name];
    if (v === undefined || v === '') return def;
    if (!re.test(v)) throw new Error(`${name}: ${what}`);
    return v;
  };

  const baseUrl = str('BASE_URL', /^https?:\/\/[^/\s]+(\/[^\s]*)?$/, '', 'must look like https://ots.example.com').replace(/\/+$/, '');
  // LANGUAGES: the languages served (empty: every translation found);
  // DEFAULT_LANG: the fallback (empty: en, or the first of LANGUAGES). Which
  // codes exist is checked when the translations are loaded (src/theme.js).
  const languages = named('LANGUAGES', () => {
    if (!env.LANGUAGES) return null;
    const list = env.LANGUAGES.toLowerCase().split(/[\s,;]+/).filter(Boolean);
    if (!list.length || list.some((l) => !/^[a-z]{2,3}$/.test(l))) throw new Error('a list of language codes, e.g. en or en,de');
    if (new Set(list).size !== list.length) throw new Error('a language is listed twice');
    return list;
  });
  const defaultLang = str('DEFAULT_LANG', /^[a-z]{2,3}$/, '', 'a language code, e.g. en');
  if (languages && defaultLang && !languages.includes(defaultLang)) throw new Error(`DEFAULT_LANG=${defaultLang} is not one of LANGUAGES`);
  const template = str('TEMPLATE', /^[a-z0-9_-]{1,32}$/, 'default', 'lower-case letters, digits, "-" and "_", at most 32 characters');
  // The expiry dropdown: TTL_OPTIONS, otherwise the built-in steps up to MAX_TTL.
  let maxTtl = num('MAX_TTL', 7 * 86400, 300, 365 * 86400);
  let ttlOptions = [300, 3600, 86400, 259200, 604800, 1209600, 2592000, 7776000].filter((t) => t <= maxTtl);
  if (env.TTL_OPTIONS) {
    ttlOptions = named('TTL_OPTIONS', () => parseDurations(env.TTL_OPTIONS || ''));
    if (!env.MAX_TTL) maxTtl = ttlOptions[ttlOptions.length - 1];
    else if (ttlOptions[ttlOptions.length - 1] > maxTtl) throw new Error('TTL_OPTIONS has an entry above MAX_TTL');
  }
  let defaultTtl;
  if (env.DEFAULT_TTL) {
    defaultTtl = named('DEFAULT_TTL', () => parseDurations(env.DEFAULT_TTL || '')[0]);
    if (defaultTtl > maxTtl) throw new Error('DEFAULT_TTL is above MAX_TTL');
    if (env.TTL_OPTIONS && !ttlOptions.includes(defaultTtl)) throw new Error('DEFAULT_TTL must be one of TTL_OPTIONS');
  } else {
    // 1 day if offered, otherwise the closest option to it
    defaultTtl = ttlOptions.reduce((a, b) => (Math.abs(b - 86400) < Math.abs(a - 86400) ? b : a));
  }
  if (!ttlOptions.includes(defaultTtl)) ttlOptions = [...ttlOptions, defaultTtl].sort((a, b) => a - b);
  /** @param {string} name */
  const text = (name) => {
    const v = (env[name] || '').trim();
    if (v.length > 1000) throw new Error(`${name}: at most 1000 characters`);
    return v;
  };
  const maxSecretChars = num('MAX_SECRET_CHARS', 10000, 1, 1000000);
  const config = {
    port: num('PORT', 3000, 1, 65535),
    host: str('HOST', /^[\w.:-]+$/, '0.0.0.0', 'an IP address or host name'),
    // REDIS_URL or, with a password in it, REDIS_URL_FILE (Docker secret).
    redisUrl: named('REDIS_URL', () => {
      const url = secretValue(env, 'REDIS_URL') || 'redis://localhost:6379';
      if (!/^rediss?:\/\/\S+$/.test(url)) throw new Error('must look like redis://host:6379 or rediss://...');
      return url;
    }),
    // rediss:// with an own CA: the PEM file (the system CAs otherwise).
    redisTlsCa: named('REDIS_TLS_CA_FILE', () => {
      const file = env.REDIS_TLS_CA_FILE;
      if (!file) return '';
      let pem = '';
      try {
        pem = readFileSync(file, 'utf8');
      } catch (err) {
        throw new Error(`cannot read ${file} (${/** @type {NodeJS.ErrnoException} */ (err).code || 'error'})`);
      }
      if (!pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error(`${file} holds no PEM certificate`);
      return pem;
    }),
    redisPrefix: str('REDIS_PREFIX', /^[\w:.-]{1,64}$/, 'vanishly:', 'letters, digits and _ : . -, at most 64'),
    baseUrl,
    trustProxy: named('TRUST_PROXY', () => trustProxy(env.TRUST_PROXY)),
    hsts: sw('HSTS', false),
    template,
    // Light/dark at the first visit; '' = the template's defaultMode.
    defaultMode: str('DEFAULT_MODE', /^(auto|light|dark)$/, '', 'auto, light or dark'),
    templatesDir: str('TEMPLATES_DIR', /^\/\S*$/, '/var/lib/vanishly/templates', 'an absolute path'),
    translationsDir: str('TRANSLATIONS_DIR', /^\/\S*$/, '/var/lib/vanishly/translations', 'an absolute path'),
    defaultTtl,
    maxTtl,
    ttlOptions,
    confirmCheckbox: sw('CONFIRM_CHECKBOX', false),
    // Own label text per language; empty = the text from translations/ or the template.
    // any: CONFIRM_TEXT, also for languages added in TRANSLATIONS_DIR.
    confirmText: { en: text('CONFIRM_TEXT_EN') || text('CONFIRM_TEXT'), de: text('CONFIRM_TEXT_DE') || text('CONFIRM_TEXT'), any: text('CONFIRM_TEXT') },
    maxViews: num('MAX_VIEWS', 10, 1, 100),
    maxSecretChars,
    minSecretChars: num('MIN_SECRET_CHARS', 1, 1, 1000000),
    minPassphraseLength: num('MIN_PASSPHRASE_LENGTH', 0, 0, 1000),
    passphraseClasses: named('PASSPHRASE_COMPLEXITY', () => classes(env.PASSPHRASE_COMPLEXITY || '')),
    // REQUIRE_PASSPHRASE: false (off), true (always) or unless-recipients
    // (only for secrets without recipients).
    passphraseRule: named('REQUIRE_PASSPHRASE', () =>
      String(env.REQUIRE_PASSPHRASE || '').trim().toLowerCase() === 'unless-recipients'
        ? /** @type {'off' | 'always' | 'unless-recipients'} */ ('unless-recipients')
        : flag(env.REQUIRE_PASSPHRASE, false)
          ? 'always'
          : 'off',
    ),
    passphraseAttempts: num('PASSPHRASE_ATTEMPTS', 5, 1, 100),
    // The "Generate" button: length and character classes (empty = all four).
    generatorLength: num('GENERATOR_LENGTH', 20, 8, 128),
    generatorClasses: named('GENERATOR_COMPLEXITY', () => classes(env.GENERATOR_COMPLEXITY || 'all')),
    receiptKeep: num('RECEIPT_KEEP', 7 * 86400, 0, 365 * 86400),
    rateCreate: num('RATE_LIMIT_CREATE', 30, 0, 100000),
    rateRead: num('RATE_LIMIT_READ', 120, 0, 100000),
    rateWindow: num('RATE_LIMIT_WINDOW', 600, 1, 86400),
    languages,
    defaultLang,
    // ENABLE_API=false: no public API; only this server's own pages may call it.
    api: sw('ENABLE_API', true),
    apiDocs: env.ENABLE_API_DOCS ? sw('ENABLE_API_DOCS', true) : sw('API_DOCS', true),
    // Features an operator can switch off (ENABLE_*=false); all on by default.
    features: {
      passphrase: sw('ENABLE_PASSPHRASE', true),
      views: sw('ENABLE_VIEWS', true),
      receipts: sw('ENABLE_RECEIPTS', true),
      burn: sw('ENABLE_BURN', true),
      viewLog: sw('ENABLE_VIEW_LOG', true),
      receiptShareLink: sw('ENABLE_RECEIPT_SHARE_LINK', true),
      generator: sw('ENABLE_GENERATOR', true),
      shareApi: sw('ENABLE_SHARE_API', true),
      openApi: sw('ENABLE_OPEN_API', true),
      // Single API endpoints the web pages do not need (create and reveal only).
      secretMetaApi: sw('ENABLE_SECRET_META_API', true),
      configApi: sw('ENABLE_CONFIG_API', true),
      meApi: sw('ENABLE_ME_API', true),
      // Endpoints the pages need: off, only this server's own pages may call them.
      createApi: sw('ENABLE_CREATE_API', true),
      revealApi: sw('ENABLE_REVEAL_API', true),
      receiptApi: sw('ENABLE_RECEIPT_API', true),
      apiIndex: sw('ENABLE_API_INDEX', true),
      langSwitch: sw('ENABLE_LANG_SWITCH', true),
      themeToggle: sw('ENABLE_THEME_TOGGLE', true),
      apiLink: sw('ENABLE_API_LINK', true),
      githubLink: sw('ENABLE_GITHUB_LINK', true),
    },
    accessLog: sw('ACCESS_LOG', true),
    auth: authConfig(env, baseUrl),
  };
  if (config.minSecretChars > maxSecretChars) throw new Error('MIN_SECRET_CHARS is above MAX_SECRET_CHARS');
  if (config.redisTlsCa && !config.redisUrl.startsWith('rediss://')) throw new Error('REDIS_TLS_CA_FILE needs a rediss:// REDIS_URL (TLS)');
  /** REQUIRE_PASSPHRASE=true: every secret needs one. */
  const requirePassphrase = config.passphraseRule === 'always';
  if (!config.features.passphrase) {
    if (config.passphraseRule !== 'off') throw new Error(`REQUIRE_PASSPHRASE=${config.passphraseRule === 'always' ? 'true' : config.passphraseRule} needs ENABLE_PASSPHRASE=true`);
    if (config.minPassphraseLength || config.passphraseClasses.length) {
      throw new Error('MIN_PASSPHRASE_LENGTH and PASSPHRASE_COMPLEXITY need ENABLE_PASSPHRASE=true');
    }
  }
  if (config.generatorLength < config.generatorClasses.length) throw new Error('GENERATOR_LENGTH is too short for GENERATOR_COMPLEXITY');
  if (!config.features.receipts) config.features.burn = config.features.viewLog = config.features.receiptShareLink = false;
  if (!config.features.views) config.maxViews = 1;
  if (!config.api) {
    config.apiDocs = false;
    config.features.shareApi = false;
    config.features.openApi = false;
  }
  if (!config.api && !config.apiDocs) config.features.apiLink = false;
  return { ...config, requirePassphrase };
}

/** @typedef {ReturnType<typeof loadConfig>} Config */
