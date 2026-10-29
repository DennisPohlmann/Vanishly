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
  'OIDC_CLIENT_SECRET_FILE', 'OIDC_SCOPES', 'OIDC_GROUPS_CLAIM', 'AUTH_ALLOWED_DOMAINS', 'DIRECTORY_API', 'DIRECTORY_URL',
  'DIRECTORY_CLIENT_ID', 'DIRECTORY_CLIENT_SECRET', 'DIRECTORY_CLIENT_SECRET_FILE', 'DIRECTORY_API_TOKEN',
  'DIRECTORY_API_TOKEN_FILE', 'DIRECTORY_GOOGLE_CREDENTIALS_FILE', 'DIRECTORY_GOOGLE_ADMIN', 'AUTH_SECRET', 'AUTH_SECRET_FILE', 'AUTH_SESSION_TTL', 'AUTH_LOGOUT', 'AUTH_CREATE', 'AUTH_API_AUDIENCE', 'RECIPIENTS', 'RECIPIENTS_MAX', 'RECIPIENT_GROUPS',
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
 * AUTH_PROVIDER: the sign-in providers besides Entra. All use OpenID Connect
 * (OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET); a preset adds what the
 * provider needs: the groups claim, the issuer format and, with
 * DIRECTORY_API=true, the people and group search in its directory.
 *   groupsClaim  default of OIDC_GROUPS_CLAIM ('' = none: set it, or groups come from the directory)
 *   example      an issuer, for the error message
 *   issuer       the issuer's form (checked); slash: the issuer ends with "/"
 *   access       what the directory needs: client (client credentials), token (API token), google, aws
 *   userGroup    the form of RECIPIENT_USER_GROUP
 *   groupSearch  RECIPIENT_GROUPS=* works (the directory lists groups by the claim's value)
 *   lower        group values are compared in lower case
 *   paths        group values are paths: "finance" (mapper without full path) counts as "/finance"
 * @type {Record<string, { groupsClaim: string, example: string, issuer?: RegExp, slash?: boolean, access?: 'client' | 'token' | 'google' | 'aws', userGroup?: [RegExp, string], groupSearch?: boolean, lower?: boolean, paths?: boolean }>}
 */
const PRESETS = {
  oidc: { groupsClaim: 'groups', example: 'https://login.example.com/realms/main' },
  keycloak: {
    groupsClaim: 'groups',
    example: 'https://login.example.com/realms/main',
    issuer: /\/realms\/[^/]+$/,
    access: 'client',
    userGroup: [/^((\/[^/]{1,100}){1,10}|[0-9a-f-]{36})$/i, 'the path of a group (/staff) or its id'],
    groupSearch: true,
    paths: true,
  },
  okta: {
    groupsClaim: 'groups',
    example: 'https://example.okta.com/oauth2/default',
    access: 'token',
    userGroup: [/^00g[A-Za-z0-9]{17}$/, 'the id of an Okta group (00g...)'],
    groupSearch: true,
  },
  auth0: {
    groupsClaim: '',
    example: 'https://example.eu.auth0.com/',
    slash: true,
    access: 'client',
    userGroup: [/^rol_[A-Za-z0-9]{16}$/, 'the id of an Auth0 role (rol_...)'],
  },
  google: {
    groupsClaim: '',
    example: 'https://accounts.google.com',
    issuer: /^https:\/\/accounts\.google\.com$/,
    access: 'google',
    userGroup: [/^[^\s@]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/i, 'the e-mail address of a Google group'],
    groupSearch: true,
    lower: true,
  },
  ping: {
    groupsClaim: 'groups',
    example: 'https://auth.pingone.eu/<environment id>/as',
    issuer: /^https:\/\/auth\.pingone\.[a-z.]+\/[0-9a-f-]{36}\/as$/,
    access: 'client',
    userGroup: [/^[0-9a-f-]{36}$/i, 'the id of a PingOne group'],
  },
  jumpcloud: {
    groupsClaim: 'groups',
    example: 'https://oauth.id.jumpcloud.com/',
    slash: true,
    access: 'token',
    userGroup: [/^[0-9a-f]{24}$/, 'the id of a JumpCloud user group'],
  },
  cognito: {
    groupsClaim: 'cognito:groups',
    example: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Example',
    issuer: /^https:\/\/cognito-idp\.[a-z0-9-]+\.amazonaws\.com\/[a-z0-9-]+_[A-Za-z0-9]+$/,
    access: 'aws',
    userGroup: [/^[\p{L}\p{M}\p{S}\p{N}\p{P}]{1,128}$/u, 'the name of a Cognito group'],
    groupSearch: true,
  },
};
export const PROVIDERS = ['entra', ...Object.keys(PRESETS)];

/**
 * A group value as it is compared and hashed (the same in config, token and form).
 * @param {string} v
 * @param {boolean} lower Entra ids, Google addresses
 * @param {boolean} paths Keycloak: "/" in front
 */
export function groupValue(v, lower, paths) {
  const t = v.trim();
  const l = lower ? t.toLowerCase() : t;
  return paths && l && !l.startsWith('/') ? `/${l}` : l;
}

/**
 * RECIPIENT_GROUPS: empty (no groups), "*" (search the directory) or
 * "Name=<group>,..." (the groups a sender may pick from): with Entra the
 * group object id, otherwise the value in the groups claim.
 * @param {string} v
 * @param {boolean} entra
 * @param {(id: string) => string} norm
 * @returns {{ any: boolean, list: { name: string, id: string }[] }}
 */
function recipientGroups(v, entra, norm) {
  if (!v.trim()) return { any: false, list: [] };
  if (v.trim() === '*') return { any: true, list: [] };
  const list = [];
  for (const part of v.split(',').map((p) => p.trim()).filter(Boolean)) {
    // Group names may hold spaces (Okta, Cognito), not an Entra id.
    const m = /^([^=]{1,64})=([^=]{1,200})$/.exec(part);
    const id = m ? m[2].trim() : '';
    if (!m || !id || /[\x00-\x1f]/.test(id) || (entra && !GUID.test(id))) {
      throw new Error(`"${part}" is not Name=${entra ? '<group object id> (a GUID)' : '<value of the groups claim>'}`);
    }
    list.push({ name: m[1].trim(), id: norm(id) });
  }
  if (!list.length) throw new Error('empty');
  return { any: false, list };
}

/**
 * The directory of a preset (DIRECTORY_API=true): where it is and how
 * Vanishly signs in to it. Credentials are checked here, used in src/directory/.
 * @param {NodeJS.ProcessEnv} env
 * @param {string} provider
 * @param {string} issuer
 * @param {(name: string, def: string, path?: boolean) => string} url
 */
function directoryConfig(env, provider, issuer, url) {
  const preset = PRESETS[provider];
  const dir = {
    provider,
    issuer,
    url: env.DIRECTORY_URL ? url('DIRECTORY_URL', 'https://admin.example.com', true) : '',
    clientId: '',
    clientSecret: '',
    token: '',
    /** @type {{ clientEmail: string, privateKey: string, keyId: string, tokenUri: string, admin: string } | null} */
    google: null,
    /** @type {{ region: string, pool: string, accessKeyId: string, secretAccessKey: string, sessionToken: string, roleArn: string, tokenFile: string } | null} */
    aws: null,
  };
  /** @param {string} name */
  const notHere = (name) => {
    if (env[name]) throw new Error(`${name} does not apply to AUTH_PROVIDER=${provider}`);
  };
  if (preset.access !== 'client') ['DIRECTORY_CLIENT_ID', 'DIRECTORY_CLIENT_SECRET', 'DIRECTORY_CLIENT_SECRET_FILE'].forEach(notHere);
  if (preset.access !== 'token') ['DIRECTORY_API_TOKEN', 'DIRECTORY_API_TOKEN_FILE'].forEach(notHere);
  if (preset.access !== 'google') ['DIRECTORY_GOOGLE_CREDENTIALS_FILE', 'DIRECTORY_GOOGLE_ADMIN'].forEach(notHere);
  if (preset.access === 'client') {
    // A client of its own (service account / worker app), or the sign-in client.
    dir.clientId = env.DIRECTORY_CLIENT_ID || '';
    if (dir.clientId && !/^[\w.:@/-]{1,200}$/.test(dir.clientId)) throw new Error('DIRECTORY_CLIENT_ID: letters, digits and _ . : @ / -');
    dir.clientSecret = named('DIRECTORY_CLIENT_SECRET', () => secretValue(env, 'DIRECTORY_CLIENT_SECRET'));
    if (Boolean(dir.clientId) !== Boolean(dir.clientSecret)) throw new Error('DIRECTORY_CLIENT_ID and DIRECTORY_CLIENT_SECRET go together');
  } else if (preset.access === 'token') {
    dir.token = named('DIRECTORY_API_TOKEN', () => secretValue(env, 'DIRECTORY_API_TOKEN'));
    if (!dir.token) throw new Error(`DIRECTORY_API_TOKEN (or DIRECTORY_API_TOKEN_FILE) is required with AUTH_PROVIDER=${provider} and DIRECTORY_API=true`);
    if (!/^[\x21-\x7e]{8,512}$/.test(dir.token)) throw new Error('DIRECTORY_API_TOKEN: the API token as issued, no spaces');
  } else if (preset.access === 'google') {
    const file = env.DIRECTORY_GOOGLE_CREDENTIALS_FILE || '';
    if (!file) throw new Error('DIRECTORY_GOOGLE_CREDENTIALS_FILE (the key file of a service account) is required with AUTH_PROVIDER=google and DIRECTORY_API=true');
    const admin = (env.DIRECTORY_GOOGLE_ADMIN || '').trim().toLowerCase();
    if (!/^[^\s@]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(admin)) {
      throw new Error('DIRECTORY_GOOGLE_ADMIN (the address of an admin the service account acts for) is required with AUTH_PROVIDER=google and DIRECTORY_API=true');
    }
    dir.google = named('DIRECTORY_GOOGLE_CREDENTIALS_FILE', () => {
      /** @type {any} */ let key;
      try {
        key = JSON.parse(readFileSync(file, 'utf8'));
      } catch (err) {
        throw new Error(`cannot read ${file} as JSON (${/** @type {NodeJS.ErrnoException} */ (err).code || 'invalid'})`);
      }
      if (key?.type !== 'service_account' || typeof key.client_email !== 'string' || typeof key.private_key !== 'string') {
        throw new Error('not the JSON key of a service account');
      }
      const tokenUri = typeof key.token_uri === 'string' ? key.token_uri : 'https://oauth2.googleapis.com/token';
      if (!/^https:\/\/[^/\s]+\/\S*$/.test(tokenUri)) throw new Error('token_uri: an https:// address');
      return { clientEmail: key.client_email, privateKey: key.private_key, keyId: String(key.private_key_id || ''), tokenUri, admin };
    });
  } else if (preset.access === 'aws') {
    // The standard AWS variables: keys, or a role through a web identity token (EKS IRSA).
    const m = /^https:\/\/cognito-idp\.([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9-]+_[A-Za-z0-9]+)$/.exec(issuer);
    if (!m) throw new Error('OIDC_ISSUER: the Cognito issuer, e.g. https://cognito-idp.<region>.amazonaws.com/<user pool id>');
    const aws = {
      region: m[1],
      pool: m[2],
      accessKeyId: env.AWS_ACCESS_KEY_ID || '',
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY || '',
      sessionToken: env.AWS_SESSION_TOKEN || '',
      roleArn: env.AWS_ROLE_ARN || '',
      tokenFile: env.AWS_WEB_IDENTITY_TOKEN_FILE || '',
    };
    if (!(aws.accessKeyId && aws.secretAccessKey) && !(aws.roleArn && aws.tokenFile)) {
      throw new Error('DIRECTORY_API=true with AUTH_PROVIDER=cognito needs AWS credentials: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE');
    }
    dir.aws = aws;
  }
  return dir;
}

/**
 * Optional sign-in (AUTH_PROVIDER=entra, oidc or a preset); null = off.
 * @param {NodeJS.ProcessEnv} env
 * @param {string} baseUrl
 */
function authConfig(env, baseUrl) {
  const provider = env.AUTH_PROVIDER || 'none';
  if (provider !== 'none' && !PROVIDERS.includes(provider)) throw new Error(`AUTH_PROVIDER: none, ${PROVIDERS.join(', ')}`);
  if (provider === 'none') {
    const set = AUTH_SETTINGS.find((k) => env[k]);
    if (set) throw new Error(`${set} needs AUTH_PROVIDER (${PROVIDERS.join(', ')})`);
    return null;
  }
  const entra = provider === 'entra';
  const preset = entra ? null : PRESETS[provider];
  const other = AUTH_SETTINGS.find((k) => env[k] && (entra ? /^(OIDC|DIRECTORY)_/.test(k) : k.startsWith('ENTRA_')));
  if (other) throw new Error(`${other} does not apply to AUTH_PROVIDER=${provider}${entra && other.startsWith('DIRECTORY_') ? ' (Entra uses ENTRA_GRAPH)' : ''}`);
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
    issuer = url('OIDC_ISSUER', preset?.example || '', true);
    const local = issuer.startsWith('http:');
    if (preset?.issuer && !local && !preset.issuer.test(issuer)) throw new Error(`OIDC_ISSUER: the issuer of ${provider}, e.g. ${preset.example}`);
    // Auth0 and JumpCloud name their issuer with a trailing slash; the token must match it exactly.
    if (preset?.slash) issuer += '/';
  }
  const clientId = need(`${prefix}_CLIENT_ID`);
  if (entra && !GUID.test(clientId)) throw new Error('ENTRA_CLIENT_ID: the application (client) id, a GUID');
  if (!/^[\w.:@/-]{1,200}$/.test(clientId)) throw new Error(`${prefix}_CLIENT_ID: letters, digits and _ . : @ / -`);
  const clientSecret = named(`${prefix}_CLIENT_SECRET`, () => secretValue(env, `${prefix}_CLIENT_SECRET`));
  if (!clientSecret) throw new Error(`${prefix}_CLIENT_SECRET (or ${prefix}_CLIENT_SECRET_FILE) is required with AUTH_PROVIDER=${provider}`);
  const secret = named('AUTH_SECRET', () => secretValue(env, 'AUTH_SECRET'));
  if (secret.length < 32) throw new Error('AUTH_SECRET: at least 32 characters (e.g. openssl rand -base64 48)');
  if (secret === clientSecret) throw new Error(`AUTH_SECRET must differ from ${prefix}_CLIENT_SECRET`);
  // Who may sign in at all, by the domain of the address (Google: also the hd claim).
  const allowedDomains = (env.AUTH_ALLOWED_DOMAINS || '').toLowerCase().split(/[\s,;]+/).filter(Boolean);
  for (const d of allowedDomains) if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) throw new Error(`AUTH_ALLOWED_DOMAINS: "${d}" is no domain`);
  if (provider === 'google' && !allowedDomains.length) {
    throw new Error('AUTH_ALLOWED_DOMAINS is required with AUTH_PROVIDER=google (the Workspace domains; otherwise every Google account could sign in)');
  }
  const groupsClaim = entra ? 'groups' : (env.OIDC_GROUPS_CLAIM || preset?.groupsClaim || '').trim();
  if (groupsClaim && !/^[\w.:/-]{1,200}$/.test(groupsClaim)) throw new Error('OIDC_GROUPS_CLAIM: the name of a claim, e.g. groups');
  const directoryOn = entra
    ? named('ENTRA_GRAPH', () => flag(env.ENTRA_GRAPH, false))
    : named('DIRECTORY_API', () => flag(env.DIRECTORY_API, false));
  if (provider === 'oidc' && directoryOn) throw new Error('DIRECTORY_API needs a provider with a directory (keycloak, okta, auth0, google, ping, jumpcloud, cognito), not oidc');
  if (!directoryOn) {
    const set = ['DIRECTORY_URL', 'DIRECTORY_CLIENT_ID', 'DIRECTORY_CLIENT_SECRET', 'DIRECTORY_CLIENT_SECRET_FILE', 'DIRECTORY_API_TOKEN', 'DIRECTORY_API_TOKEN_FILE', 'DIRECTORY_GOOGLE_CREDENTIALS_FILE', 'DIRECTORY_GOOGLE_ADMIN'].find((k) => env[k]);
    if (set) throw new Error(`${set} needs DIRECTORY_API=true`);
  }
  const directory = !entra && directoryOn ? directoryConfig(env, provider, issuer, url) : null;
  const graph = entra && directoryOn;
  const groupSearch = graph || Boolean(directory && preset?.groupSearch);
  const lower = entra || Boolean(preset?.lower);
  const groupPaths = Boolean(preset?.paths);
  const groups = named('RECIPIENT_GROUPS', () => recipientGroups(env.RECIPIENT_GROUPS || '', entra, (id) => groupValue(id, lower, groupPaths)));
  if (groups.any && !groupSearch) {
    throw new Error(
      entra
        ? 'RECIPIENT_GROUPS=* needs ENTRA_GRAPH=true (the group search uses Microsoft Graph)'
        : preset?.groupSearch
          ? 'RECIPIENT_GROUPS=* needs DIRECTORY_API=true (the group search uses the directory)'
          : `RECIPIENT_GROUPS=* is not available with AUTH_PROVIDER=${provider}; list the groups as Name=<value>`,
    );
  }
  if ((groups.any || groups.list.length) && !groupsClaim && !directory) {
    throw new Error(
      provider === 'google'
        ? 'RECIPIENT_GROUPS with AUTH_PROVIDER=google needs DIRECTORY_API=true (Google puts no groups into the token)'
        : `RECIPIENT_GROUPS needs OIDC_GROUPS_CLAIM (the claim your ${provider} setup puts the groups into)`,
    );
  }
  const recipients = env.RECIPIENTS || 'optional';
  if (!/^(off|optional|required)$/.test(recipients)) throw new Error('RECIPIENTS: off, optional or required');
  if (recipients === 'off' && (groups.any || groups.list.length)) throw new Error('RECIPIENT_GROUPS needs RECIPIENTS=optional or required');
  // The people search of the form: the members of one group in the directory.
  let userGroup = (env.RECIPIENT_USER_GROUP || '').trim();
  if (userGroup) {
    if (entra) {
      userGroup = userGroup.toLowerCase();
      if (!GUID.test(userGroup)) throw new Error('RECIPIENT_USER_GROUP: the object id of a group, a GUID');
      if (!graph) throw new Error('RECIPIENT_USER_GROUP needs ENTRA_GRAPH=true (the people search uses Microsoft Graph)');
    } else {
      if (!preset?.userGroup) throw new Error('RECIPIENT_USER_GROUP needs a provider with a directory (entra, keycloak, okta, auth0, google, ping, jumpcloud, cognito)');
      if (!preset.userGroup[0].test(userGroup)) throw new Error(`RECIPIENT_USER_GROUP: ${preset.userGroup[1]}`);
      if (!directory) throw new Error('RECIPIENT_USER_GROUP needs DIRECTORY_API=true (the people search uses the directory)');
      if (preset.lower) userGroup = userGroup.toLowerCase();
    }
    if (recipients === 'off') throw new Error('RECIPIENT_USER_GROUP needs RECIPIENTS=optional or required');
  }
  // Sign out also at the provider (RP-initiated logout), so the next sign-in
  // asks again. Not for Entra by default: that ends the Microsoft 365 session too.
  const logout = env.AUTH_LOGOUT || (entra ? 'local' : 'provider');
  if (!/^(provider|local)$/.test(logout)) throw new Error('AUTH_LOGOUT: provider or local');
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
    provider,
    tenant,
    issuer,
    clientId,
    clientSecret,
    secret,
    scopes,
    redirectUri: `${baseUrl}/auth/callback`,
    graph,
    directory,
    groupsClaim,
    lowerGroups: lower,
    groupPaths,
    allowedDomains,
    graphUrl: entra ? url('ENTRA_GRAPH_URL', 'https://graph.microsoft.com') : '',
    sessionTtl: num('AUTH_SESSION_TTL', 8 * 3600, 300, 7 * 86400),
    createNeedsLogin: create === 'signed-in',
    apiAudience: audience,
    recipients: /** @type {'off' | 'optional' | 'required'} */ (recipients),
    recipientsMax: num('RECIPIENTS_MAX', 10, 1, 50),
    groups,
    userGroup,
    domains,
    logout: /** @type {'provider' | 'local'} */ (logout),
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
