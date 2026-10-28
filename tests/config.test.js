import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { duration } from '../src/app.js';
import { loadConfig, parseDurations } from '../src/config.js';

test('TTL_OPTIONS: units, order, duplicates, limits', () => {
  assert.deepEqual(parseDurations('1d, 15m,1h 2w,1d,3600'), [900, 3600, 86400, 1209600]);
  assert.throws(() => parseDurations('5x'));
  assert.throws(() => parseDurations('30s'));
  assert.throws(() => parseDurations('2y'));
});

test('dropdown defaults follow TTL_OPTIONS', () => {
  let c = loadConfig({ TTL_OPTIONS: '1h,12h,3d' });
  assert.deepEqual(c.ttlOptions, [3600, 43200, 259200]);
  assert.equal(c.maxTtl, 259200);
  assert.equal(c.defaultTtl, 43200); // closest to one day
  c = loadConfig({ TTL_OPTIONS: '1h,1d,7d', DEFAULT_TTL: '1h' });
  assert.equal(c.defaultTtl, 3600);
  assert.throws(() => loadConfig({ TTL_OPTIONS: '1h,1d', DEFAULT_TTL: '2h' }), /one of TTL_OPTIONS/);
  assert.throws(() => loadConfig({ TTL_OPTIONS: '30d', MAX_TTL: '604800' }), /above MAX_TTL/);
  c = loadConfig({});
  assert.deepEqual(c.ttlOptions, [300, 3600, 86400, 259200, 604800]);
  assert.equal(c.defaultTtl, 86400);
  assert.equal(c.confirmCheckbox, false);
});

test('confirmation text per language', () => {
  const c = loadConfig({ CONFIRM_CHECKBOX: 'true', CONFIRM_TEXT: 'Same', CONFIRM_TEXT_DE: 'Deutsch' });
  assert.equal(c.confirmCheckbox, true);
  assert.deepEqual(c.confirmText, { en: 'Same', de: 'Deutsch', any: 'Same' });
});

test('duration labels', () => {
  const t = { 'unit.d.1': '{n} day', 'unit.d.n': '{n} days', 'unit.w.n': '{n} weeks', 'unit.h.n': '{n} hours', 'unit.m.n': '{n} minutes' };
  assert.equal(duration(86400, t), '1 day');
  assert.equal(duration(1209600, t), '2 weeks');
  assert.equal(duration(259200, t), '3 days');
  assert.equal(duration(43200, t), '12 hours');
  assert.equal(duration(900, t), '15 minutes');
});

test('passphrase complexity', async () => {
  const { missingClasses } = await import('../public/js/rules.js');
  assert.deepEqual(loadConfig({ PASSPHRASE_COMPLEXITY: 'digit, upper' }).passphraseClasses, ['upper', 'digit']);
  assert.deepEqual(loadConfig({ PASSPHRASE_COMPLEXITY: 'all' }).passphraseClasses, ['upper', 'lower', 'digit', 'symbol']);
  assert.deepEqual(loadConfig({}).passphraseClasses, []);
  assert.throws(() => loadConfig({ PASSPHRASE_COMPLEXITY: 'emoji' }), /PASSPHRASE_COMPLEXITY/);
  const all = ['upper', 'lower', 'digit', 'symbol'];
  assert.deepEqual(missingClasses('abc', all), ['upper', 'digit', 'symbol']);
  assert.deepEqual(missingClasses('Äbc3!', all), []);
  assert.deepEqual(missingClasses('ABC def', all), ['digit', 'symbol']); // a space is no symbol
});

test('languages: LANGUAGES and DEFAULT_LANG are checked for form here, for existence in theme.js', () => {
  const none = loadConfig({});
  assert.deepEqual([none.languages, none.defaultLang], [null, '']);
  assert.deepEqual(loadConfig({ LANGUAGES: 'de, en' }).languages, ['de', 'en']);
  assert.equal(loadConfig({ LANGUAGES: 'en,de', DEFAULT_LANG: 'de' }).defaultLang, 'de');
  assert.throws(() => loadConfig({ LANGUAGES: 'en', DEFAULT_LANG: 'de' }), /DEFAULT_LANG=de is not one of LANGUAGES/);
});

test('feature switches', () => {
  const sw = loadConfig({}).features;
  assert.deepEqual([sw.secretMetaApi, sw.configApi, sw.meApi], [true, true, true]);
  const offs = loadConfig({ ENABLE_SECRET_META_API: 'false', ENABLE_CONFIG_API: 'no', ENABLE_ME_API: '0' }).features;
  assert.deepEqual([offs.secretMetaApi, offs.configApi, offs.meApi], [false, false, false]);
  assert.throws(() => loadConfig({ ENABLE_ME_API: 'maybe' }), /ENABLE_ME_API/);
  assert.deepEqual([loadConfig({}).passphraseRule, loadConfig({}).requirePassphrase], ['off', false]);
  assert.deepEqual([loadConfig({ REQUIRE_PASSPHRASE: 'true' }).passphraseRule, loadConfig({ REQUIRE_PASSPHRASE: 'true' }).requirePassphrase], ['always', true]);
  const ur = loadConfig({ REQUIRE_PASSPHRASE: 'Unless-Recipients' });
  assert.deepEqual([ur.passphraseRule, ur.requirePassphrase], ['unless-recipients', false]);
  assert.throws(() => loadConfig({ REQUIRE_PASSPHRASE: 'unless-recipients', ENABLE_PASSPHRASE: 'false' }), /REQUIRE_PASSPHRASE=unless-recipients needs ENABLE_PASSPHRASE=true/);
  assert.throws(() => loadConfig({ REQUIRE_PASSPHRASE: 'sometimes' }), /REQUIRE_PASSPHRASE/);
  assert.equal(loadConfig({}).features.passphrase, true);
  assert.equal(loadConfig({ ENABLE_PASSPHRASE: 'off' }).features.passphrase, false);
  assert.throws(() => loadConfig({ ENABLE_VIEWS: 'maybe' }), /invalid switch/);
  assert.equal(loadConfig({}).features.githubLink, true);
  assert.equal(loadConfig({ ENABLE_GITHUB_LINK: 'false' }).features.githubLink, false);
  assert.throws(() => loadConfig({ ENABLE_GITHUB_LINK: 'maybe' }), /invalid switch/);
  assert.throws(() => loadConfig({ ENABLE_PASSPHRASE: 'false', REQUIRE_PASSPHRASE: 'true' }), /REQUIRE_PASSPHRASE/);
  const c = loadConfig({ ENABLE_API: 'false' });
  assert.deepEqual([c.api, c.apiDocs, c.features.shareApi, c.features.apiLink], [false, false, false, false]);
});

test('every wrong setting stops the start', () => {
  /** @type {[string, string, RegExp][]} */
  const cases = [
    ['PORT', 'abc', /PORT/],
    ['HSTS', 'maybe', /HSTS/],
    ['REQUIRE_PASSPHRASE', 'ja', /REQUIRE_PASSPHRASE/],
    ['ACCESS_LOG', '2', /ACCESS_LOG/],
    ['DEFAULT_LANG', 'german', /DEFAULT_LANG/],
    ['LANGUAGES', 'english', /LANGUAGES/],
    ['LANGUAGES', 'en,en', /LANGUAGES/],
    ['LANGUAGES', ',', /LANGUAGES/],
    ['REDIS_URL', 'localhost:6379', /REDIS_URL/],
    ['TRUST_PROXY', 'my proxy', /TRUST_PROXY/],
    ['TEMPLATE', 'Bad Name', /TEMPLATE/],
    ['TEMPLATES_DIR', 'relative/dir', /TEMPLATES_DIR/],
    ['DEFAULT_TTL', '30d', /DEFAULT_TTL/],
    ['MIN_SECRET_CHARS', '20000', /MIN_SECRET_CHARS/],
    ['GENERATOR_LENGTH', '4', /GENERATOR_LENGTH/],
    ['GENERATOR_COMPLEXITY', 'emoji', /GENERATOR_COMPLEXITY/],
    ['ENABLE_VEIWS', 'false', /did you mean ENABLE_VIEWS/],
    ['RATE_LIMIT_CREAT', '5', /did you mean RATE_LIMIT_CREATE/],
  ];
  for (const [name, value, msg] of cases) {
    assert.throws(() => loadConfig({ [name]: value }), msg, `${name}=${value}`);
  }
  assert.throws(() => loadConfig({ ENABLE_PASSPHRASE: 'false', MIN_PASSPHRASE_LENGTH: '8' }), /ENABLE_PASSPHRASE/);
  // empty values (as in docker-compose.yml) mean the default; other variables are left alone
  const c = loadConfig({ PORT: '', HSTS: '', TTL_OPTIONS: '', PASSPHRASE_COMPLEXITY: '', PATH: '/bin', HOSTNAME: 'x', NODE_VERSION: '24' });
  assert.equal(c.port, 3000);
  assert.deepEqual(c.generatorClasses, ['upper', 'lower', 'digit', 'symbol']);
  assert.equal(c.generatorLength, 20);
});

test('DEFAULT_MODE', () => {
  assert.equal(loadConfig({}).defaultMode, '');
  assert.equal(loadConfig({ DEFAULT_MODE: 'dark' }).defaultMode, 'dark');
  assert.throws(() => loadConfig({ DEFAULT_MODE: 'sepia' }), /DEFAULT_MODE/);
});

test('sign-in settings: off by default, checked when on', () => {
  assert.equal(loadConfig({}).auth, null);
  assert.throws(() => loadConfig({ RECIPIENTS: 'required' }), /RECIPIENTS needs AUTH_PROVIDER/);
  const entra = {
    AUTH_PROVIDER: 'entra',
    BASE_URL: 'https://ots.example.com',
    ENTRA_TENANT_ID: '11111111-2222-3333-4444-555555555555',
    ENTRA_CLIENT_ID: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ENTRA_CLIENT_SECRET: 'change-me',
    AUTH_SECRET: 'x'.repeat(32),
  };
  const a = /** @type {NonNullable<ReturnType<typeof loadConfig>['auth']>} */ (loadConfig(entra).auth);
  assert.equal(a.issuer, 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0');
  assert.equal(a.redirectUri, 'https://ots.example.com/auth/callback');
  assert.equal(a.createNeedsLogin, true);
  assert.equal(a.recipients, 'optional');
  assert.equal(a.showViewer, false);
  assert.throws(() => loadConfig({ ...entra, BASE_URL: '' }), /BASE_URL is required/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_TENANT_ID: 'contoso' }), /ENTRA_TENANT_ID/);
  assert.throws(() => loadConfig({ ...entra, AUTH_SECRET: 'short' }), /at least 32/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_AUTHORITY: 'http://login.example.com' }), /https/);
  assert.throws(() => loadConfig({ ...entra, RECIPIENT_GROUPS: '*' }), /ENTRA_GRAPH=true/);
  assert.throws(() => loadConfig({ ...entra, RECIPIENT_GROUPS: 'IT=it' }), /GUID/);
  assert.throws(() => loadConfig({ ...entra, OIDC_ISSUER: 'https://x.example.com' }), /does not apply/);
  assert.throws(() => loadConfig({ ...entra, AUTH_CREATE: 'nobody' }), /AUTH_CREATE/);
  assert.throws(() => loadConfig({ ...entra, RECIPIENT_DOMAINS: 'not a domain' }), /RECIPIENT_DOMAINS/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_CLIENT_SECRET_FILE: '/nope' }), /both set/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_CLIENT_SECRET: '', ENTRA_CLIENT_SECRET_FILE: '/nonexistent/x' }), /cannot read/);
  const g = loadConfig({ ...entra, ENTRA_GRAPH: 'true', RECIPIENT_GROUPS: 'IT Admins=0F0F0F0F-1111-2222-3333-444444444444' }).auth;
  assert.deepEqual(g?.groups.list, [{ name: 'IT Admins', id: '0f0f0f0f-1111-2222-3333-444444444444' }]);
  assert.throws(() => loadConfig({ ...entra, ENTRA_GRAPH: 'true', RECIPIENTS: 'off', RECIPIENT_GROUPS: '*' }), /RECIPIENT_GROUPS needs/);
  const ug = '0F0F0F0F-1111-2222-3333-444444444444';
  assert.equal(loadConfig({ ...entra, ENTRA_GRAPH: 'true', RECIPIENT_USER_GROUP: ug }).auth?.userGroup, ug.toLowerCase());
  assert.equal(loadConfig(entra).auth?.userGroup, '');
  assert.throws(() => loadConfig({ ...entra, RECIPIENT_USER_GROUP: ug }), /ENTRA_GRAPH=true/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_GRAPH: 'true', RECIPIENT_USER_GROUP: 'IT Admins' }), /GUID/);
  assert.throws(() => loadConfig({ ...entra, ENTRA_GRAPH: 'true', RECIPIENTS: 'off', RECIPIENT_USER_GROUP: ug }), /RECIPIENTS=optional/);
  const o = loadConfig({
    AUTH_PROVIDER: 'oidc',
    BASE_URL: 'http://localhost:3000',
    OIDC_ISSUER: 'http://localhost:8080/default',
    OIDC_CLIENT_ID: 'vanishly',
    OIDC_CLIENT_SECRET: 'change-me',
    AUTH_SECRET: 'y'.repeat(32),
    RECIPIENT_GROUPS: 'Ops=ops',
  }).auth;
  assert.equal(o?.issuer, 'http://localhost:8080/default');
  assert.throws(() => loadConfig({ AUTH_PROVIDER: 'oidc', BASE_URL: 'https://a.example.com', OIDC_ISSUER: 'https://x.example.com', OIDC_CLIENT_ID: 'v', OIDC_CLIENT_SECRET: 's', AUTH_SECRET: 'z'.repeat(32), ENTRA_GRAPH: 'true' }), /does not apply/);
  assert.throws(() => loadConfig({ AUTH_PROVIDER: 'oidc', BASE_URL: 'https://a.example.com', OIDC_ISSUER: 'https://x.example.com', OIDC_CLIENT_ID: 'v', OIDC_CLIENT_SECRET: 's', AUTH_SECRET: 'z'.repeat(32), RECIPIENT_USER_GROUP: 'ops' }), /needs AUTH_PROVIDER=entra/);
  assert.throws(() => loadConfig({ AUTH_PROVIDER: 'okta' }), /none, entra or oidc/);
});

test('external Redis: REDIS_URL_FILE and REDIS_TLS_CA_FILE', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vanishly-redis-'));
  const urlFile = join(dir, 'url');
  writeFileSync(urlFile, 'rediss://app:change-me@redis.example.com:6380/2\n');
  assert.equal(loadConfig({ REDIS_URL_FILE: urlFile }).redisUrl, 'rediss://app:change-me@redis.example.com:6380/2');
  assert.equal(loadConfig({ REDIS_URL: 'redis://user:change-me@10.0.0.5:6379/1' }).redisUrl, 'redis://user:change-me@10.0.0.5:6379/1');
  assert.throws(() => loadConfig({ REDIS_URL: 'redis://a:6379', REDIS_URL_FILE: urlFile }), /REDIS_URL and REDIS_URL_FILE are both set/);
  assert.throws(() => loadConfig({ REDIS_URL_FILE: join(dir, 'missing') }), /REDIS_URL_FILE: cannot read/);
  writeFileSync(join(dir, 'bad'), 'localhost:6379');
  assert.throws(() => loadConfig({ REDIS_URL_FILE: join(dir, 'bad') }), /REDIS_URL: must look like/);
  const ca = join(dir, 'ca.pem');
  writeFileSync(ca, '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n');
  assert.match(loadConfig({ REDIS_URL: 'rediss://redis.example.com:6380', REDIS_TLS_CA_FILE: ca }).redisTlsCa, /BEGIN CERTIFICATE/);
  assert.equal(loadConfig({}).redisTlsCa, '');
  assert.throws(() => loadConfig({ REDIS_URL: 'redis://redis.example.com:6379', REDIS_TLS_CA_FILE: ca }), /REDIS_TLS_CA_FILE needs a rediss:\/\//);
  assert.throws(() => loadConfig({ REDIS_URL: 'rediss://r:6380', REDIS_TLS_CA_FILE: join(dir, 'nope.pem') }), /REDIS_TLS_CA_FILE: cannot read/);
  assert.throws(() => loadConfig({ REDIS_URL: 'rediss://r:6380', REDIS_TLS_CA_FILE: urlFile }), /no PEM certificate/);
});
