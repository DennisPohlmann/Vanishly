// Audit log (AUDIT_LOG) and personal API tokens (API_TOKENS): the hash
// chain and its check, the formats, the token rules (IP networks behind a
// proxy and IPv6, expiry, scopes, revocation), comments, the admin view,
// fail-closed, and that nothing of a secret reaches the log. Unit tests run
// always; the app tests need Redis (REDIS_URL or a local redis-server).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { createApp, csvCell } from '../src/app.js';
import { Audit, canonical, chainOf, clean, formatEvent, hashOf, normalize, parseTraceparent, sanitizeText, secretsOverview, splitObjects, verifyText } from '../src/audit.js';
import { expiryAt, loadConfig, parseExpiry } from '../src/config.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';
import { ipAllowed, parseNetworks } from '../src/tokens.js';
import { encryptSecret } from '../public/js/vanishly-crypto.js';
import { startMock } from './oidc-mock.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };
const TENANT = '11111111-2222-3333-4444-555555555555';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const SECRET = 'client-secret-for-tests';
const ALICE = { oid: '00000000-0000-0000-0000-00000000000a', tid: TENANT, name: 'Alice Example', preferred_username: 'alice@example.com' };
const IT = '0f0f0f0f-1111-2222-3333-444444444444';
const HR = '0e0e0e0e-1111-2222-3333-444444444444';
const BOB = { oid: '00000000-0000-0000-0000-00000000000b', tid: TENANT, name: 'Bob Example', preferred_username: 'bob@example.com' };
const PLAIN = 'Hunter2-very-secret-plaintext-0815';
const dir = mkdtempSync(join(tmpdir(), 'vanishly-audit-'));

// ------------------------------------------------------------------ unit
/** A small chain of events in a format, as the Audit class writes them. @param {'ecs' | 'otel' | 'plain'} format */
async function chainText(format, n = 5, { pretty = false, hmacKey = '' } = {}) {
  const file = join(dir, `chain-${format}-${pretty}-${Math.random()}.jsonl`);
  const a = new Audit(/** @type {any} */ ({ format, pretty, file, fsync: false, stdout: false, redis: false, hmacKey, failClosed: true, ip: 'full', userAgent: true, instance: 'unit', checkpoint: 0 }), { version: 't' });
  for (let i = 0; i < n; i++) {
    await a.log({ type: 'secret.created', actor: { type: 'user', user: 'alice@example.com', name: 'Alice' }, recipients: { users: ['bob@example.com'] }, comment: `c${i}`, runId: `run-${i}`, details: { max_views: 1 } });
  }
  await a.close();
  return { file, text: readFileSync(file, 'utf8') };
}

test('canonical JSON sorts keys; clean drops empty values but keeps false and 0', () => {
  assert.equal(canonical({ b: 1, a: { d: [2, { z: 1, y: 0 }], c: 'x' } }), '{"a":{"c":"x","d":[2,{"y":0,"z":1}]},"b":1}');
  assert.deepEqual(clean({ a: '', b: null, c: [], d: {}, e: false, f: 0, g: { h: undefined }, i: 'x' }), { e: false, f: 0, i: 'x' });
  assert.equal(sanitizeText('  reset\na\tuser\u202Epw\u0000  ', 100), 'reset a user pw');
  assert.equal(sanitizeText('x'.repeat(50), 10).length, 10);
  assert.deepEqual(parseTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'), { traceId: '4bf92f3577b34da6a3ce929d0e0e4736', parentId: '00f067aa0ba902b7', flags: '01' });
  assert.equal(parseTraceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01'), null);
  assert.equal(parseTraceparent('garbage'), null);
  assert.equal(csvCell('=HYPERLINK("x")'), `"'=HYPERLINK(""x"")"`);
  assert.equal(csvCell(['a', 'b']), '"a; b"');
});

for (const format of /** @type {const} */ (['ecs', 'otel', 'plain'])) {
  test(`${format}: valid JSON lines with the expected keys; verify finds changes, removals, moves and insertions`, async () => {
    const { text } = await chainText(format);
    const lines = text.trim().split('\n');
    assert.equal(lines.length, 5);
    for (const l of lines) {
      const r = JSON.parse(l);
      const c = chainOf(r);
      assert.equal(c.format, format);
      assert.match(c.get('hash'), /^[0-9a-f]{64}$/);
      assert.equal(hashOf(r), c.get('hash'));
      if (format === 'ecs') {
        for (const k of ['@timestamp', 'log.level', 'message', 'ecs.version']) assert.ok(k in r, k);
        assert.equal(r.event.action, 'secret.created');
        assert.equal(r.event.outcome, 'success');
        assert.deepEqual(r.event.category, ['web']);
        assert.equal(r.user.name, 'alice@example.com');
        assert.equal(r.service.name, 'vanishly');
        assert.ok(r.labels.run_id);
        assert.deepEqual(r.related.user, ['alice@example.com', 'bob@example.com']);
      } else if (format === 'otel') {
        for (const k of ['Timestamp', 'SeverityText', 'SeverityNumber', 'Body', 'Resource', 'Attributes']) assert.ok(k in r, k);
        assert.equal(r.Attributes['event.name'], 'vanishly.secret.created');
        assert.equal(r.Resource['service.name'], 'vanishly');
        assert.equal(r.Attributes['user.id'], 'alice@example.com');
      } else {
        for (const k of ['ts', 'id', 'type', 'outcome', 'actor', 'run_id', 'audit']) assert.ok(k in r, k);
      }
      // No noise: no null, no empty strings.
      assert.doesNotMatch(l, /:null|:""|:\[\]|:\{\}/);
      const n = normalize(r);
      assert.equal(n.type, 'secret.created');
      assert.equal(n.actor.user, 'alice@example.com');
      assert.deepEqual(n.recipients, ['bob@example.com']);
    }
    assert.equal(verifyText(text).ok, true);
    // changed content
    const changed = lines.map((l, i) => (i === 2 ? l.replace('c2', 'c9') : l)).join('\n');
    assert.match(verifyText(changed).errors[0].problem, /hash does not match/);
    // a removed entry
    const removed = lines.filter((_, i) => i !== 2).join('\n');
    assert.ok(verifyText(removed).errors.some((e) => /missing|prev_hash/.test(e.problem)));
    // two entries swapped
    const swapped = [lines[0], lines[2], lines[1], lines[3], lines[4]].join('\n');
    assert.equal(verifyText(swapped).ok, false);
    // the hash recomputed after a change does not help: the next prev_hash no longer fits
    const forged = JSON.parse(lines[1]);
    const fc = chainOf(forged);
    if (format === 'ecs') forged.vanishly.comment = 'forged';
    else if (format === 'otel') forged.Attributes['vanishly.comment'] = 'forged';
    else forged.comment = 'forged';
    fc.set('hash', hashOf(forged));
    const r = verifyText([lines[0], JSON.stringify(forged), ...lines.slice(2)].join('\n'));
    assert.ok(r.errors.some((e) => /prev_hash/.test(e.problem)));
    // the front cut off
    assert.match(verifyText(lines.slice(1).join('\n')).errors[0].problem, /starts at seq 2/);
    // garbage line
    assert.equal(verifyText(`${text}not json\n`).ok, false);
  });
}

test('pretty output, HMAC signatures, restart resume and several instances', async () => {
  const { text } = await chainText('ecs', 3, { pretty: true, hmacKey: 'k'.repeat(40) });
  assert.ok(text.split('\n').length > 20, 'pretty-printed over several lines');
  assert.equal([...splitObjects(text)].length, 3);
  assert.equal(verifyText(text, { hmacKey: 'k'.repeat(40) }).ok, true);
  assert.match(verifyText(text, { hmacKey: 'w'.repeat(40) }).errors[0].problem, /signature/);
  // Forge: change, rehash; without the key the signature cannot be made.
  const objs = [...splitObjects(text)].map((o) => JSON.parse(o.text));
  objs[2].vanishly.comment = 'forged';
  chainOf(objs[2]).set('hash', hashOf(objs[2]));
  assert.match(verifyText(objs.map((o) => JSON.stringify(o)).join('\n'), { hmacKey: 'k'.repeat(40) }).errors[0].problem, /signature/);

  // Restart: a new Audit on the same file continues the chain.
  const file = join(dir, 'restart.jsonl');
  const cfg = /** @type {any} */ ({ format: 'plain', file, fsync: true, stdout: false, redis: false, failClosed: true, ip: 'full', userAgent: true, instance: 'a', checkpoint: 2 });
  for (let round = 0; round < 3; round++) {
    const a = new Audit(cfg, {});
    await a.log({ type: 'system.startup', actor: { type: 'system' } });
    if (round === 0) await a.log({ type: 'auth.login', actor: { type: 'user', user: 'alice@example.com' } });
    await a.close();
  }
  // A second instance writes into the same file: its own chain.
  const b = new Audit({ ...cfg, instance: 'b' }, {});
  await b.log({ type: 'system.startup', actor: { type: 'system' } });
  await b.close();
  const r = verifyText(readFileSync(file, 'utf8'));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.deepEqual(r.instances.map((i) => [i.instance, i.lastSeq]), [['a', 5], ['b', 1]]); // 3 starts, 1 login, 1 checkpoint
  assert.ok(readFileSync(file, 'utf8').includes('audit.checkpoint'));

  // The CLI: OK, then BROKEN on a changed copy (exit 1).
  const ok = spawnSync(process.execPath, ['src/audit-verify.js', file], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /OK - 6 events/);
  const bad = join(dir, 'restart-tampered.jsonl');
  writeFileSync(bad, readFileSync(file, 'utf8').replace('"instance":"a","prev_hash"', '"instance":"a","x":1,"prev_hash"'));
  const broken = spawnSync(process.execPath, ['src/audit-verify.js', bad], { encoding: 'utf8' });
  assert.equal(broken.status, 1);
  assert.match(broken.stdout, /BROKEN/);
  const head = r.instances[0].head;
  const cut = spawnSync(process.execPath, ['src/audit-verify.js', file, '--expect-head', `a=${'0'.repeat(64)}`], { encoding: 'utf8' });
  assert.equal(cut.status, 1);
  assert.equal(spawnSync(process.execPath, ['src/audit-verify.js', file, '--expect-head', `a=${head}`]).status, 0);
});

test('formatEvent: refused token call in ECS, OTel and plain', () => {
  const e = { id: '1', ts: new Date('2026-10-29T12:00:00Z'), type: 'api.ip_denied', outcome: /** @type {const} */ ('denied'), reason: 'ip_denied', actor: { type: /** @type {const} */ ('api_token'), user: 'a@example.com', name: 'A', token: { id: 'abc', name: 'api_aap' } }, source: { ip: '203.0.113.9' }, traceId: 'f'.repeat(32) };
  const svc = { name: 'vanishly', version: '1', instance: 'i' };
  const ecs = formatEvent(e, 'ecs', svc, { seq: 1, prev: '0'.repeat(64) });
  assert.equal(ecs['log.level'], 'warn');
  assert.equal(ecs.event.outcome, 'failure');
  assert.deepEqual(ecs.event.type, ['denied']);
  assert.equal(ecs.source.ip, '203.0.113.9');
  assert.equal(ecs.trace.id, 'f'.repeat(32));
  assert.equal(ecs.labels.token_name, 'api_aap');
  const otel = formatEvent(e, 'otel', svc, { seq: 1, prev: '0'.repeat(64) });
  assert.equal(otel.SeverityNumber, 13);
  assert.equal(otel.TraceId, 'f'.repeat(32));
  assert.equal(otel.Attributes['client.address'], '203.0.113.9');
  assert.equal(otel.Attributes['vanishly.actor.token.name'], 'api_aap');
  const plain = formatEvent(e, 'plain', svc, { seq: 1, prev: '0'.repeat(64) });
  assert.equal(plain.message, 'api.ip_denied denied (ip_denied) by a@example.com via token api_aap');
});

test('token lifetimes: units d, m, y; calendar months; config caps and errors', () => {
  assert.equal(parseExpiry('30D'), '30d');
  assert.equal(parseExpiry('6m'), '6m');
  assert.equal(parseExpiry('never'), 'never');
  assert.equal(parseExpiry('0'), 'never');
  for (const bad of ['30', '1w', '0d', '-1d', '11y', '121m', 'soon', '']) assert.throws(() => parseExpiry(bad), /lifetime/, bad);
  const jan31 = Date.UTC(2027, 0, 31, 10, 0);
  assert.equal(new Date(expiryAt('1m', jan31)).toISOString(), '2027-02-28T10:00:00.000Z');
  assert.equal(new Date(expiryAt('1m', Date.UTC(2028, 0, 31))).toISOString(), '2028-02-29T00:00:00.000Z');
  assert.equal(new Date(expiryAt('1y', Date.UTC(2028, 1, 29))).toISOString(), '2029-02-28T00:00:00.000Z');
  assert.equal(new Date(expiryAt('13m', Date.UTC(2027, 11, 15))).toISOString(), '2029-01-15T00:00:00.000Z');
  assert.equal(expiryAt('30d', 0), 30 * 86400000);
  assert.equal(expiryAt('never', 5), 0);

  const base = { BASE_URL: 'https://ots.example.com', AUTH_PROVIDER: 'entra', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT, ENTRA_CLIENT_SECRET: SECRET, AUTH_SECRET: 'x'.repeat(40) };
  let c = loadConfig({ ...base, API_TOKENS: 'true' });
  assert.deepEqual(c.auth?.tokens?.expiryOptions, ['30d', '60d', '90d', 'never']);
  assert.equal(c.auth?.tokens?.defaultExpiry, '90d');
  c = loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_EXPIRY_OPTIONS: '1y,30d,6m,never,60d', API_TOKEN_MAX_EXPIRY: '6m' });
  assert.deepEqual(c.auth?.tokens?.expiryOptions, ['30d', '60d', '6m'], 'never and 1y go with a cap');
  assert.equal(c.auth?.tokens?.defaultExpiry, '6m');
  c = loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_EXPIRY_OPTIONS: '30d,1y', API_TOKEN_DEFAULT_EXPIRY: '6m' });
  assert.deepEqual(c.auth?.tokens?.expiryOptions, ['30d', '6m', '1y'], 'the default joins the options');
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_DEFAULT_EXPIRY: '1y', API_TOKEN_MAX_EXPIRY: '90d' }), /above API_TOKEN_MAX_EXPIRY/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_EXPIRY_OPTIONS: '1y,never', API_TOKEN_MAX_EXPIRY: '30d' }), /no lifetime within/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_EXPIRY_OPTIONS: '30x' }), /API_TOKEN_EXPIRY_OPTIONS: "30x"/);
  assert.throws(() => loadConfig({ ...base, API_TOKEN_REQUIRED: 'true' }), /needs API_TOKENS=true/);
  assert.equal(loadConfig({ ...base, API_TOKENS: 'true' }).auth?.tokens?.maxPerUser, 10, 'default: 10 active tokens per user');
  assert.equal(loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_MAX_PER_USER: '0' }).auth?.tokens?.maxPerUser, 0, '0 = no limit');
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_MAX_PER_USER: '-1' }), /API_TOKEN_MAX_PER_USER/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_TOKEN_MAX_PER_USER: '1001' }), /API_TOKEN_MAX_PER_USER/);
  assert.throws(() => loadConfig({ API_TOKENS: 'true' }), /needs AUTH_PROVIDER/);
  // Audit settings
  assert.equal(loadConfig({}).audit, null);
  assert.throws(() => loadConfig({ AUDIT_COMMENT: 'optional' }), /AUDIT_COMMENT needs AUDIT_LOG=true/);
  assert.throws(() => loadConfig({ AUDIT_LOG_FILE: '/tmp/x' }), /needs AUDIT_LOG=true/);
  assert.throws(() => loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_FORMAT: 'xml' }), /ecs, otel or plain/);
  assert.throws(() => loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_STDOUT: 'false' }), /needs a sink/);
  assert.throws(() => loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_HMAC_KEY: 'short' }), /at least 32/);
  assert.throws(() => loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_SYSLOG: 'http://x:514' }), /udp:\/\//);
  assert.throws(() => loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_WEBHOOK_AUTH: 'Bearer x' }), /need AUDIT_LOG_WEBHOOK_URL/);
  assert.throws(() => loadConfig({ AUDIT_LOGG: 'true' }), /did you mean AUDIT_LOG/);
  const a = loadConfig({ AUDIT_LOG: 'true', AUDIT_LOG_SYSLOG: 'tls://[2001:db8::1]:6514', AUDIT_LOG_OTLP_URL: 'http://collector:4318/v1/logs', AUDIT_LOG_OTLP_HEADERS: 'x-scope-orgid=t1' }).audit;
  assert.equal(a?.format, 'ecs');
  assert.equal(a?.stdout, true, 'stdout when no file or Redis');
  assert.equal(a?.failClosed, true);
  assert.deepEqual(a?.syslog, { proto: 'tls', host: '2001:db8::1', port: 6514, ca: '' });
  assert.deepEqual(a?.otlp?.headers, { 'x-scope-orgid': 't1' });
});

test('IP networks: IPv4, IPv6, IPv4-mapped, invalid ones refused', () => {
  assert.deepEqual(parseNetworks('203.0.113.0/24, 2001:DB8::/32 198.51.100.7'), ['203.0.113.0/24', '2001:db8::/32', '198.51.100.7/32']);
  for (const bad of ['10.0.0.0/33', '10.0.0.0/4', 'example.com', '1.2.3', '::/8', '2001:db8::/129']) assert.throws(() => parseNetworks(bad), undefined, bad);
  assert.ok(ipAllowed('203.0.113.77', ['203.0.113.0/24']));
  assert.ok(ipAllowed('::ffff:203.0.113.77', ['203.0.113.0/24']));
  assert.ok(!ipAllowed('203.0.114.1', ['203.0.113.0/24']));
  assert.ok(ipAllowed('2001:db8:1::5', ['2001:db8::/32']));
  assert.ok(!ipAllowed('2001:db9::5', ['2001:db8::/32']));
  assert.ok(!ipAllowed('', ['0.0.0.0/8']));
  assert.ok(!ipAllowed('203.0.113.77', []));
});

// ------------------------------------------------------------------ app
/** @type {any} */ let redisProc;
let redisUrl = '';
/** @type {Awaited<ReturnType<typeof startMock>>} */ let mock;
/** @type {(() => Promise<void>)[]} */ const closers = [];

before(async () => {
  if (!haveRedis) return;
  redisUrl = process.env.REDIS_URL || '';
  if (!redisUrl) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    redisProc = spawn('redis-server', ['--port', String(port), '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
    redisUrl = `redis://127.0.0.1:${port}`;
    await new Promise((r) => setTimeout(r, 300));
  }
  mock = await startMock({ tenant: TENANT, clientId: CLIENT, clientSecret: SECRET });
});

after(async () => {
  for (const c of closers) await c();
  await mock?.close();
  redisProc?.kill();
});

let n = 0;
/**
 * An app with sign-in (alice is admin) and, unless env says otherwise, the
 * audit log in a file plus Redis and personal API tokens.
 * @param {Record<string, string>} env
 * @param {{ noAudit?: boolean }} [o]
 */
async function startApp(env = {}, o = {}) {
  /** @type {any} */ let handler = null;
  const server = createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(undefined)));
  const base = `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
  const file = join(dir, `app-${n}.jsonl`);
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `audittest${process.pid}-${n++}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ACCESS_LOG: 'false',
    BASE_URL: base,
    AUTH_PROVIDER: 'entra',
    ENTRA_TENANT_ID: TENANT,
    ENTRA_CLIENT_ID: CLIENT,
    ENTRA_CLIENT_SECRET: SECRET,
    ENTRA_AUTHORITY: mock.base,
    ENTRA_GRAPH_URL: mock.base,
    AUTH_SECRET: 'x'.repeat(40),
    AUTH_CREATE: 'anyone',
    ...(o.noAudit ? {} : { AUDIT_LOG: 'true', AUDIT_LOG_FILE: file, AUDIT_LOG_REDIS: 'true', AUDIT_LOG_STDOUT: 'true', AUDIT_LOG_FSYNC: 'false', AUDIT_LOG_INSTANCE: 'test', AUDIT_COMMENT: 'optional', ADMIN_USERS: 'alice@example.com', API_TOKENS: 'true' }),
    ...env,
  });
  const store = await Store.connect(redisUrl, config);
  /** @type {string[]} */ const stdout = [];
  const audit = config.audit ? new Audit(config.audit, { redis: store.redis, p: store.p, version: 'test', write: (s) => void stdout.push(s) }) : null;
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test', audit });
  handler = app;
  closers.push(async () => {
    server.close();
    await audit?.close();
    await store.close();
  });
  /**
   * @param {string} path
   * @param {{ body?: any, cookie?: string, bearer?: string, headers?: Record<string, string>, method?: string }} [q]
   */
  const call = async (path, q = {}) => {
    const res = await fetch(base + path, {
      method: q.method || (q.body === undefined ? 'GET' : 'POST'),
      headers: { 'Content-Type': 'application/json', ...(q.cookie ? { Cookie: q.cookie } : {}), ...(q.bearer ? { Authorization: `Bearer ${q.bearer}` } : {}), ...q.headers },
      body: q.body === undefined ? undefined : JSON.stringify(q.body),
      redirect: 'manual',
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: res.status, data, text, headers: res.headers };
  };
  /** @param {Record<string, any>} claims */
  const login = async (claims) => {
    mock.user = claims;
    const start = await fetch(`${base}/auth/login?return=/`, { redirect: 'manual' });
    const atProvider = await fetch(String(start.headers.get('location')), { redirect: 'manual' });
    const done = await fetch(String(atProvider.headers.get('location')), { redirect: 'manual' });
    return String(done.headers.get('set-cookie') || '').split(';')[0];
  };
  /** The audit events so far (file), each as the normalized view plus raw. */
  const events = async () => {
    await audit?.queue;
    return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => ({ ...normalize(JSON.parse(l)), raw: JSON.parse(l), line: l }));
  };
  return { base, call, login, config, store, audit, file, stdout, events };
}

test('API token: made on the session, used from its network with comment and run id; the log says who, what, for whom', opts, async () => {
  const a = await startApp();
  const cookie = await a.login(ALICE);
  const made = await a.call('/api/v1/tokens', { cookie, body: { name: 'api_aap', expires: '30d', ips: ['127.0.0.1/32', '2001:db8::/32'], scopes: ['create', 'status'] } });
  assert.equal(made.status, 201, made.text);
  assert.match(made.data.token, /^vnly_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
  assert.equal(made.data.state, 'active');
  const token = made.data.token;
  // Never stored as such.
  const keys = await a.store.redis.keys(`${a.store.p}tok:*`);
  for (const k of keys) {
    const v = (await a.store.redis.type(k)) === 'hash' ? JSON.stringify(await a.store.redis.hGetAll(k)) : '';
    assert.ok(!v.includes(token.split('_')[2]), 'no token secret in Redis');
  }
  // The list shows it without the token, with expiry.
  const list = await a.call('/api/v1/tokens', { cookie });
  assert.equal(list.data.tokens[0].prefix, `vnly_${made.data.id}_`);
  assert.ok(Date.parse(list.data.tokens[0].expires) - Date.now() > 29 * 86400000);
  assert.ok(!list.text.includes(token));
  assert.equal(list.data.options.yourIp, '127.0.0.1');

  const shared = await a.call('/api/v1/share', { bearer: token, headers: { 'X-Run-Id': 'run-4711', 'X-Audit-Comment': 'reset a user pw', 'X-On-Behalf-Of': 'ticket INC-42' }, body: { secret: PLAIN, ttl: 600, recipients: ['bob@example.com'] } });
  assert.equal(shared.status, 201, shared.text);
  assert.equal(shared.headers.get('x-run-id'), 'run-4711');
  // A token cannot make tokens.
  assert.equal((await a.call('/api/v1/tokens', { bearer: token, body: { name: 'x' } })).status, 403);

  const ev = await a.events();
  const created = ev.find((e) => e.type === 'secret.created');
  assert.ok(created);
  assert.equal(created.actor.type, 'api_token');
  assert.equal(created.actor.user, 'alice@example.com');
  assert.equal(created.actor.token, 'api_aap');
  assert.equal(created.actor.onBehalfOf, 'ticket INC-42');
  assert.equal(created.comment, 'reset a user pw');
  assert.equal(created.runId, 'run-4711');
  assert.deepEqual(created.recipients, ['bob@example.com']);
  assert.equal(created.ip, '127.0.0.1');
  assert.equal(created.raw.vanishly.details.encrypted, 'server');
  assert.ok(ev.some((e) => e.type === 'api.token_created' && e.actor.user === 'alice@example.com'));
  assert.ok(ev.some((e) => e.type === 'api.token_used' && e.runId === 'run-4711' && e.raw.http.response.status_code === 201));
  assert.ok(ev.some((e) => e.type === 'auth.login'));

  // Bob opens it: logged with Bob as actor, the same secret ref.
  const bob = await a.login(BOB);
  const link = shared.data.shareUrl;
  const opened = await a.call('/api/v1/open', { cookie: bob, body: { link } });
  assert.equal(opened.data.secret, PLAIN);
  const after = await a.events();
  const revealed = after.find((e) => e.type === 'secret.revealed');
  assert.equal(revealed?.actor.user, 'bob@example.com');
  assert.equal(revealed?.secretRef, created.secretRef);

  // Nothing of the secret anywhere in the log: file, stdout, Redis stream.
  const id = shared.data.id;
  const key = link.split('#')[1];
  const stream = JSON.stringify(await a.store.redis.xRange(`${a.store.p}audit`, '-', '+'));
  for (const where of [readFileSync(a.file, 'utf8'), a.stdout.join(''), stream]) {
    for (const bad of [PLAIN, id, key, token, shared.data.receiptId]) assert.ok(!where.includes(bad), `leak of ${bad.slice(0, 6)}...`);
    assert.doesNotMatch(where, /"ciphertext"|vnly_[0-9a-f]{16}_[A-Za-z0-9_-]{20}/);
  }
  assert.equal(verifyText(readFileSync(a.file, 'utf8')).ok, true);
});

test('IP binding: other address (behind a proxy, IPv6) refused and logged; expiry, revocation, scopes', opts, async () => {
  const a = await startApp({ TRUST_PROXY: 'loopback', API_TOKEN_IP_BINDING: 'required' });
  const cookie = await a.login(ALICE);
  assert.equal((await a.call('/api/v1/tokens', { cookie, body: { name: 'nets' } })).data.error, 'ips_required');
  assert.equal((await a.call('/api/v1/tokens', { cookie, body: { name: 'nets', ips: ['not-an-ip'] } })).data.error, 'invalid_ips');
  assert.equal((await a.call('/api/v1/tokens', { cookie, body: { name: 'nets', ips: ['203.0.113.0/24'], expires: '5y' } })).data.error, 'invalid_expiry');
  const t = (await a.call('/api/v1/tokens', { cookie, body: { name: 'nets', ips: ['203.0.113.0/24', '2001:db8::/32'], scopes: ['create'] } })).data;
  const body = { secret: PLAIN, ttl: 600 };
  /** @param {string} xff */
  const from = (xff) => a.call('/api/v1/share', { bearer: t.token, headers: { 'X-Forwarded-For': xff }, body });
  assert.equal((await from('203.0.113.50')).status, 201);
  assert.equal((await from('2001:db8:5::1')).status, 201);
  const denied = await from('198.51.100.9');
  assert.equal(denied.status, 403);
  assert.equal(denied.data.error, 'ip_not_allowed');
  assert.equal((await from('2001:db9::1')).status, 403);
  // A forged X-Forwarded-For only counts from a trusted proxy: here the
  // proxy (loopback) is trusted; the first untrusted address decides.
  const ev = await a.events();
  const ipDenied = ev.filter((e) => e.type === 'api.ip_denied');
  assert.equal(ipDenied.length, 2);
  assert.equal(ipDenied[0].ip, '198.51.100.9');
  assert.equal(ipDenied[0].actor.token, 'nets');
  assert.equal(ipDenied[0].outcome, 'denied');
  // Scope: no "status".
  const s = (await from('203.0.113.50')).data;
  const rc = await a.call(`/api/v1/receipts/${s.receiptId}`, { bearer: t.token, headers: { 'X-Forwarded-For': '203.0.113.50' } });
  assert.equal(rc.status, 403);
  assert.equal(rc.data.error, 'insufficient_scope');
  // Expired: refused and logged as api.token_expired.
  await a.store.redis.hSet(`${a.store.p}tok:${t.id}`, 'expires', String(Date.now() - 1000));
  const exp = await from('203.0.113.50');
  assert.equal(exp.data.error, 'token_expired');
  assert.ok((await a.events()).some((e) => e.type === 'api.token_expired'));
  assert.equal((await a.call('/api/v1/tokens', { cookie })).data.tokens[0].state, 'expired');
  // Revoked (by an admin): refused.
  await a.store.redis.hSet(`${a.store.p}tok:${t.id}`, 'expires', String(Date.now() + 86400000));
  assert.equal((await from('203.0.113.50')).status, 201);
  assert.equal((await a.call(`/api/v1/admin/tokens/${t.id}/revoke`, { cookie, body: {} })).data.state, 'revoked');
  assert.equal((await from('203.0.113.50')).data.error, 'invalid_token');
  assert.equal((await a.call('/api/v1/share', { bearer: `vnly_${'0'.repeat(16)}_${'A'.repeat(43)}`, body })).data.error, 'invalid_token');
  const last = await a.events();
  assert.ok(last.some((e) => e.type === 'admin.token_revoked' && e.actor.user === 'alice@example.com'));
  assert.ok(last.some((e) => e.type === 'api.token_denied' && e.reason === 'revoked'));
});

test('API_TOKEN_MAX_PER_USER: active tokens only, revoked and expired ones do not count, the refusal is logged; 0 = no limit', opts, async () => {
  const a = await startApp({ API_TOKEN_MAX_PER_USER: '3' });
  const cookie = await a.login(ALICE);
  /** @param {string} name */
  const make = (name) => a.call('/api/v1/tokens', { cookie, body: { name } });
  for (const name of ['one', 'two', 'three']) assert.equal((await make(name)).status, 201);
  let list = await a.call('/api/v1/tokens', { cookie });
  assert.equal(list.data.active, 3);
  assert.equal(list.data.options.maxPerUser, 3);
  const fourth = await make('four');
  assert.equal(fourth.status, 400);
  assert.equal(fourth.data.error, 'too_many_tokens');
  assert.deepEqual([fourth.data.active, fourth.data.max], [3, 3]);
  const denied = (await a.events()).find((e) => e.type === 'api.token_create_denied');
  assert.equal(denied?.reason, 'limit_reached');
  assert.deepEqual(denied?.raw.vanishly.details, { active: 3, max: 3 });
  assert.equal(denied?.actor.user, 'alice@example.com');
  // A revoked token frees a place.
  const one = list.data.tokens.find((/** @type {any} */ t) => t.name === 'one');
  await a.call(`/api/v1/tokens/${one.id}/revoke`, { cookie, body: {} });
  assert.equal((await a.call('/api/v1/tokens', { cookie })).data.active, 2);
  assert.equal((await make('four')).status, 201);
  assert.equal((await make('five')).data.error, 'too_many_tokens');
  // So does an expired one.
  list = await a.call('/api/v1/tokens', { cookie });
  const two = list.data.tokens.find((/** @type {any} */ t) => t.name === 'two');
  await a.store.redis.hSet(`${a.store.p}tok:${two.id}`, 'expires', String(Date.now() - 1000));
  assert.equal((await a.call('/api/v1/tokens', { cookie })).data.active, 2);
  assert.equal((await make('five')).status, 201);
  // The page knows the limit (it shows "x of 3"; the default would be 10).
  assert.match(await (await fetch(`${a.base}/settings/tokens`, { headers: { Cookie: cookie } })).text(), /data-max="3"/);
  // Requests at the same time do not get past the limit together.
  const bob = await a.login(BOB);
  const race = await Promise.all(Array.from({ length: 6 }, (_, i) => a.call('/api/v1/tokens', { cookie: bob, body: { name: `p${i}` } })));
  assert.ok(race.filter((r) => r.status === 201).length <= 3);
  assert.ok((await a.call('/api/v1/tokens', { cookie: bob })).data.active <= 3);

  const free = await startApp({ API_TOKEN_MAX_PER_USER: '0' });
  const c2 = await free.login(ALICE);
  for (let i = 0; i < 6; i++) assert.equal((await free.call('/api/v1/tokens', { cookie: c2, body: { name: `t${i}` } })).status, 201);
  assert.equal((await free.call('/api/v1/tokens', { cookie: c2 })).data.active, 6);
});

test('scopes: API_TOKEN_ALLOWED_SCOPES, _DEFAULT_SCOPES, _SCOPES_BY_GROUP and API_TOKEN_ADMIN_POLICY are checked at start', () => {
  const base = { BASE_URL: 'https://ots.example.com', AUTH_PROVIDER: 'entra', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT, ENTRA_CLIENT_SECRET: SECRET, AUTH_SECRET: 'x'.repeat(40), API_TOKENS: 'true' };
  let t = loadConfig(base).auth?.tokens;
  assert.deepEqual([t?.allowedScopes, t?.defaultScopes, t?.scopesByGroup, t?.adminPolicy], [['create', 'read', 'status'], ['create', 'status'], [], false]);
  t = loadConfig({ ...base, API_TOKEN_ALLOWED_SCOPES: 'read', API_TOKEN_SCOPES_BY_GROUP: `${IT}=create+read; ${HR}=none` }).auth?.tokens;
  assert.deepEqual(t?.allowedScopes, ['read']);
  assert.deepEqual(t?.defaultScopes, [], 'create,status filtered by the allowed ones');
  assert.deepEqual(t?.scopesByGroup, [{ group: IT, scopes: ['create', 'read'] }, { group: HR, scopes: [] }]);
  assert.ok(loadConfig({ ...base, API_TOKEN_SCOPES_BY_GROUP: `${IT}=read` }).auth?.extraGroups.includes(IT), 'the group is kept in the identity');
  assert.throws(() => loadConfig({ ...base, API_TOKEN_ALLOWED_SCOPES: 'create,delete' }), /API_TOKEN_ALLOWED_SCOPES: "delete" is not one of/);
  assert.throws(() => loadConfig({ ...base, API_TOKEN_ALLOWED_SCOPES: 'create', API_TOKEN_DEFAULT_SCOPES: 'read' }), /read is not in API_TOKEN_ALLOWED_SCOPES/);
  assert.throws(() => loadConfig({ ...base, API_TOKEN_SCOPES_BY_GROUP: 'it-read' }), /API_TOKEN_SCOPES_BY_GROUP/);
  assert.throws(() => loadConfig({ ...base, API_TOKEN_SCOPES_BY_GROUP: 'not-a-guid=read' }), /group object id/);
  assert.throws(() => loadConfig({ ...base, API_TOKEN_ADMIN_POLICY: 'true' }), /needs ADMIN_USERS or ADMIN_GROUPS/);
  assert.equal(loadConfig({ ...base, API_TOKEN_ADMIN_POLICY: 'true', ADMIN_USERS: 'alice@example.com' }).auth?.tokens?.adminPolicy, true);
});

test('scopes per token: only create, only retrieve, both, status; refusals are api.scope_denied', opts, async () => {
  const a = await startApp();
  const alice = await a.login(ALICE);
  const bob = await a.login(BOB);
  /** @param {string[]} scopes */
  const token = async (scopes) => (await a.call('/api/v1/tokens', { cookie: alice, body: { name: scopes.join('+'), scopes } })).data.token;
  const tok = { create: await token(['create']), read: await token(['read']), both: await token(['create', 'read']), status: await token(['status']) };
  // A secret for bob or anyone: made on the page by bob.
  const fresh = async () => (await a.call('/api/v1/share', { cookie: bob, body: { secret: PLAIN, ttl: 600 } })).data;
  /** @param {string} t */
  const share = (t) => a.call('/api/v1/share', { bearer: t, body: { secret: 'x', ttl: 600 } });
  /** @param {string} t */
  const open = async (t) => a.call('/api/v1/open', { bearer: t, body: { link: (await fresh()).shareUrl } });
  /** @param {string} t */
  const status = async (t) => a.call(`/api/v1/receipts/${(await share(tok.create)).data.receiptId}`, { bearer: t });
  const table = {
    create: [201, 403, 403],
    read: [403, 200, 403],
    both: [201, 200, 403],
    status: [403, 403, 200],
  };
  for (const [name, [s, o, st]] of Object.entries(table)) {
    const t = tok[/** @type {keyof typeof tok} */ (name)];
    assert.equal((await share(t)).status, s, `${name}: share`);
    const op = await open(t);
    assert.equal(op.status, o, `${name}: open`);
    if (o === 200) assert.equal(op.data.secret, PLAIN);
    else assert.equal(op.data.error, 'insufficient_scope');
    assert.equal((await status(t)).status, st, `${name}: status`);
  }
  const denied = (await a.events()).filter((e) => e.type === 'api.scope_denied');
  assert.ok(denied.length >= 6);
  assert.equal(denied[0].reason, 'not_granted');
  assert.equal(denied[0].actor.user, 'alice@example.com');
  assert.ok(denied[0].raw.vanishly.details.scope);
  // The default when no scopes are sent: create and status.
  const d = (await a.call('/api/v1/tokens', { cookie: alice, body: { name: 'default' } })).data;
  assert.deepEqual(d.scopes, ['create', 'status']);
  // The form: "only create", "only retrieve", "both" and the status box.
  const html = await (await fetch(`${a.base}/settings/tokens`, { headers: { Cookie: alice } })).text();
  for (const id of ['access-create', 'access-read', 'access-both', 'scope-status']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /id="access-create"[^>]*checked/, 'default create,status: "only create" and status');
});

test('API_TOKEN_ALLOWED_SCOPES: only these can be given; the form offers only them', opts, async () => {
  const a = await startApp({ API_TOKEN_ALLOWED_SCOPES: 'create', API_TOKEN_DEFAULT_SCOPES: 'create' });
  const alice = await a.login(ALICE);
  const r = await a.call('/api/v1/tokens', { cookie: alice, body: { name: 'x', scopes: ['create', 'read'] } });
  assert.equal(r.data.error, 'scope_not_allowed');
  assert.deepEqual(r.data.allowed, ['create']);
  assert.ok((await a.events()).some((e) => e.type === 'api.token_create_denied' && e.reason === 'scope_not_allowed'));
  assert.deepEqual((await a.call('/api/v1/tokens', { cookie: alice, body: { name: 'y' } })).data.scopes, ['create']);
  const list = await a.call('/api/v1/tokens', { cookie: alice });
  assert.deepEqual(list.data.options.allowedScopes, ['create']);
  const html = await (await fetch(`${a.base}/settings/tokens`, { headers: { Cookie: alice } })).text();
  assert.match(html, /id="access-create"/);
  assert.doesNotMatch(html, /id="access-read"|id="access-both"|id="scope-status"/);
});

test('API_TOKEN_ADMIN_POLICY: per user beats per group beats env; tighter policies apply at once; every change logged', opts, async () => {
  const env = { API_TOKEN_ADMIN_POLICY: 'true', API_TOKEN_SCOPES_BY_GROUP: `${HR}=status` };
  const a = await startApp(env);
  const alice = await a.login(ALICE);
  const CAROL = { oid: '00000000-0000-0000-0000-00000000000c', tid: TENANT, name: 'Carol', preferred_username: 'carol@example.com', groups: [IT, HR] };
  const DAVE = { oid: '00000000-0000-0000-0000-00000000000d', tid: TENANT, name: 'Dave', preferred_username: 'dave@example.com', groups: [HR] };
  const bob = await a.login(BOB);
  const carol = await a.login(CAROL);
  const dave = await a.login(DAVE);
  /** @param {string} c */
  const policy = async (c) => (await a.call('/api/v1/tokens', { cookie: c })).data.options;
  // Without admin settings: env by group for dave, the defaults for bob.
  assert.deepEqual([(await policy(dave)).allowedScopes, (await policy(dave)).policy], [['status'], 'env-group']);
  assert.deepEqual((await policy(bob)).allowedScopes, ['create', 'read', 'status']);
  // Only admins set policies.
  assert.equal((await a.call('/api/v1/admin/token-policies', { cookie: bob, body: { type: 'user', subject: 'bob@example.com', scopes: ['create'] } })).status, 403);
  /** @param {any} body */
  const set = (body) => a.call('/api/v1/admin/token-policies', { cookie: alice, body });
  // bob: only retrieve, at most 1 token.
  assert.equal((await set({ type: 'user', subject: 'Bob@Example.com', scopes: ['read'], max: 1 })).status, 200);
  assert.deepEqual([(await policy(bob)).allowedScopes, (await policy(bob)).maxPerUser, (await policy(bob)).policy], [['read'], 1, 'user']);
  assert.equal((await a.call('/api/v1/tokens', { cookie: bob, body: { name: 'c', scopes: ['create'] } })).data.error, 'scope_not_allowed');
  const bt = await a.call('/api/v1/tokens', { cookie: bob, body: { name: 'r' } });
  assert.deepEqual(bt.data.scopes, ['read'], 'default within the policy');
  assert.equal((await a.call('/api/v1/tokens', { cookie: bob, body: { name: 'r2' } })).data.error, 'too_many_tokens');
  // Group IT: create+read; carol (IT and HR) gets the IT policy (admin groups beat env groups).
  await set({ type: 'group', subject: IT, scopes: ['create', 'read'] });
  assert.deepEqual([(await policy(carol)).allowedScopes, (await policy(carol)).policy], [['create', 'read'], 'group']);
  // A user policy beats the group.
  await set({ type: 'user', subject: 'carol@example.com', scopes: ['status'] });
  assert.deepEqual((await policy(carol)).allowedScopes, ['status']);
  await set({ type: 'user', subject: 'carol@example.com', remove: true });
  assert.deepEqual((await policy(carol)).allowedScopes, ['create', 'read']);
  // Tightening: bob's read token stops reading at once (no revoke) ...
  const secret = (await a.call('/api/v1/share', { cookie: alice, body: { secret: PLAIN, ttl: 600 } })).data;
  await set({ type: 'user', subject: 'bob@example.com', scopes: ['create'], max: 1 });
  const op = await a.call('/api/v1/open', { bearer: bt.data.token, body: { link: secret.shareUrl } });
  assert.equal(op.status, 403);
  assert.equal(op.data.error, 'insufficient_scope');
  const sd = (await a.events()).filter((e) => e.type === 'api.scope_denied').pop();
  assert.equal(sd?.reason, 'policy');
  const mine = (await a.call('/api/v1/tokens', { cookie: bob })).data.tokens[0];
  assert.deepEqual([mine.scopes, mine.allowedNow, mine.state], [['read'], [], 'active']);
  // ... and with "revoke existing" it is revoked.
  const r = await set({ type: 'user', subject: 'bob@example.com', scopes: ['create'], max: 1, revokeExceeding: true });
  assert.deepEqual(r.data.revoked.map((/** @type {any} */ x) => x.owner), ['bob@example.com']);
  assert.equal((await a.call('/api/v1/tokens', { cookie: bob })).data.tokens[0].state, 'revoked');
  // The admin page lists them; every change is in the log with old and new.
  const list = await a.call('/api/v1/admin/token-policies', { cookie: alice });
  assert.deepEqual(list.data.policies.map((/** @type {any} */ p) => [p.type, p.subject]), [['user', 'bob@example.com'], ['group', IT]]);
  const changes = (await a.events()).filter((e) => /^admin\.token_policy_/.test(e.type));
  assert.equal(changes.length, 6);
  const first = changes[0].raw.vanishly.details;
  assert.deepEqual([first.subject_type, first.subject, first.old, first.new], ['user', 'bob@example.com', undefined, { scopes: ['read'], max: 1 }]);
  assert.ok((await a.events()).some((e) => e.type === 'admin.token_revoked' && e.reason === 'policy'));
  const page = await (await fetch(`${a.base}/admin`, { headers: { Cookie: alice } })).text();
  assert.match(page, /data-policies="1"/);
  assert.match(page, /id="policy-form"/);
  // Off: no endpoint.
  const off = await startApp();
  const c2 = await off.login(ALICE);
  assert.equal((await off.call('/api/v1/admin/token-policies', { cookie: c2 })).data.error, 'endpoint_disabled');
});

test('secrets overview: states from the audit events (open, partly opened, opened, expired, burned) and filters', () => {
  const ev = (/** @type {any} */ e) => ({ actor: { type: 'user', user: '', name: '', token: '' }, recipients: [], responsible: [], comment: '', runId: '', reason: '', receiptRef: '', details: {}, ...e });
  const now = Date.parse('2026-10-30T12:00:00Z');
  const created = (/** @type {string} */ ref, /** @type {any} */ x = {}) => ev({ type: 'secret.created', secretRef: ref, ts: '2026-10-30T10:00:00Z', actor: { type: 'api_token', user: 'svc:api_aap', name: 'api_aap', token: 'prod' }, recipients: ['bob@example.com'], comment: 'reset a user pw', details: { expires: '2026-10-30T13:00:00Z', max_views: 1, encrypted: 'server' }, ...x });
  const events = [
    created('a'),
    created('b', { details: { expires: '2026-10-30T11:00:00Z', max_views: 1 } }),
    created('c', { details: { expires: '2026-10-30T13:00:00Z', max_views: 2 }, recipients: [] }),
    ev({ type: 'secret.revealed', secretRef: 'c', ts: '2026-10-30T10:30:00Z', actor: { type: 'user', user: 'bob@example.com', name: 'Bob', token: '' }, details: { via: 'browser' } }),
    created('d'),
    ev({ type: 'secret.revealed', secretRef: 'd', ts: '2026-10-30T10:40:00Z', actor: { type: 'service_account', user: 'svc:pull', name: 'pull', token: 't1' }, details: { via: 'server' } }),
    created('e'),
    ev({ type: 'secret.burned', secretRef: 'e', ts: '2026-10-30T10:50:00Z', reason: 'manual' }),
    ev({ type: 'secret.revealed', secretRef: 'zz', ts: '2026-10-30T10:55:00Z' }),
  ];
  const all = secretsOverview(events, {}, now);
  assert.deepEqual(all.map((x) => [x.ref, x.status]), [['e', 'burned'], ['d', 'opened'], ['c', 'partly_opened'], ['b', 'expired'], ['a', 'open']]);
  assert.equal(all[1].views[0].via, 'token');
  assert.equal(all[2].views[0].via, 'browser');
  assert.equal(all[4].creator.token, 'prod');
  assert.deepEqual(secretsOverview(events, { status: 'opened' }, now).map((x) => x.ref), ['d']);
  assert.deepEqual(secretsOverview(events, { recipient: 'bob' }, now).map((x) => x.ref), ['e', 'd', 'b', 'a']);
  assert.equal(secretsOverview(events, { creator: 'nobody' }, now).length, 0);
});

/** An app with the admin interface, technical users and admin tokens. @param {Record<string, string>} [env] */
const adminApp = (env = {}) => startApp({ API_TOKEN_ADMIN_POLICY: 'true', API_ADMIN_TOKENS: 'true', TRUST_PROXY: 'loopback', ...env });

test('admin interface: tabs, Redis warnings, secrets overview from the audit stream (metadata only)', opts, async () => {
  const a = await adminApp();
  const alice = await a.login(ALICE);
  const bob = await a.login(BOB);
  const html = await (await fetch(`${a.base}/admin?tab=secrets`, { headers: { Cookie: alice } })).text();
  for (const tab of ['audit', 'secrets', 'tokens', 'services', 'policies']) assert.match(html, new RegExp(`href="/admin\\?tab=${tab}"`));
  assert.match(html, /aria-current="page">Secrets</);
  assert.match(html, /data-tab="secrets"/);
  // The test Redis runs without persistence: the page says so.
  assert.match(html, /Redis keeps nothing over a restart/);
  const st = await a.call('/api/v1/admin/status', { cookie: alice });
  assert.deepEqual([st.data.auditRedis, st.data.persistence.aof, st.data.warnings], [true, false, ['no_persistence']]);
  // Secrets: one for bob (opened), one anyone (open).
  const one = await a.call('/api/v1/share', { cookie: alice, body: { secret: PLAIN, ttl: 600, recipients: ['bob@example.com'], comment: 'reset a user pw' } });
  await a.call('/api/v1/share', { cookie: alice, body: { secret: 'other', ttl: 600 } });
  await a.call('/api/v1/open', { cookie: bob, body: { link: one.data.shareUrl } });
  const list = await a.call('/api/v1/admin/secrets', { cookie: alice });
  assert.equal(list.data.count, 2);
  const s = list.data.secrets.find((/** @type {any} */ x) => x.comment === 'reset a user pw');
  assert.deepEqual([s.status, s.recipients, s.creator.user, s.views[0].by, s.views[0].via], ['opened', ['bob@example.com'], 'alice@example.com', 'bob@example.com', 'api']);
  for (const bad of [PLAIN, 'other', one.data.id, one.data.shareUrl.split('#')[1]]) assert.ok(!list.text.includes(bad), 'no content, id or key');
  assert.equal((await a.call('/api/v1/admin/secrets?status=opened', { cookie: alice })).data.count, 1);
  assert.equal((await a.call('/api/v1/admin/secrets?status=nope', { cookie: alice })).data.error, 'invalid_status');
  assert.ok((await a.events()).some((e) => e.type === 'admin.secrets_viewed'));
  // Without the audit stream in Redis: no secrets tab, a warning.
  const b = await adminApp({ AUDIT_LOG_REDIS: 'false' });
  const c2 = await b.login(ALICE);
  const h2 = await (await fetch(`${b.base}/admin`, { headers: { Cookie: c2 } })).text();
  assert.doesNotMatch(h2, /tab=secrets/);
  assert.match(h2, /AUDIT_LOG_REDIS=false/);
  assert.equal((await b.call('/api/v1/admin/secrets', { cookie: c2 })).data.error, 'endpoint_disabled');
  // ADMIN_UI=false: no admin pages, no admin API.
  const off = await startApp({ ADMIN_UI: 'false' });
  const c3 = await off.login(ALICE);
  assert.equal((await fetch(`${off.base}/admin`, { headers: { Cookie: c3 } })).status, 404);
  assert.equal((await off.call('/api/v1/admin/status', { cookie: c3 })).data.error, 'endpoint_disabled');
});

test('technical users: create, tokens act as the technical user, disable/delete revoke, rotate with grace', opts, async () => {
  const a = await adminApp();
  const alice = await a.login(ALICE);
  /** @param {string} path @param {any} body */
  const admin = (path, body) => a.call(`/api/v1/admin/service-accounts${path}`, { cookie: alice, body });
  assert.equal((await admin('', { name: 'API AAP' })).data.error, 'invalid_name');
  const c = await admin('', { name: 'api_aap', description: 'password resets', responsible: 'alice@example.com', ips: ['127.0.0.1/32'] });
  assert.equal(c.status, 201);
  assert.equal((await admin('', { name: 'api_aap' })).status, 409);
  const issued = await admin('/api_aap/tokens', { name: 'prod', scopes: ['create'], expires: '30d' });
  assert.equal(issued.status, 201);
  assert.deepEqual([issued.data.kind, issued.data.service, issued.data.ips], ['service', 'api_aap', ['127.0.0.1/32']], 'the default networks');
  const tok = issued.data.token;
  const shared = await a.call('/api/v1/share', { bearer: tok, headers: { 'X-Audit-Comment': 'reset a user pw', 'X-Run-Id': 'svc-run' }, body: { secret: PLAIN, ttl: 600 } });
  assert.equal(shared.status, 201);
  const created = (await a.events()).find((e) => e.type === 'secret.created' && e.runId === 'svc-run');
  assert.deepEqual([created?.actor.type, created?.actor.user, created?.actor.name, created?.actor.token], ['service_account', 'svc:api_aap', 'api_aap', 'prod']);
  // With "status" it sees and burns its own secrets (STATUS_ACCESS=signed-in).
  const st = (await admin('/api_aap/tokens', { name: 'status', scopes: ['create', 'status'] })).data.token;
  const own = await a.call('/api/v1/share', { bearer: st, body: { secret: 'x', ttl: 600 } });
  assert.equal((await a.call(`/api/v1/receipts/${own.data.receiptId}`, { bearer: st })).status, 200);
  assert.equal((await a.call(`/api/v1/receipts/${own.data.receiptId}/burn`, { bearer: st, body: {} })).status, 200);
  assert.equal((await a.call(`/api/v1/receipts/${shared.data.receiptId}`, { bearer: (await a.call('/api/v1/tokens', { cookie: alice, body: { name: 'other', scopes: ['status'] } })).data.token })).status, 403, 'not for others');
  // A technical user cannot sign in, has no session and cannot manage tokens.
  assert.equal((await a.call('/api/v1/tokens', { bearer: tok })).status, 403);
  // Rotate with grace: both work for now; the old one expires later.
  const rot = await admin(`/api_aap/tokens/${issued.data.id}/rotate`, { graceSeconds: 3600 });
  assert.equal(rot.status, 201);
  assert.equal(rot.data.replaced.id, issued.data.id);
  assert.equal((await a.call('/api/v1/share', { bearer: tok, body: { secret: 'x', ttl: 600 } })).status, 201);
  assert.equal((await a.call('/api/v1/share', { bearer: rot.data.token, body: { secret: 'x', ttl: 600 } })).status, 201);
  // Rotate without grace: the old one stops at once.
  const rot2 = await admin(`/api_aap/tokens/${rot.data.id}/rotate`, {});
  assert.equal((await a.call('/api/v1/share', { bearer: rot.data.token, body: { secret: 'x', ttl: 600 } })).data.error, 'invalid_token');
  // Disable: all tokens revoked; enable does not bring them back.
  const dis = await admin('/api_aap', { enabled: false });
  assert.ok(dis.data.revoked.length >= 2);
  assert.equal((await a.call('/api/v1/share', { bearer: rot2.data.token, body: { secret: 'x', ttl: 600 } })).status, 401);
  assert.equal((await admin('/api_aap/tokens', { name: 'x' })).data.error, 'disabled');
  await admin('/api_aap', { enabled: true });
  const t3 = (await admin('/api_aap/tokens', { name: 'again', scopes: ['read'] })).data;
  const del = await admin('/api_aap/delete', {});
  assert.deepEqual(del.data.revoked.map((/** @type {any} */ x) => x.id), [t3.id]);
  assert.equal((await a.call('/api/v1/admin/service-accounts', { cookie: alice })).data.services.length, 0);
  const types = (await a.events()).map((e) => e.type);
  for (const t of ['admin.service_created', 'admin.service_token_issued', 'admin.service_token_rotated', 'admin.service_changed', 'admin.service_deleted']) assert.ok(types.includes(t), t);
});

test('admin API with an admin token: IP binding, comment, max expiry, no admin from admin; non-admin tokens get 403 everywhere', opts, async () => {
  const a = await adminApp();
  const alice = await a.login(ALICE);
  const bob = await a.login(BOB);
  /** @param {string} path @param {any} body */
  const admin = (path, body) => a.call(`/api/v1/admin/service-accounts${path}`, { cookie: alice, body });
  await admin('', { name: 'ops', description: 'automation' });
  await admin('', { name: 'pusher' });
  assert.equal((await admin('/ops/tokens', { name: 'adm', scopes: ['admin'] })).data.error, 'ips_required', 'admin tokens need networks');
  assert.equal((await admin('/ops/tokens', { name: 'adm', scopes: ['admin'], ips: ['127.0.0.1'], expires: 'never' })).data.error, 'invalid_expiry', 'API_ADMIN_TOKEN_MAX_EXPIRY (90d)');
  const adm = (await admin('/ops/tokens', { name: 'adm', scopes: ['admin'], ips: ['203.0.113.0/24'], expires: '30d' })).data.token;
  const svcPlain = (await admin('/pusher/tokens', { name: 'p', scopes: ['create', 'read', 'status'] })).data.token;
  const personal = (await a.call('/api/v1/tokens', { cookie: bob, body: { name: 'mine', scopes: ['create', 'read', 'status'] } })).data.token;
  const from = { 'X-Forwarded-For': '203.0.113.7' };
  // With comment and from its network: the admin API works.
  const q = await a.call('/api/v1/admin/audit?type=admin.', { bearer: adm, headers: { ...from, 'X-Audit-Comment': 'nightly export', 'X-Run-Id': 'adm-1' } });
  assert.equal(q.status, 200, q.text);
  // Without a comment: refused (API_ADMIN_COMMENT=required).
  assert.equal((await a.call('/api/v1/admin/status', { bearer: adm, headers: from })).data.error, 'comment_required');
  // From another address: refused and logged.
  const wrong = await a.call('/api/v1/admin/status', { bearer: adm, headers: { 'X-Forwarded-For': '198.51.100.1', 'X-Audit-Comment': 'x' } });
  assert.deepEqual([wrong.status, wrong.data.error], [403, 'ip_not_allowed']);
  // An admin token may not issue admin tokens (API_ADMIN_TOKEN_CAN_ISSUE_ADMIN=false) ...
  const h = { ...from, 'X-Audit-Comment': 'issue' };
  const deny = await a.call('/api/v1/admin/service-accounts/pusher/tokens', { bearer: adm, headers: h, body: { name: 'x', scopes: ['admin'], ips: ['203.0.113.0/24'] } });
  assert.equal(deny.data.error, 'admin_scope_not_allowed');
  // ... but other tokens, and every admin function: technical users, policies, tokens.
  assert.equal((await a.call('/api/v1/admin/service-accounts/pusher/tokens', { bearer: adm, headers: h, body: { name: 'x', scopes: ['read'] } })).status, 201);
  assert.equal((await a.call('/api/v1/admin/token-policies', { bearer: adm, headers: h, body: { type: 'user', subject: 'bob@example.com', scopes: ['read'] } })).status, 200);
  assert.equal((await a.call('/api/v1/admin/tokens', { bearer: adm, headers: h })).status, 200);
  const logged = (await a.events()).find((e) => e.type === 'admin.token_policy_changed');
  assert.deepEqual([logged?.actor.type, logged?.actor.user, logged?.actor.token, logged?.comment], ['service_account', 'svc:ops', 'adm', 'issue']);
  // Every admin route refuses personal tokens, technical users without "admin" and non-admin sessions.
  const routes = [
    ['GET', '/api/v1/admin/status'], ['GET', '/api/v1/admin/audit'], ['GET', '/api/v1/admin/audit/verify'], ['GET', '/api/v1/admin/secrets'],
    ['GET', '/api/v1/admin/tokens'], ['POST', '/api/v1/admin/tokens/0123456789abcdef/revoke'], ['GET', '/api/v1/admin/token-policies'], ['POST', '/api/v1/admin/token-policies'],
    ['GET', '/api/v1/admin/service-accounts'], ['POST', '/api/v1/admin/service-accounts'], ['POST', '/api/v1/admin/service-accounts/ops'], ['POST', '/api/v1/admin/service-accounts/ops/delete'],
    ['GET', '/api/v1/admin/service-accounts/ops/tokens'], ['POST', '/api/v1/admin/service-accounts/ops/tokens'], ['POST', '/api/v1/admin/service-accounts/ops/tokens/0123456789abcdef/rotate'],
  ];
  for (const [method, path] of routes) {
    for (const [who, auth] of /** @type {const} */ ([['personal token', { bearer: personal }], ['technical user without admin', { bearer: svcPlain }], ['non-admin session', { cookie: bob }]])) {
      const r = await a.call(path, { ...auth, method, headers: { 'X-Audit-Comment': 'probe' }, ...(method === 'POST' ? { body: { type: 'user', subject: 'x@example.com', name: 'zz' } } : {}) });
      assert.equal(r.status, 403, `${who}: ${method} ${path} -> ${r.status} ${r.text.slice(0, 80)}`);
    }
  }
  assert.ok((await a.events()).some((e) => e.type === 'api.scope_denied' && e.reason === 'personal_token'));
  // API_ADMIN_TOKENS=false: the scope cannot be given, existing admin tokens lose it.
  const noAdm = await adminApp({ API_ADMIN_TOKENS: 'false', REDIS_PREFIX: a.store.p });
  const c4 = await noAdm.login(ALICE);
  assert.equal((await noAdm.call('/api/v1/admin/service-accounts/pusher/tokens', { cookie: c4, body: { name: 'y', scopes: ['admin'], ips: ['127.0.0.1'] } })).data.error, 'scope_not_allowed');
  assert.equal((await noAdm.call('/api/v1/admin/status', { bearer: adm, headers: { ...from, 'X-Audit-Comment': 'x' } })).status, 403);
});

test('admin and technical user settings are checked at start', () => {
  const base = { BASE_URL: 'https://ots.example.com', AUTH_PROVIDER: 'entra', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT, ENTRA_CLIENT_SECRET: SECRET, AUTH_SECRET: 'x'.repeat(40) };
  assert.throws(() => loadConfig({ ...base, API_ADMIN_TOKENS: 'true' }), /needs API_TOKENS=true/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_ADMIN_TOKENS: 'true' }), /API_ADMIN_TOKENS needs/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', ADMIN_USERS: 'a@example.com', API_SERVICE_ACCOUNTS: 'false', API_ADMIN_TOKENS: 'true' }), /API_SERVICE_ACCOUNTS=true/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', ADMIN_USERS: 'a@example.com', API_ADMIN_TOKENS: 'true', API_ADMIN_TOKEN_MAX_EXPIRY: '5x' }), /API_ADMIN_TOKEN_MAX_EXPIRY/);
  assert.throws(() => loadConfig({ ...base, API_TOKENS: 'true', API_ADMIN_COMMENT: 'maybe' }), /API_ADMIN_COMMENT/);
  const t = loadConfig({ ...base, API_TOKENS: 'true', ADMIN_USERS: 'a@example.com' }).auth?.tokens;
  assert.deepEqual([t?.services, t?.adminTokens], [true, { enabled: false, requireIp: true, maxExpiry: '90d', canIssueAdmin: false, comment: 'required' }]);
  assert.equal(loadConfig({ ...base, API_TOKENS: 'true' }).auth?.tokens?.services, false, 'no admins: no technical users');
});

test('API_TOKEN_REQUIRED: scripts need a token, the pages keep working; API_TOKEN_USERS limits who makes tokens', opts, async () => {
  const a = await startApp({ API_TOKEN_REQUIRED: 'true', API_TOKEN_USERS: 'alice@example.com', AUTH_CREATE: 'signed-in' });
  const alice = await a.login(ALICE);
  const bob = await a.login(BOB);
  const body = { secret: PLAIN, ttl: 600 };
  // A script with a session cookie or nothing: refused.
  assert.equal((await a.call('/api/v1/share', { body })).data.error, 'token_required');
  assert.equal((await a.call('/api/v1/share', { cookie: alice, body })).data.error, 'token_required');
  // Other bearer tokens (AUTH_API_AUDIENCE) neither.
  assert.equal((await a.call('/api/v1/share', { bearer: 'eyJhbGciOi.x.y', body })).data.error, 'token_required');
  // The page (same-origin fetch) still works.
  const { payload } = await encryptSecret(PLAIN);
  const page = await a.call('/api/v1/secrets', { cookie: alice, headers: { 'Sec-Fetch-Site': 'same-origin' }, body: { ...payload, ttl: 600 } });
  assert.equal(page.status, 201, page.text);
  // Tokens are managed on the page only. Bob may not make tokens; Alice may.
  const same = { 'Sec-Fetch-Site': 'same-origin' };
  assert.equal((await a.call('/api/v1/tokens', { cookie: alice, body: { name: 'b' } })).data.error, 'token_required');
  assert.equal((await a.call('/api/v1/tokens', { cookie: bob, headers: same, body: { name: 'b' } })).data.error, 'tokens_not_allowed');
  assert.equal((await a.call('/api/v1/tokens', { cookie: bob, headers: same })).data.mayCreate, false);
  const html = await (await fetch(`${a.base}/settings/tokens`, { headers: { Cookie: alice } })).text();
  assert.match(html, /id="token-form"/);
  const t = (await a.call('/api/v1/tokens', { cookie: alice, headers: same, body: { name: 'cli' } })).data.token;
  assert.equal((await a.call('/api/v1/share', { bearer: t, body })).status, 201);
  const ev = await a.events();
  assert.ok(ev.some((e) => e.type === 'api.denied' && e.reason === 'token_required'));
  assert.ok(ev.some((e) => e.type === 'api.token_create_denied' && e.actor.user === 'bob@example.com'));
});

test('comments: off, optional, required; API_TOKEN_COMMENT=required; shown on the status page', opts, async () => {
  const req = await startApp({ AUDIT_COMMENT: 'required', API_TOKEN_COMMENT: 'required' });
  const cookie = await req.login(ALICE);
  const { payload } = await encryptSecret(PLAIN);
  const none = await req.call('/api/v1/secrets', { cookie, body: { ...payload, ttl: 600 } });
  assert.equal(none.data.error, 'comment_required');
  const ok = await req.call('/api/v1/secrets', { cookie, body: { ...payload, ttl: 600, comment: ' reset\n a user pw ' } });
  assert.equal(ok.status, 201);
  assert.equal(ok.data.comment, 'reset a user pw');
  assert.equal((await req.call(`/api/v1/receipts/${ok.data.receiptId}`, { cookie })).data.comment, 'reset a user pw');
  const home = await (await fetch(req.base, { headers: { Cookie: cookie } })).text();
  assert.match(home, /id="comment"[^>]*data-required="1"/);
  const t = (await req.call('/api/v1/tokens', { cookie, body: { name: 'x' } })).data.token;
  assert.equal((await req.call('/api/v1/share', { bearer: t, body: { secret: 'x', ttl: 600 } })).data.error, 'comment_required');
  assert.ok((await req.events()).some((e) => e.type === 'api.token_used' && e.reason === 'comment_required'), 'refused token call logged');
  // Percent-encoded UTF-8 in the header.
  const enc = await req.call('/api/v1/share', { bearer: t, headers: { 'X-Audit-Comment': encodeURIComponent('Passwort zurücksetzen') }, body: { secret: 'x', ttl: 600 } });
  assert.equal(enc.data.comment, 'Passwort zurücksetzen');

  const off = await startApp({ AUDIT_COMMENT: 'off' });
  const c2 = await off.login(ALICE);
  assert.equal((await off.call('/api/v1/secrets', { cookie: c2, body: { ...payload, ttl: 600, comment: 'x' } })).data.error, 'comment_disabled');
  assert.doesNotMatch(await (await fetch(off.base, { headers: { Cookie: c2 } })).text(), /id="comment"/);
});

test('admin view: only admins, filters, CSV and JSON lines export, chain check; every look logged', opts, async () => {
  const a = await startApp();
  const alice = await a.login(ALICE);
  const bob = await a.login(BOB);
  await a.call('/api/v1/share', { cookie: bob, headers: { 'X-Run-Id': 'r-1' }, body: { secret: PLAIN, ttl: 600, comment: '=cmd|calc' } });
  assert.equal((await a.call('/api/v1/admin/audit', { cookie: bob })).status, 403);
  assert.equal((await fetch(`${a.base}/admin`, { headers: { Cookie: bob } })).status, 403);
  const page = await fetch(`${a.base}/admin`, { headers: { Cookie: alice } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /id="audit-filter"/);
  const q = await a.call('/api/v1/admin/audit?type=secret.created&actor=bob', { cookie: alice });
  assert.equal(q.status, 200);
  assert.equal(q.data.source, 'redis');
  assert.equal(q.data.count, 1);
  assert.equal(q.data.events[0].runId, 'r-1');
  assert.equal((await a.call('/api/v1/admin/audit?runId=nope', { cookie: alice })).data.count, 0);
  assert.equal((await a.call('/api/v1/admin/audit?from=yesterday', { cookie: alice })).data.error, 'invalid_time');
  const csv = await a.call('/api/v1/admin/audit?format=csv&type=secret.', { cookie: alice });
  assert.match(String(csv.headers.get('content-type')), /text\/csv/);
  assert.match(csv.text, /^ts,type,outcome/);
  assert.match(csv.text, /"'=cmd\|calc"/, 'formula escaped');
  const jl = await a.call('/api/v1/admin/audit?format=jsonl', { cookie: alice });
  for (const l of jl.text.trim().split('\n')) JSON.parse(l);
  const v = await a.call('/api/v1/admin/audit/verify', { cookie: alice });
  assert.equal(v.data.ok, true);
  const ev = await a.events();
  assert.ok(ev.some((e) => e.type === 'admin.audit_viewed' && e.actor.user === 'alice@example.com'));
  assert.ok(ev.some((e) => e.type === 'admin.audit_exported'));
  assert.ok(ev.some((e) => e.type === 'admin.denied' && e.actor.user === 'bob@example.com'));
  // The menu links.
  const menu = await (await fetch(a.base, { headers: { Cookie: alice } })).text();
  assert.match(menu, /href="\/settings\/tokens"/);
  assert.match(menu, /href="\/admin"/);
  assert.doesNotMatch(await (await fetch(a.base, { headers: { Cookie: bob } })).text(), /href="\/admin"/);
});

test('AUDIT_LOG_FAIL=closed: no secret, no reveal and no token without its event', opts, async () => {
  const a = await startApp({ AUDIT_LOG_REDIS: 'false' });
  const cookie = await a.login(ALICE);
  const s = await a.call('/api/v1/share', { cookie, body: { secret: PLAIN, ttl: 600 } });
  assert.equal(s.status, 201);
  // The file breaks.
  const audit = /** @type {Audit} */ (a.audit);
  closeSync(/** @type {number} */ (audit.fd));
  audit.fd = 2 ** 30;
  const before = (await a.store.redis.keys(`${a.store.p}s:*`)).length;
  const r = await a.call('/api/v1/share', { cookie, body: { secret: PLAIN, ttl: 600 } });
  assert.equal(r.status, 503);
  assert.equal(r.data.error, 'audit_unavailable');
  assert.equal((await a.store.redis.keys(`${a.store.p}s:*`)).length, before, 'the secret was removed again');
  // While the log fails (10 s): refused before anything is used up.
  const open = await a.call('/api/v1/open', { cookie, body: { link: s.data.shareUrl } });
  assert.equal(open.status, 503);
  assert.ok((await a.store.redis.exists(`${a.store.p}s:${s.data.id}`)) === 1, 'no view used');
  assert.equal((await a.call('/api/v1/tokens', { cookie, body: { name: 'x' } })).status, 503);
  audit.fd = null;
  // fail open: goes on, only logged to stderr.
  const o = await startApp({ AUDIT_LOG_REDIS: 'false', AUDIT_LOG_FAIL: 'open' });
  const c2 = await o.login(ALICE);
  const oa = /** @type {Audit} */ (o.audit);
  closeSync(/** @type {number} */ (oa.fd));
  oa.fd = 2 ** 30;
  assert.equal((await o.call('/api/v1/share', { cookie: c2, body: { secret: PLAIN, ttl: 600 } })).status, 201);
  oa.fd = null;
});

test('everything off: no run id header, no token or admin endpoints, no comment field', opts, async () => {
  const a = await startApp({}, { noAudit: true });
  const cookie = await a.login(ALICE);
  const r = await a.call('/api/v1/share', { cookie, headers: { 'X-Run-Id': 'abc' }, body: { secret: PLAIN, ttl: 600 } });
  assert.equal(r.status, 201);
  assert.equal(r.headers.get('x-run-id'), null);
  assert.equal((await a.call('/api/v1/tokens', { cookie })).data.error, 'endpoint_disabled');
  assert.equal((await a.call('/api/v1/admin/audit', { cookie })).data.error, 'endpoint_disabled');
  assert.equal((await fetch(`${a.base}/settings/tokens`, { headers: { Cookie: cookie } })).status, 404);
  assert.equal((await fetch(`${a.base}/admin`, { headers: { Cookie: cookie } })).status, 404);
  const home = await (await fetch(a.base, { headers: { Cookie: cookie } })).text();
  assert.doesNotMatch(home, /id="comment"|settings\/tokens|href="\/admin"/);
  const spec = await a.call('/api/openapi.json');
  assert.ok(!spec.data.paths['/v1/tokens'] && !spec.data.paths['/v1/admin/audit']);
  // A vnly_ token without API_TOKENS is just an unknown bearer: anonymous.
  assert.equal((await a.call('/api/v1/me', { bearer: `vnly_${'0'.repeat(16)}_${'A'.repeat(43)}` })).data.signedIn, false);
});
