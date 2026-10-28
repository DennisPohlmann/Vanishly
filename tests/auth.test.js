// Sign-in tests (AUTH_PROVIDER=entra/oidc) against a real Redis and the
// provider stand-in in oidc-mock.js.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';
import { encryptSecret, unlockKey, verifierFor, decryptSecret } from '../public/js/vanishly-crypto.js';
import { startMock } from './oidc-mock.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };
const TENANT = '11111111-2222-3333-4444-555555555555';
const OTHER_TENANT = '99999999-2222-3333-4444-555555555555';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const SECRET = 'client-secret-for-tests';
const IT = '0f0f0f0f-1111-2222-3333-444444444444';
const HR = '0e0e0e0e-1111-2222-3333-444444444444';
const ALICE = { oid: '00000000-0000-0000-0000-00000000000a', tid: TENANT, name: 'Alice Example', preferred_username: 'alice@example.com' };
const BOB = { oid: '00000000-0000-0000-0000-00000000000b', tid: TENANT, name: 'Bob Example', preferred_username: 'Bob@Example.com' };
const CAROL = { oid: '00000000-0000-0000-0000-00000000000c', tid: TENANT, name: 'Carol', preferred_username: 'carol@example.com' };

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
 * An app with sign-in on; BASE_URL is its own address.
 * @param {Record<string, string>} env
 */
async function startApp(env = {}) {
  /** @type {any} */ let handler = null;
  const server = createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(undefined)));
  const base = `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `authtest${process.pid}-${n++}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ACCESS_LOG: 'false',
    PASSPHRASE_ATTEMPTS: '2',
    BASE_URL: base,
    AUTH_PROVIDER: 'entra',
    ENTRA_TENANT_ID: TENANT,
    ENTRA_CLIENT_ID: CLIENT,
    ENTRA_CLIENT_SECRET: SECRET,
    ENTRA_AUTHORITY: mock.base,
    ENTRA_GRAPH_URL: mock.base,
    AUTH_SECRET: 'x'.repeat(40),
    ...env,
  });
  const store = await Store.connect(redisUrl, config);
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
  handler = app;
  closers.push(async () => {
    server.close();
    await store.close();
  });
  /**
   * @param {string} path
   * @param {{ body?: any, cookie?: string, bearer?: string, headers?: Record<string, string> }} [o]
   */
  const call = async (path, o = {}) => {
    const res = await fetch(base + path, {
      method: o.body === undefined ? 'GET' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(o.cookie ? { Cookie: o.cookie } : {}),
        ...(o.bearer ? { Authorization: `Bearer ${o.bearer}` } : {}),
        ...o.headers,
      },
      body: o.body === undefined ? undefined : JSON.stringify(o.body),
      redirect: 'manual',
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: res.status, data, headers: res.headers };
  };
  /**
   * Signs in like a browser: /auth/login -> provider -> /auth/callback.
   * @param {Record<string, any>} claims
   * @param {string} [returnTo]
   */
  const login = async (claims, returnTo = '/') => {
    mock.user = claims;
    const start = await fetch(`${base}/auth/login?return=${encodeURIComponent(returnTo)}`, { redirect: 'manual' });
    assert.equal(start.status, 303);
    const atProvider = await fetch(String(start.headers.get('location')), { redirect: 'manual' });
    const callback = String(atProvider.headers.get('location'));
    assert.ok(callback.startsWith(`${base}/auth/callback?`));
    const done = await fetch(callback, { redirect: 'manual' });
    const cookie = String(done.headers.get('set-cookie') || '').split(';')[0];
    return { status: done.status, location: done.headers.get('location'), cookie, callback };
  };
  return { base, call, login, config };
}

/** @param {any} call @param {string} cookie @param {any} extra */
async function create(call, cookie, extra = {}, secret = 'for the chosen ones', pass = '') {
  const { key, payload } = await encryptSecret(secret, pass);
  const r = await call('/api/v1/secrets', { cookie, body: { ...payload, ttl: 600, ...extra } });
  return { ...r, key };
}

test('sign-in off: recipients are refused, nothing else changes', opts, async () => {
  const config = loadConfig({ REDIS_URL: redisUrl, REDIS_PREFIX: `authoff${process.pid}:`, ACCESS_LOG: 'false' });
  assert.equal(config.auth, null);
  const store = await Store.connect(redisUrl, config);
  const server = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' }).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  closers.push(async () => {
    server.close();
    await store.close();
  });
  const base = `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
  const { payload } = await encryptSecret('x');
  const post = (/** @type {any} */ b) =>
    fetch(`${base}/api/v1/secrets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
  const r = await post({ ...payload, recipients: ['a@example.com'] });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, 'recipients_disabled');
  assert.equal((await post({ ...payload, recipients: [] })).status, 201);
  const home = await (await fetch(base)).text();
  assert.doesNotMatch(home, /auth\/login|recipients-wrap/);
  assert.equal((await fetch(`${base}/auth/login`, { redirect: 'manual' })).status, 404);
});

test('login: state, nonce and PKCE; creators must sign in', opts, async () => {
  const { call, login, base } = await startApp();
  // Not signed in: the home page asks for a sign-in, the API refuses.
  const home = await call('/');
  assert.equal(home.status, 200);
  assert.match(home.data, /href="\/auth\/login\?return=\/"/);
  assert.doesNotMatch(home.data, /create-form/);
  const { payload } = await encryptSecret('x');
  const anon = await call('/api/v1/secrets', { body: { ...payload } });
  assert.equal(anon.status, 401);
  assert.equal(anon.data.error, 'login_required');

  const a = await login(ALICE, '/');
  assert.equal(a.status, 303);
  assert.equal(a.location, '/');
  assert.match(a.cookie, /^vanishly-session=[A-Za-z0-9_-]{43}$/);
  const q = /** @type {URLSearchParams} */ (mock.lastAuthorize);
  assert.equal(q.get('redirect_uri'), `${base}/auth/callback`);
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.ok(q.get('nonce') && q.get('state'));
  // The state works once.
  const again = await fetch(a.callback, { redirect: 'manual' });
  assert.equal(again.status, 400);
  // Unknown state, provider error, open redirect.
  assert.equal((await call('/auth/callback?code=x&state=AAAAAAAAAAAAAAAAAAAAAA')).status, 400);
  assert.equal((await call('/auth/callback?error=access_denied&state=x')).status, 400);
  const evil = await login(ALICE, 'https://evil.example.com/');
  assert.equal(evil.location, '/');

  const me = await call('/api/v1/me', { cookie: a.cookie });
  assert.deepEqual(me.data, { signedIn: true, name: 'Alice Example', user: 'alice@example.com', app: false });
  const signedHome = await call('/', { cookie: a.cookie });
  assert.match(signedHome.data, /recipients-wrap/);
  assert.match(signedHome.data, /Alice Example/);
  const c = await create(call, a.cookie);
  assert.equal(c.status, 201);
  assert.equal(c.data.restricted, false);

  // Sign out ends the session in Redis too.
  const out = await call('/auth/logout', { cookie: a.cookie, body: {} });
  assert.equal(out.status, 303);
  assert.equal((await call('/api/v1/me', { cookie: a.cookie })).data.signedIn, false);
});

test('only a signed-in recipient gets the ciphertext; others use no view', opts, async () => {
  const { call, login } = await startApp({ RECEIPT_SHOW_VIEWER: 'true' });
  const alice = (await login(ALICE)).cookie;
  const bob = (await login(BOB)).cookie;
  const c = await create(call, alice, { recipients: ['bob@example.COM'], views: 2 });
  assert.equal(c.status, 201);
  assert.equal(c.data.restricted, true);
  const id = c.data.id;

  // Not signed in / not a recipient: refused, nothing counted.
  const anon = await call(`/api/v1/secrets/${id}/reveal`, { body: {} });
  assert.equal(anon.status, 401);
  assert.equal(anon.data.error, 'login_required');
  const wrong = await call(`/api/v1/secrets/${id}/reveal`, { cookie: alice, body: {} });
  assert.equal(wrong.status, 403);
  assert.equal(wrong.data.error, 'not_recipient');
  // The status (salt, views) only for a recipient, the list never.
  assert.equal((await call(`/api/v1/secrets/${id}`)).status, 401);
  assert.equal((await call(`/api/v1/secrets/${id}`, { cookie: alice })).data.error, 'not_recipient');
  const meta = await call(`/api/v1/secrets/${id}`, { cookie: bob });
  assert.equal(meta.data.viewsLeft, 2);
  assert.equal(meta.data.restricted, true);
  assert.equal(JSON.stringify(meta.data).includes('bob'), false);
  // /v1/open without a session or as somebody else: refused too.
  const link = `http://x/s/${id}#${c.key}`;
  assert.equal((await call('/api/v1/open', { body: { link } })).data.error, 'login_required');
  assert.equal((await call('/api/v1/open', { cookie: alice, body: { link } })).data.error, 'not_recipient');
  // The receipt shows the state and the number of recipients, not who.
  const r0 = await call(`/api/v1/receipts/${c.data.receiptId}`);
  assert.equal(r0.data.viewsLeft, 2);
  assert.equal(JSON.stringify(r0.data).includes('bob'), false);

  // The page tells, without using a view.
  assert.match((await call(`/s/${id}`)).data, /data-locked="login"/);
  const denied = (await call(`/s/${id}`, { cookie: alice })).data;
  assert.match(denied, /data-locked="denied"/);
  assert.doesNotMatch(denied, /2 more time/); // no view count for others
  assert.match(denied, /alice@example\.com/);
  assert.match((await call(`/s/${id}`, { cookie: bob })).data, /data-locked=""/);

  // Bob (case of the address does not matter) opens it.
  const ok = await call(`/api/v1/secrets/${id}/reveal`, { cookie: bob, body: {} });
  assert.equal(ok.status, 200);
  assert.equal(await decryptSecret(ok.data, c.key), 'for the chosen ones');
  const receipt = await call(`/api/v1/receipts/${c.data.receiptId}`);
  assert.equal(receipt.data.recipients, 1);
  assert.deepEqual(receipt.data.viewedBy, ['Bob Example']);

  // A cross-site request does not carry the session (CSRF).
  const csrf = await call(`/api/v1/secrets/${id}/reveal`, { cookie: bob, body: {}, headers: { 'Sec-Fetch-Site': 'cross-site' } });
  assert.equal(csrf.status, 401);
  const csrf2 = await call(`/api/v1/secrets/${id}/reveal`, { cookie: bob, body: {}, headers: { Origin: 'https://evil.example.com' } });
  assert.equal(csrf2.status, 401);
});

/**
 * Reveals like the page does with ENABLE_SECRET_META_API=false: salt and
 * iterations from the /s/:id page data, then POST reveal.
 * @param {any} call @param {string} id @param {string} key @param {string} pass @param {string} [cookie]
 */
async function revealLikePage(call, id, key, pass, cookie) {
  const html = String((await call(`/s/${id}`, { cookie })).data);
  const salt = /data-salt="([^"]*)"/.exec(html)?.[1] || '';
  const iterations = Number(/data-iterations="([^"]*)"/.exec(html)?.[1] || 0);
  /** @type {Uint8Array | undefined} */ let pk;
  /** @type {Record<string, string>} */ const body = {};
  if (pass) {
    pk = await unlockKey(pass, { salt, iterations });
    body.verifier = await verifierFor(pk, { salt });
  }
  const r = await call(`/api/v1/secrets/${id}/reveal`, { cookie, body });
  return { html, salt, status: r.status, data: r.data, text: r.status === 200 ? await decryptSecret(r.data, key, pk) : null };
}

test('ENABLE_SECRET_META_API=false: restricted secrets reveal from the page data, only for recipients', opts, async () => {
  const { call, login } = await startApp({ ENABLE_SECRET_META_API: 'false' });
  const alice = (await login(ALICE)).cookie;
  const bob = (await login(BOB)).cookie;
  const c = await create(call, alice, { recipients: ['bob@example.com'] }, 'for bob', 'Pass phrase 1');
  assert.equal(c.status, 201);
  assert.equal((await call(`/api/v1/secrets/${c.data.id}`, { cookie: bob })).status, 404);
  // Others get no salt in the page and no secret.
  const other = await revealLikePage(call, c.data.id, c.key, '', alice);
  assert.equal(other.salt, '');
  assert.match(other.html, /data-locked="denied"/);
  assert.equal(other.status, 403);
  // The recipient: salt from the page, the right passphrase opens it.
  const r = await revealLikePage(call, c.data.id, c.key, 'Pass phrase 1', bob);
  assert.notEqual(r.salt, '');
  assert.equal(r.text, 'for bob');
});

test('REQUIRE_PASSPHRASE=unless-recipients: a passphrase only for secrets without recipients', opts, async () => {
  const { call, login, base } = await startApp({ REQUIRE_PASSPHRASE: 'unless-recipients' });
  const alice = (await login(ALICE)).cookie;
  const none = await create(call, alice);
  assert.equal(none.status, 400);
  assert.equal(none.data.error, 'passphrase_required');
  assert.equal(none.data.message, 'A passphrase is required when no recipients are given');
  assert.equal((await create(call, alice, {}, 'with pass', 'Pass phrase 1')).status, 201);
  assert.equal((await create(call, alice, { recipients: ['bob@example.com'] })).status, 201);
  assert.equal((await create(call, alice, { recipientGroups: [] })).status, 400);
  const share = await call('/api/v1/share', { cookie: alice, body: { secret: 'x' } });
  assert.equal(share.data.message, 'A passphrase is required when no recipients are given');
  assert.equal((await call('/api/v1/share', { cookie: alice, body: { secret: 'x', recipients: ['bob@example.com'] } })).status, 201);
  const cfg = await call('/api/v1/config');
  assert.deepEqual([cfg.data.requirePassphrase, cfg.data.passphraseRule], [false, 'unless-recipients']);
  // The form: required until a recipient is chosen (the page script switches it).
  const html = String((await call('/', { cookie: alice })).data);
  assert.match(html, /data-pass-required="unless-recipients"/);
  assert.match(html, /<label for="passphrase" id="passphrase-label" data-required="Passphrase \(required\)" data-optional="Passphrase \(optional\)">Passphrase \(required\)<\/label>/);
  assert.ok(base);
});

test('a non-recipient cannot burn a restricted secret with wrong passphrases', opts, async () => {
  const { call, login } = await startApp();
  const alice = (await login(ALICE)).cookie;
  const bob = (await login(BOB)).cookie;
  const c = await create(call, alice, { recipients: ['bob@example.com'] }, 'pp', 'right one');
  for (let i = 0; i < 4; i++) {
    const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: alice, body: { verifier: 'A'.repeat(43) } });
    assert.equal(r.data.error, 'not_recipient');
  }
  const meta = (await call(`/api/v1/secrets/${c.data.id}`, { cookie: bob })).data;
  assert.equal(meta.passphrase, true);
  const pk = await unlockKey('right one', meta);
  const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: bob, body: { verifier: await verifierFor(pk, meta) } });
  assert.equal(r.status, 200);
  assert.equal(await decryptSecret(r.data, c.key, pk), 'pp');
});

test('recipient rules: required, maximum, domains, address format', opts, async () => {
  const { call, login } = await startApp({ RECIPIENTS: 'required', RECIPIENTS_MAX: '2', RECIPIENT_DOMAINS: 'example.com' });
  const alice = (await login(ALICE)).cookie;
  assert.equal((await create(call, alice)).data.error, 'recipients_required');
  assert.equal((await create(call, alice, { recipients: ['a@example.com', 'b@example.com', 'c@example.com'] })).data.error, 'too_many_recipients');
  const dom = await create(call, alice, { recipients: ['x@other.org'] });
  assert.equal(dom.data.error, 'recipient_domain');
  assert.deepEqual(dom.data.domains, ['example.com']);
  assert.equal((await create(call, alice, { recipients: ['not an address'] })).data.error, 'invalid_recipient');
  assert.equal((await create(call, alice, { recipients: 'a@example.com' })).data.error, 'invalid_recipients');
  assert.equal((await create(call, alice, { recipientGroups: [IT] })).data.error, 'groups_disabled');
  assert.equal((await create(call, alice, { recipients: ['b@example.com'] })).status, 201);
  // /v1/share follows the same rules.
  const share = await call('/api/v1/share', { cookie: alice, body: { secret: 's', recipients: ['b@example.com'] } });
  assert.equal(share.status, 201);
  assert.equal(share.data.restricted, true);
});

test('groups from a fixed list (groups claim)', opts, async () => {
  const { call, login } = await startApp({ RECIPIENT_GROUPS: `IT Admins=${IT},HR=${HR}` });
  const alice = (await login(ALICE)).cookie;
  const carol = (await login({ ...CAROL, groups: [IT.toUpperCase(), 'f0000000-0000-0000-0000-000000000000'] })).cookie;
  const bob = (await login({ ...BOB, groups: [HR] })).cookie;
  const home = (await call('/', { cookie: alice })).data;
  assert.match(home, /<option value="0f0f0f0f-1111-2222-3333-444444444444">IT Admins<\/option>/);
  assert.equal((await call('/api/v1/config')).data.auth.groupList.length, 0); // only for signed-in users
  assert.equal((await call('/api/v1/config', { cookie: alice })).data.auth.groupList.length, 2);
  assert.equal((await create(call, alice, { recipientGroups: ['f0000000-0000-0000-0000-000000000000'] })).data.error, 'invalid_group');
  const c = await create(call, alice, { recipientGroups: [IT] });
  assert.equal(c.status, 201);
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: bob, body: {} })).data.error, 'not_recipient');
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: carol, body: {} })).status, 200);
});

test('RECIPIENT_GROUPS=*: group search and overage via Graph', opts, async () => {
  const { call, login } = await startApp({ RECIPIENT_GROUPS: '*', ENTRA_GRAPH: 'true' });
  mock.groups = [
    { id: IT, displayName: 'IT Admins' },
    { id: HR, displayName: 'HR' },
  ];
  mock.memberGroups[CAROL.oid] = [IT, 'f0000000-0000-0000-0000-000000000000'];
  const alice = (await login(ALICE)).cookie;
  assert.equal((await call('/api/v1/groups?q=it')).status, 401);
  const found = await call('/api/v1/groups?q=it', { cookie: alice });
  assert.deepEqual(found.data.groups, [{ id: IT, name: 'IT Admins' }]);
  assert.match((await call('/', { cookie: alice })).data, /id="group-search"/);
  const c = await create(call, alice, { recipientGroups: [IT] });
  assert.equal(c.status, 201);
  // Carol's token has too many groups (overage): Vanishly asks Graph.
  const before = mock.graphCalls;
  const carol = (await login({ ...CAROL, _claim_names: { groups: 'src1' } })).cookie;
  assert.ok(mock.graphCalls > before);
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: carol, body: {} })).status, 200);
});

test('RECIPIENT_USER_GROUP: people search from one group, picked person can open', opts, async () => {
  assert.throws(() => loadConfig({ AUTH_PROVIDER: 'entra', RECIPIENT_USER_GROUP: IT }), /RECIPIENT_USER_GROUP|required/);
  const { call, login } = await startApp({ RECIPIENT_USER_GROUP: IT.toUpperCase(), ENTRA_GRAPH: 'true' });
  mock.members[IT] = [
    { displayName: 'Bob Example', mail: 'bob.example@example.com', userPrincipalName: 'Bob@Example.com' },
    { displayName: 'Bobby Guest', mail: 'bobby@partner.example', userPrincipalName: 'bobby_partner.example#EXT#@example.onmicrosoft.com' },
    { displayName: 'Carol', mail: null, userPrincipalName: 'carol@example.com' },
  ];
  const alice = (await login(ALICE)).cookie;
  assert.equal((await call('/api/v1/people?q=bo')).status, 401);
  const found = await call('/api/v1/people?q=bo', { cookie: alice });
  assert.equal(found.status, 200);
  assert.deepEqual(found.data.people, [
    { name: 'Bob Example', user: 'bob@example.com', mail: 'bob.example@example.com' },
    { name: 'Bobby Guest', user: 'bobby@partner.example', mail: 'bobby@partner.example' },
  ]);
  assert.match(String(mock.lastSearch?.get('$search')), /"userPrincipalName:bo"/);
  assert.deepEqual((await call('/api/v1/people?q=b', { cookie: alice })).data.people, []);
  assert.equal((await call('/api/v1/config', { cookie: alice })).data.auth.peopleSearch, true);
  const home = (await call('/', { cookie: alice })).data;
  assert.match(home, /role="combobox"/);
  assert.match(home, /id="people-results" role="listbox"/);
  // The address from the search is the one Bob signs in with.
  const c = await create(call, alice, { recipients: [found.data.people[0].user] });
  assert.equal(c.status, 201);
  const bob = (await login(BOB)).cookie;
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: bob, body: {} })).status, 200);
  // Graph down: a clear error, no crash.
  mock.members = {};
  const graphFetch = await startApp({ RECIPIENT_USER_GROUP: IT, ENTRA_GRAPH: 'true', ENTRA_GRAPH_URL: 'http://127.0.0.1:9' });
  const a2 = (await graphFetch.login(ALICE)).cookie;
  assert.equal((await graphFetch.call('/api/v1/people?q=bo', { cookie: a2 })).data.error, 'directory_unavailable');
  // Off by default: no endpoint, plain e-mail field.
  const plain = await startApp({});
  const a3 = (await plain.login(ALICE)).cookie;
  assert.equal((await plain.call('/api/v1/people?q=bo', { cookie: a3 })).status, 404);
  assert.doesNotMatch((await plain.call('/', { cookie: a3 })).data, /role="combobox"/);
});

test('API bearer tokens: create, open; other tenants and audiences refused', opts, async () => {
  const { call, base } = await startApp({ AUTH_API_AUDIENCE: `api://${CLIENT}` });
  const aud = `api://${CLIENT}`;
  const alice = await mock.sign(ALICE, { aud });
  const bob = await mock.sign({ ...BOB, upn: 'bob@example.com', preferred_username: undefined }, { aud });
  const share = await call('/api/v1/share', { bearer: alice, body: { secret: 'via api', recipients: ['bob@example.com'] } });
  assert.equal(share.status, 201);
  assert.ok(share.data.shareUrl.startsWith(`${base}/s/`));
  // Alice cannot open it, Bob can.
  assert.equal((await call('/api/v1/open', { bearer: alice, body: { link: share.data.shareUrl } })).data.error, 'not_recipient');
  const opened = await call('/api/v1/open', { bearer: bob, body: { link: share.data.shareUrl } });
  assert.equal(opened.status, 200);
  assert.equal(opened.data.secret, 'via api');
  // Wrong audience, other tenant, v1 issuer of Entra, an app without user.
  const wrongAud = await mock.sign(ALICE, { aud: 'api://other' });
  assert.equal((await call('/api/v1/share', { bearer: wrongAud, body: { secret: 's' } })).status, 401);
  const other = await mock.sign({ ...ALICE, tid: OTHER_TENANT }, { aud });
  assert.equal((await call('/api/v1/share', { bearer: other, body: { secret: 's' } })).status, 401);
  const app = await mock.sign({ tid: TENANT, idtyp: 'app', azp: 'my-script' }, { aud });
  const byApp = await call('/api/v1/share', { bearer: app, body: { secret: 's' } });
  assert.equal(byApp.status, 201);
  // An app has no user: it cannot choose recipients' secrets to open.
  const s2 = await call('/api/v1/share', { bearer: alice, body: { secret: 's', recipients: ['bob@example.com'] } });
  assert.equal((await call('/api/v1/open', { bearer: app, body: { link: s2.data.shareUrl } })).data.error, 'not_recipient');
  assert.equal((await call('/api/v1/me', { bearer: 'not.a.token' })).data.signedIn, false);
});

test('sign-in tokens from another tenant are refused; Entra e-mail only when verified', opts, async () => {
  const { login, call } = await startApp();
  const r = await login({ ...ALICE, tid: OTHER_TENANT });
  assert.equal(r.status, 400);
  assert.equal(r.cookie, '');
  const alice = (await login(ALICE)).cookie;
  const c = await create(call, alice, { recipients: ['boss@example.com'] });
  const fake = (await login({ ...CAROL, email: 'boss@example.com' })).cookie;
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: fake, body: {} })).data.error, 'not_recipient');
  const real = (await login({ ...CAROL, email: 'boss@example.com', xms_edov: true })).cookie;
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: real, body: {} })).status, 200);
});

test('AUTH_CREATE=anyone: anonymous secrets, restricting still needs a sign-in', opts, async () => {
  const { call } = await startApp({ AUTH_CREATE: 'anyone' });
  assert.match((await call('/')).data, /create-form/);
  assert.equal((await create(call, '')).status, 201);
  assert.equal((await create(call, '', { recipients: ['a@example.com'] })).status, 401);
});

test('generic OIDC provider: issuer with a path, groups claim values', opts, async () => {
  const oidc = await startMock({ clientId: 'vanishly', clientSecret: SECRET, path: '/realms/test' });
  closers.push(() => oidc.close());
  const saved = mock;
  mock = oidc;
  try {
    const { call, login } = await startApp({
      AUTH_PROVIDER: 'oidc',
      ENTRA_TENANT_ID: '',
      ENTRA_CLIENT_ID: '',
      ENTRA_CLIENT_SECRET: '',
      ENTRA_AUTHORITY: '',
      ENTRA_GRAPH_URL: '',
      OIDC_ISSUER: oidc.issuer,
      OIDC_CLIENT_ID: 'vanishly',
      OIDC_CLIENT_SECRET: SECRET,
      RECIPIENT_GROUPS: 'Ops=ops',
    });
    const alice = (await login({ sub: 'a', email: 'alice@example.org', name: 'Alice' })).cookie;
    const ops = (await login({ sub: 'b', email: 'bert@example.org', groups: ['ops'] })).cookie;
    // A user name the account may have picked itself, or an unverified e-mail, does not count.
    const c1 = await create(call, alice, { recipients: ['bert@example.org'] });
    const picked = (await login({ sub: 'x', preferred_username: 'bert@example.org' })).cookie;
    assert.equal(picked, ''); // no usable address: no session
    const unverified = (await login({ sub: 'y', email: 'bert@example.org', email_verified: false })).cookie;
    assert.equal(unverified, '');
    assert.equal((await call(`/api/v1/secrets/${c1.data.id}/reveal`, { cookie: ops, body: {} })).status, 200);
    const c = await create(call, alice, { recipientGroups: ['ops'] });
    assert.equal(c.status, 201);
    assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, { cookie: ops, body: {} })).status, 200);
  } finally {
    mock = saved;
  }
});
