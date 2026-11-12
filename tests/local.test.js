// Local accounts (AUTH_PROVIDER=local) against a real Redis: hashing, the
// first admin, sign-in with lockout, sessions, the admin API.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';
import { hashPassword, verifyPassword } from '../src/users.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };
const ADMIN = 'admin@example.com';
const PW = 'change-me-admin-password';

/** @type {any} */ let redisProc;
let redisUrl = '';
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
});

after(async () => {
  for (const c of closers) await c();
  redisProc?.kill();
});

let n = 0;
/** @param {Record<string, string>} env */
async function startApp(env = {}) {
  /** @type {any} */ let handler = null;
  const server = createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(undefined)));
  const base = `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `localtest${process.pid}-${n++}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ACCESS_LOG: 'false',
    BASE_URL: base,
    AUTH_PROVIDER: 'local',
    AUTH_SECRET: 'x'.repeat(40),
    LOCAL_ADMIN_USERNAME: ADMIN,
    LOCAL_ADMIN_PASSWORD: PW,
    AUDIT_LOG: 'true',
    AUDIT_LOG_REDIS: 'true',
    ...env,
  });
  const store = await Store.connect(redisUrl, config);
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
  /** @type {import('../src/users.js').Users} */
  const users = app.locals.users;
  handler = app;
  closers.push(async () => {
    server.closeAllConnections();
    server.close();
    await store.close();
  });
  await users.bootstrap();
  /** @param {string} path @param {{ body?: any, cookie?: string }} [o] */
  const call = async (path, o = {}) => {
    const res = await fetch(base + path, {
      method: o.body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', ...(o.cookie ? { Cookie: o.cookie } : {}) },
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
  /** A form post like the browser's. @param {string} path @param {Record<string, string>} fields @param {{ cookie?: string, origin?: string }} [o] */
  const form = async (path, fields, o = {}) => {
    const res = await fetch(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: o.origin || base, ...(o.cookie ? { Cookie: o.cookie } : {}) },
      body: new URLSearchParams(fields).toString(),
      redirect: 'manual',
    });
    return { status: res.status, text: await res.text(), location: res.headers.get('location'), cookie: String(res.headers.get('set-cookie') || '').split(';')[0] };
  };
  /** @param {string} user @param {string} password @param {string} [cookie] */
  const login = (user, password, cookie) => form('/auth/login', { user, password, return: '/admin' }, { cookie });
  return { base, call, form, login, users, store, config };
}

test('password hashes: scrypt with salt and parameters, constant-time check, tampered parameters refused', async () => {
  const a = await hashPassword('correct horse battery');
  const b = await hashPassword('correct horse battery');
  assert.match(a, /^scrypt\$32768\$8\$3\$[\w-]{22}\$[\w-]{43}$/);
  assert.notEqual(a, b, 'a fresh salt each time');
  assert.equal(await verifyPassword('correct horse battery', a), true);
  assert.equal(await verifyPassword('correct horse batterz', a), false);
  assert.equal(await verifyPassword('', a), false);
  assert.equal(await verifyPassword('x', 'garbage'), false);
  // A record pointing at huge parameters is refused without hashing.
  assert.equal(await verifyPassword('correct horse battery', a.replace('$32768$', '$4194304$')), false);
  assert.equal(await verifyPassword('correct horse battery', a.replace('$32768$', '$30000$')), false);
});

test('the first admin: only while there are no users; a changed password stays; no admin, no start', opts, async () => {
  const { users, config } = await startApp();
  const first = await users.get(ADMIN);
  assert.equal(first?.role, 'admin');
  assert.ok(!JSON.stringify(first).includes(PW), 'only the hash is kept');
  assert.equal(await users.bootstrap(), null, 'second start: nothing to do');
  assert.ok(!('error' in (await users.setPassword(ADMIN, 'a-new-password-for-admin'))));
  assert.equal(await users.bootstrap(), null);
  assert.equal((await users.login(ADMIN, PW)).ok, false, 'the env password does not come back');
  assert.equal((await users.login(ADMIN, 'a-new-password-for-admin')).ok, true);
  // Another prefix = an empty store, without LOCAL_ADMIN_*: the start is refused.
  const empty = await startApp({ LOCAL_ADMIN_USERNAME: '', LOCAL_ADMIN_PASSWORD: '' }).catch((err) => err);
  assert.match(String(empty), /no users yet: set LOCAL_ADMIN_USERNAME and LOCAL_ADMIN_PASSWORD/);
  assert.equal(config.auth?.local?.minLength, 12);
});

test('sign-in: form, same answer for unknown and wrong, new session each time, only from this site', opts, async () => {
  const { call, login, form } = await startApp();
  const page = await call('/auth/login?return=%2Fadmin');
  assert.equal(page.status, 200);
  assert.match(String(page.data), /<form method="post" action="\/auth\/login">/);
  assert.match(String(page.data), /name="return" value="\/admin"/);
  assert.match(String(page.data), /autocomplete="current-password"/);
  const wrong = await login(ADMIN, 'wrong-password-123');
  const unknown = await login('nobody@example.com', 'wrong-password-123');
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  const msg = (/** @type {string} */ t) => /<p class="notice notice-error" role="alert">([^<]*)<\/p>/.exec(t)?.[1];
  assert.equal(msg(wrong.text), msg(unknown.text));
  assert.equal(wrong.cookie, '');
  const ok = await login(ADMIN, PW);
  assert.equal(ok.status, 303);
  assert.equal(ok.location, '/admin');
  assert.match(ok.cookie, /^vanishly-session=[\w-]{43}$/);
  const me = await call('/api/v1/me', { cookie: ok.cookie });
  assert.equal(me.data.user, ADMIN);
  // Signing in again from the same browser: a new id, the old one is gone.
  const again = await login(ADMIN, PW, ok.cookie);
  assert.notEqual(again.cookie, ok.cookie);
  assert.equal((await call('/api/v1/me', { cookie: ok.cookie })).data.signedIn, false);
  // A form from another site is refused, and an open redirect is not possible.
  assert.equal((await form('/auth/login', { user: ADMIN, password: PW }, { origin: 'https://evil.example' })).status, 403);
  assert.equal((await form('/auth/login', { user: ADMIN, password: PW, return: 'https://evil.example/' })).location, '/');
  // Logout ends it; the CSP has no provider in form-action.
  assert.equal((await form('/auth/logout', {}, { cookie: again.cookie })).status, 303);
  assert.equal((await call('/api/v1/me', { cookie: again.cookie })).data.signedIn, false);
  assert.match(String(page.headers.get('content-security-policy')), /form-action 'self'(;|$)/);
});

test('lockout: LOCAL_LOGIN_ATTEMPTS per account, also for the right password; cleared by a success', opts, async () => {
  const { login, users } = await startApp({ LOCAL_LOGIN_ATTEMPTS: '3' });
  await users.create({ user: 'bob@example.com', password: 'bobs-password-123' });
  assert.equal((await login('bob@example.com', 'bad-password-1')).status, 401);
  assert.equal((await login('bob@example.com', 'bobs-password-123')).status, 303, 'a success clears the count');
  for (let i = 0; i < 3; i++) assert.equal((await login('bob@example.com', 'bad-password-1')).status, 401);
  const locked = await login('bob@example.com', 'bobs-password-123');
  assert.equal(locked.status, 429);
  assert.equal(locked.cookie, '');
  // Other accounts are not affected; unknown ones lock the same way.
  assert.equal((await login(ADMIN, PW)).status, 303);
  for (let i = 0; i < 3; i++) await login('ghost@example.com', 'bad-password-1');
  assert.equal((await login('ghost@example.com', 'bad-password-1')).status, 429);
});

test('own password: current one needed, other sessions end, this one goes on; groups open secrets', opts, async () => {
  const { form, login, call, users } = await startApp({ RECIPIENT_GROUPS: 'Finance=finance' });
  await users.create({ user: 'dave@example.com', password: 'daves-password-123', groups: ['finance'] });
  const a = (await login('dave@example.com', 'daves-password-123')).cookie;
  const b = (await login('dave@example.com', 'daves-password-123')).cookie;
  assert.match(String((await call('/settings/password', { cookie: a })).data), /autocomplete="new-password"/);
  assert.equal((await call('/settings/password')).status, 303, 'signed out: to the sign-in');
  const bad = await form('/settings/password', { current: 'nope-nope-nope', password: 'daves-new-password', repeat: 'daves-new-password' }, { cookie: a });
  assert.equal(bad.status, 400);
  assert.equal((await form('/settings/password', { current: 'daves-password-123', password: 'daves-new-password', repeat: 'other' }, { cookie: a })).status, 400);
  assert.equal((await form('/settings/password', { current: 'daves-password-123', password: 'short', repeat: 'short' }, { cookie: a })).status, 400);
  const ok = await form('/settings/password', { current: 'daves-password-123', password: 'daves-new-password', repeat: 'daves-new-password' }, { cookie: a });
  assert.equal(ok.status, 200);
  assert.match(ok.cookie, /^vanishly-session=/);
  assert.equal((await call('/api/v1/me', { cookie: ok.cookie })).data.user, 'dave@example.com');
  assert.equal((await call('/api/v1/me', { cookie: b })).data.signedIn, false, 'the other session ended');
  assert.equal((await call('/api/v1/me', { cookie: a })).data.signedIn, false, 'the old id of this one too');
  // The groups of the account work as recipient groups.
  const { Auth } = await import('../src/auth.js');
  const who = users.identity(/** @type {any} */ (await users.get('dave@example.com')));
  assert.ok(Auth.allowed(who, [/** @type {any} */ (users).hash('g', 'finance')]));
});
