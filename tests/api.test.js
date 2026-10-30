// API tests against a real Redis: REDIS_URL, or a redis-server started here.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';
import { decryptSecret, encryptSecret, unlockKey, verifierFor } from '../public/js/vanishly-crypto.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
/** @type {any} */ let redisProc;
/** @type {any} */ let server;
/** @type {Store} */ let store;
let base = '';
let redisUrl = '';

before(async () => {
  if (!haveRedis) return;
  let url = process.env.REDIS_URL;
  if (!url) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    redisProc = spawn('redis-server', ['--port', String(port), '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
    url = `redis://127.0.0.1:${port}`;
    await new Promise((r) => setTimeout(r, 300));
  }
  redisUrl = url;
  const config = loadConfig({
    REDIS_URL: url,
    REDIS_PREFIX: `test${process.pid}:`,
    PASSPHRASE_ATTEMPTS: '3',
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    MAX_SECRET_CHARS: '100',
    ACCESS_LOG: 'false',
  });
  store = await Store.connect(url, config);
  const theme = loadTheme(config, 'test');
  const app = createApp({ config, store, theme, version: 'test' });
  server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server?.close();
  await store?.close();
  redisProc?.kill();
});

/** @param {string} path @param {any} [body] */
async function call(path, body) {
  const res = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, data, headers: res.headers };
}

const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };

test('one-view secret: reveal once, then gone; receipt follows', opts, async () => {
  const { key, payload } = await encryptSecret('top secret');
  const c = await call('/api/v1/secrets', { ...payload, ttl: 600 });
  assert.equal(c.status, 201);
  assert.match(c.data.secretPath, /^\/s\/[A-Za-z0-9_-]{22}$/);
  const r0 = await call(`/api/v1/receipts/${c.data.receiptId}`);
  assert.equal(r0.data.state, 'new');
  const page = await fetch(base + c.data.secretPath);
  assert.equal(page.status, 200); // the page itself uses no view
  assert.equal(page.headers.get('cache-control'), 'no-store');
  const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, {});
  assert.equal(r.status, 200);
  assert.equal(r.data.viewsLeft, 0);
  assert.equal(await decryptSecret(r.data, key), 'top secret');
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, {})).status, 404);
  assert.equal((await fetch(base + c.data.secretPath)).status, 404);
  const r1 = await call(`/api/v1/receipts/${c.data.receiptId}`);
  assert.equal(r1.data.state, 'received');
  assert.equal(r1.data.views.length, 1);
  assert.equal(r1.data.secretPath, null);
});

test('parallel reveals of a one-view secret: exactly one wins', opts, async () => {
  const { payload } = await encryptSecret('race');
  const c = await call('/api/v1/secrets', payload);
  const results = await Promise.all(Array.from({ length: 10 }, () => call(`/api/v1/secrets/${c.data.id}/reveal`, {})));
  assert.equal(results.filter((x) => x.status === 200).length, 1);
});

test('views: a 3-view secret can be read three times', opts, async () => {
  const { payload } = await encryptSecret('multi');
  const c = await call('/api/v1/secrets', { ...payload, views: 3 });
  const left = [];
  for (let i = 0; i < 4; i++) {
    const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, {});
    left.push(r.status === 200 ? r.data.viewsLeft : r.status);
  }
  assert.deepEqual(left, [2, 1, 0, 404]);
});

test('passphrase: wrong ones use no view, too many destroy the secret', opts, async () => {
  const { key, payload } = await encryptSecret('guarded', 'pw');
  const c = await call('/api/v1/secrets', payload);
  const meta = await call(`/api/v1/secrets/${c.data.id}`);
  assert.equal(meta.data.passphrase, true);
  assert.equal(meta.data.verifier, undefined);
  const badPk = await unlockKey('nope', meta.data);
  const bad = await verifierFor(badPk, meta.data);
  let r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { verifier: bad });
  assert.equal(r.status, 403);
  assert.equal(r.data.attemptsLeft, 2);
  r = await call(`/api/v1/secrets/${c.data.id}/reveal`, {});
  assert.equal(r.status, 403);
  const pk = await unlockKey('pw', meta.data);
  r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { verifier: await verifierFor(pk, meta.data) });
  assert.equal(r.status, 200);
  assert.equal(await decryptSecret(r.data, key, pk), 'guarded');

  const c2 = await call('/api/v1/secrets', (await encryptSecret('x', 'pw')).payload);
  for (const want of [403, 403, 410]) {
    assert.equal((await call(`/api/v1/secrets/${c2.data.id}/reveal`, { verifier: bad })).status, want);
  }
  assert.equal((await call(`/api/v1/receipts/${c2.data.receiptId}`)).data.state, 'burned');
});

test('burn through the receipt', opts, async () => {
  const c = await call('/api/v1/secrets', (await encryptSecret('burn me')).payload);
  assert.equal((await call(`/api/v1/receipts/${c.data.receiptId}/burn`, {})).status, 200);
  assert.equal((await call(`/api/v1/receipts/${c.data.receiptId}/burn`, {})).status, 409);
  assert.equal((await call(`/api/v1/secrets/${c.data.id}/reveal`, {})).status, 404);
  const r = await call(`/api/v1/receipts/${c.data.receiptId}`);
  assert.equal(r.data.state, 'burned');
  assert.ok(r.data.burned);
});

test('share: server-side encryption returns working links', opts, async () => {
  const c = await call('/api/v1/share', { secret: 'from curl', passphrase: 'p', views: 2, ttl: 3600 });
  assert.equal(c.status, 201);
  const [, id, key] = /\/s\/([\w-]{22})#([\w-]{43})$/.exec(c.data.shareUrl) || [];
  assert.ok(id && key);
  const meta = (await call(`/api/v1/secrets/${id}`)).data;
  const pk = await unlockKey('p', meta);
  const r = await call(`/api/v1/secrets/${id}/reveal`, { verifier: await verifierFor(pk, meta) });
  assert.equal(await decryptSecret(r.data, key, pk), 'from curl');
});

test('input validation', opts, async () => {
  const { payload } = await encryptSecret('v');
  /** @type {[any, string][]} */
  const cases = [
    [{ ...payload, ttl: 10 }, 'invalid_ttl'],
    [{ ...payload, ttl: 99999999 }, 'invalid_ttl'],
    [{ ...payload, views: 0 }, 'invalid_views'],
    [{ ...payload, views: 1.5 }, 'invalid_views'],
    [{ ...payload, iv: 'short' }, 'invalid_iv'],
    [{ ...payload, ciphertext: '<script>' }, 'invalid_ciphertext'],
    [{ ...payload, iterations: 5_000_000 }, 'invalid_iterations'],
    [{ ...payload, verifier: 'x' }, 'invalid_verifier'],
    [{ ...payload, v: 2 }, 'invalid_version'],
  ];
  for (const [body, code] of cases) {
    const r = await call('/api/v1/secrets', body);
    assert.equal(r.status, 400, code);
    assert.equal(r.data.error, code);
  }
  assert.equal((await call('/api/v1/secrets', { ...payload, ciphertext: 'A'.repeat(5000) })).status, 413);
  assert.equal((await call('/api/v1/share', { secret: 'x'.repeat(101) })).status, 413);
  assert.equal((await call('/api/v1/share', { secret: '' })).status, 400);
  const raw = await fetch(`${base}/api/v1/secrets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{nope' });
  assert.equal(raw.status, 400);
  assert.equal((await call('/api/v1/secrets/..%2f..%2fetc/reveal', {})).status, 404);
  assert.equal((await call('/api/v1/receipts/short')).status, 404);
  assert.equal((await call('/api/v1/nothing')).status, 404);
  assert.equal((await fetch(`${base}/s/not-an-id`)).status, 404);
});

test('headers, health, OpenAPI document, static files', opts, async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy') || '', /script-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.equal(await (await fetch(`${base}/healthz`)).text(), 'ok');
  const spec = (await call('/api/openapi.json')).data;
  assert.equal(spec.openapi, '3.1.0');
  assert.equal(spec.info.version, 'test');
  for (const p of ['/v1/secrets', '/v1/share', '/v1/secrets/{id}', '/v1/secrets/{id}/reveal', '/v1/receipts/{id}', '/v1/receipts/{id}/burn', '/v1/config']) {
    assert.ok(spec.paths[p], p);
  }
  const docs = await fetch(`${base}/api/docs`);
  assert.equal(docs.status, 200);
  assert.match(docs.headers.get('content-security-policy') ?? '', /script-src 'self';/);
  const scalar = await fetch(`${base}/api/docs/assets/scalar.js`);
  assert.equal(scalar.status, 200);
  // No URL in the bundle points to the font host (compared as host name).
  const hosts = new Set([...(await scalar.text()).matchAll(/(?:https?:)?\/\/([\w.-]+)/g)].map((m) => m[1].toLowerCase()));
  assert.equal(hosts.has('fonts.scalar.com'), false);
  assert.equal((await fetch(`${base}/static/js/vanishly-crypto.js`)).status, 200);
  const css = await fetch(`${base}/theme/theme.css`);
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type') ?? '', /^text\/css/);
  assert.equal((await fetch(`${base}/theme/theme.css`, { headers: { 'If-None-Match': css.headers.get('etag') ?? '', 'Cache-Control': 'max-age=0' } })).status, 304);
  assert.equal((await fetch(`${base}/static/../package.json`)).status, 404);
  const de = await (await fetch(`${base}/`, { headers: { 'Accept-Language': 'de-DE,de;q=0.9' } })).text();
  assert.match(de, /Geheimnis teilen/);
});

test('minimum lengths, required passphrase, confirmation, expiry options', opts, async () => {
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `testmin${process.pid}:`,
    MIN_SECRET_CHARS: '12',
    MIN_PASSPHRASE_LENGTH: '8',
    PASSPHRASE_COMPLEXITY: 'upper,digit',
    RATE_LIMIT_CREATE: '1000',
    REQUIRE_PASSPHRASE: 'true',
    CONFIRM_CHECKBOX: 'true',
    CONFIRM_TEXT_EN: 'One password only, <b>please</b>',
    TTL_OPTIONS: '10m,1h,2d',
    ACCESS_LOG: 'false',
  });
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const b = `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`;
  /** @param {string} path @param {any} body */
  const post = async (path, body) => {
    const r = await fetch(b + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json() };
  };
  try {
    const ok = { confirmed: true, ttl: 3600 };
    // client-encrypted: length from the ciphertext size, passphrase presence from the verifier
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('short', 'Longenough1')).payload, ...ok })).data.error, 'too_short');
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('twelve chars')).payload, ...ok })).data.error, 'passphrase_required');
    assert.equal((await post('/api/v1/secrets', (await encryptSecret('twelve chars', 'Longenough1')).payload)).data.error, 'confirmation_required');
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('twelve chars', 'Longenough1')).payload, ...ok })).status, 201);
    // a multibyte secret long enough in characters is never refused
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('äöüäöüäöüäöü', 'Longenough1')).payload, ...ok })).status, 201);
    // MAX_TTL follows TTL_OPTIONS
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('twelve chars', 'Longenough1')).payload, confirmed: true, ttl: 3 * 86400 })).data.error, 'invalid_ttl');
    // server-side encryption checks everything
    assert.equal((await post('/api/v1/share', { secret: 'short', passphrase: 'Longenough1', ...ok })).data.error, 'too_short');
    assert.equal((await post('/api/v1/share', { secret: 'twelve chars', ...ok })).data.error, 'passphrase_required');
    assert.equal((await post('/api/v1/share', { secret: 'twelve chars', passphrase: 'short', ...ok })).data.error, 'passphrase_too_short');
    assert.equal((await post('/api/v1/share', { secret: 'twelve chars', passphrase: 'Longenough1' })).data.error, 'confirmation_required');
    const weak = await post('/api/v1/share', { secret: 'twelve chars', passphrase: 'longenough', ...ok });
    assert.equal(weak.data.error, 'passphrase_too_weak');
    assert.deepEqual(weak.data.missing, ['upper', 'digit']);
    assert.equal((await post('/api/v1/share', { secret: 'twelve chars', passphrase: 'Longenough1', ...ok })).status, 201);
    const cfg = await (await fetch(`${b}/api/v1/config`)).json();
    assert.deepEqual([cfg.minSecretChars, cfg.minPassphraseLength, cfg.requirePassphrase], [12, 8, true]);
    const html = await (await fetch(`${b}/`)).text();
    assert.match(html, /data-min-chars="12" data-min-pass="8" data-pass-required="1"/);
    assert.match(html, /Passphrase \(required\)/);
    assert.match(html, /data-pass-classes="upper,digit"/);
    assert.match(html, /At least 8 characters\. Must contain an upper-case letter, a digit\./);
    assert.match(html, /<input type="checkbox" id="confirm" name="confirm" required><label for="confirm">One password only, &lt;b&gt;please&lt;\/b&gt;<\/label>/);
    assert.match(html, /<option value="600">10 minutes<\/option><option value="3600" selected>1 hour<\/option><option value="172800">2 days<\/option>/);
    const de = await (await fetch(`${b}/?lang=de`)).text();
    assert.match(de, /Ich bestätige/);
    assert.match(de, /2 Tagen/);
    assert.equal(cfg.confirmation.en, 'One password only, <b>please</b>');
  } finally {
    srv.close();
  }
});

test('switched-off features', opts, async () => {
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `testoff${process.pid}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ENABLE_PASSPHRASE: 'false',
    ENABLE_VIEWS: 'false',
    ENABLE_RECEIPTS: 'false',
    ENABLE_GENERATOR: 'false',
    ENABLE_THEME_TOGGLE: 'false',
    ENABLE_GITHUB_LINK: 'false',
    ENABLE_API: 'false',
    ACCESS_LOG: 'false',
  });
  assert.equal(config.maxViews, 1);
  assert.equal(config.features.burn, false);
  assert.equal(config.features.apiLink, false);
  const s2 = await Store.connect(redisUrl, config);
  const app = createApp({ config, store: s2, theme: loadTheme(config, 'test'), version: 'test' });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const b = `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`;
  const page = { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' };
  /** @param {string} path @param {any} body @param {Record<string, string>} [headers] */
  const post = async (path, body, headers = page) => {
    const r = await fetch(b + path, { method: 'POST', headers, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json() };
  };
  try {
    // ENABLE_API=false: scripts get 404, the own pages still work
    assert.equal((await post('/api/v1/secrets', (await encryptSecret('hi')).payload, { 'Content-Type': 'application/json' })).status, 404);
    assert.equal((await post('/api/v1/share', { secret: 'hi' })).status, 404);
    assert.equal((await fetch(`${b}/api/v1/config`)).status, 404);
    assert.equal((await post('/api/v1/open', { link: 'x' })).status, 404);
    assert.equal((await fetch(`${b}/api/openapi.json`)).status, 404);
    assert.equal((await fetch(`${b}/api/docs`)).status, 404);
    assert.equal((await fetch(`${b}/api/docs/assets/scalar.js`)).status, 404);
    assert.equal((await post('/api/v1/secrets', (await encryptSecret('hi', 'pass')).payload)).data.error, 'passphrase_disabled');
    assert.equal((await post('/api/v1/secrets', { ...(await encryptSecret('hi')).payload, views: 2 })).data.error, 'invalid_views');
    const { key, payload } = await encryptSecret('hi');
    const c = await post('/api/v1/secrets', payload);
    assert.equal(c.status, 201);
    assert.equal(c.data.receiptId, null);
    assert.equal(c.data.receiptPath, null);
    const r = await post(`/api/v1/secrets/${c.data.id}/reveal`, {});
    assert.equal(await decryptSecret(r.data, key), 'hi');
    // no receipt was stored, and the receipt page and API are gone
    assert.equal((await s2.redis.keys(`testoff${process.pid}:r:*`)).length, 0);
    assert.equal((await fetch(`${b}/api/v1/receipts/${'a'.repeat(22)}`, { headers: page })).status, 404);
    assert.equal((await fetch(`${b}/r/${'a'.repeat(22)}`)).status, 404);
    const html = await (await fetch(`${b}/`)).text();
    assert.match(html, /class="no-passphrase no-views no-receipts no-burn no-view-log no-receipt-key no-generator no-theme-toggle no-api-link no-github-link"/);
    assert.match(html, /data-mode-toggle="0"/);
  } finally {
    srv.close();
    await s2.close();
  }
});

test('view log off keeps the receipt without times', opts, async () => {
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `testlog${process.pid}:`,
    ENABLE_VIEW_LOG: 'false',
    ENABLE_BURN: 'false',
    ENABLE_RECEIPT_SHARE_LINK: 'false',
    ENABLE_SHARE_API: 'false',
    ENABLE_API_LINK: 'false',
    ACCESS_LOG: 'false',
  });
  const s2 = await Store.connect(redisUrl, config);
  const app = createApp({ config, store: s2, theme: loadTheme(config, 'test'), version: 'test' });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const b = `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`;
  /** @param {string} path @param {any} body */
  const post = async (path, body) => {
    const r = await fetch(b + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json() };
  };
  try {
    assert.equal((await post('/api/v1/share', { secret: 'hi' })).status, 404);
    const c = await post('/api/v1/secrets', { ...(await encryptSecret('hi')).payload, views: 2 });
    await post(`/api/v1/secrets/${c.data.id}/reveal`, {});
    const r = await (await fetch(`${b}/api/v1/receipts/${c.data.receiptId}`)).json();
    assert.equal(r.state, 'viewed');
    assert.deepEqual(r.views, []);
    assert.equal(r.secretPath, null);
    assert.equal((await s2.redis.exists(`testlog${process.pid}:r:${c.data.receiptId}:v`)), 0);
    assert.equal((await post(`/api/v1/receipts/${c.data.receiptId}/burn`, {})).status, 404);
    // the API itself stays, only the footer link is gone
    assert.equal((await fetch(`${b}/api/openapi.json`)).status, 200);
    const home = await (await fetch(`${b}/`)).text();
    assert.match(home, /no-api-link/);
    // the GitHub link is on by default
    assert.doesNotMatch(home, /no-github-link/);
    assert.match(home, /class="github-link" href="https:\/\/github\.com\//);
  } finally {
    srv.close();
    await s2.close();
  }
});

/**
 * Starts the app with these settings and calls fn with its base URL.
 * @param {Record<string, string>} env
 * @param {(b: string) => Promise<void>} fn
 */
async function withApp(env, fn) {
  const config = loadConfig({ REDIS_URL: redisUrl, REDIS_PREFIX: `testlang${process.pid}:`, ACCESS_LOG: 'false', ...env });
  const s2 = await Store.connect(redisUrl, config);
  const app = createApp({ config, store: s2, theme: loadTheme(config, 'test'), version: 'test' });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  try {
    await fn(`http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`);
  } finally {
    srv.close();
    await s2.close();
  }
}

/**
 * The page language and the Set-Cookie header of a request.
 * @param {string} url
 * @param {Record<string, string>} [headers]
 */
async function pageLang(url, headers = {}) {
  const r = await fetch(url, { headers });
  const html = await r.text();
  return { lang: /<html lang="(\w+)"/.exec(html)?.[1], cookie: r.headers.get('set-cookie'), html };
}

test('languages: browser language, ?lang= and cookie, fallback English', opts, async () => {
  await withApp({}, async (b) => {
    assert.equal((await pageLang(`${b}/`, { 'Accept-Language': 'de-CH,de;q=0.9,en;q=0.5' })).lang, 'de');
    assert.equal((await pageLang(`${b}/`, { 'Accept-Language': 'fr-FR,fr;q=0.9' })).lang, 'en');
    assert.equal((await pageLang(`${b}/`)).lang, 'en');
    const q = await pageLang(`${b}/?lang=de`, { 'Accept-Language': 'en' });
    assert.equal(q.lang, 'de');
    assert.match(q.cookie || '', /^lang=de;/);
    assert.match(q.html, /<a class="lang-switch" href="\?lang=en" hreflang="en" lang="en">English<\/a>/);
    assert.equal((await pageLang(`${b}/`, { Cookie: 'lang=de', 'Accept-Language': 'en' })).lang, 'de');
    assert.equal((await pageLang(`${b}/?lang=xx`)).lang, 'en');
    const cfg = await (await fetch(`${b}/api/v1/config`)).json();
    assert.deepEqual([cfg.languages, cfg.defaultLang, cfg.features.langSwitch], [['en', 'de'], 'en', true]);
  });
});

test('languages: LANGUAGES=en serves English only, whatever the visitor asks', opts, async () => {
  await withApp({ LANGUAGES: 'en' }, async (b) => {
    for (const [path, headers] of /** @type {[string, Record<string, string>][]} */ ([
      ['/?lang=de', {}],
      ['/', { Cookie: 'lang=de' }],
      ['/', { 'Accept-Language': 'de-DE,de;q=0.9' }],
    ])) {
      const p = await pageLang(b + path, headers);
      assert.equal(p.lang, 'en', path);
      assert.equal(p.cookie, null, path);
      assert.match(p.html, /class="[^"]*no-lang-switch/, path);
    }
    const cfg = await (await fetch(`${b}/api/v1/config`)).json();
    assert.deepEqual([cfg.languages, cfg.defaultLang, cfg.features.langSwitch], [['en'], 'en', false]);
  });
});

test('languages: ENABLE_LANG_SWITCH=false ignores ?lang= and the cookie, not the browser', opts, async () => {
  await withApp({ ENABLE_LANG_SWITCH: 'false' }, async (b) => {
    const q = await pageLang(`${b}/?lang=de`);
    assert.deepEqual([q.lang, q.cookie], ['en', null]);
    assert.equal((await pageLang(`${b}/`, { Cookie: 'lang=de' })).lang, 'en');
    assert.equal((await pageLang(`${b}/`, { 'Accept-Language': 'de' })).lang, 'de');
  });
});

test('languages: a file in TRANSLATIONS_DIR adds a language, missing texts in English', opts, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vanishly-tr-'));
  writeFileSync(join(dir, 'fr.json'), JSON.stringify({ 'lang.name': 'Français', 'home.title': 'Partager un secret' }));
  writeFileSync(join(dir, 'de.json'), JSON.stringify({ 'home.title': 'Geheimnis weitergeben' }));
  await withApp({ TRANSLATIONS_DIR: dir, LANGUAGES: 'fr,en,de', CONFIRM_CHECKBOX: 'true' }, async (b) => {
    const fr = await pageLang(`${b}/`, { 'Accept-Language': 'fr' });
    assert.equal(fr.lang, 'fr');
    assert.match(fr.html, /Partager un secret/);
    assert.match(fr.html, /Expires after/); // not translated: English
    assert.match(fr.html, /href="\?lang=en" hreflang="en" lang="en">English</); // next in LANGUAGES
    const de = await pageLang(`${b}/?lang=de`);
    assert.match(de.html, /Geheimnis weitergeben/); // replaced
    assert.match(de.html, /Läuft ab nach/); // the rest stays German
    assert.match(de.html, /lang="fr">Français</);
    assert.equal((await pageLang(`${b}/`)).lang, 'en'); // DEFAULT_LANG en, served
    const cfg = await (await fetch(`${b}/api/v1/config`)).json();
    assert.deepEqual(cfg.languages, ['fr', 'en', 'de']);
    assert.deepEqual(Object.keys(cfg.confirmation), ['fr', 'en', 'de']);
  });
});

test('confirmation: the API error states the same rule as the form', opts, async () => {
  /** @param {string} html */
  const label = (html) => /<label for="confirm">([^<]*)<\/label>/.exec(html)?.[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
  /**
   * @param {string} b @param {string} path @param {any} body @param {Record<string, string>} [headers]
   */
  const post = async (b, path, body, headers = {}) => {
    const r = await fetch(b + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json() };
  };
  await withApp({ CONFIRM_CHECKBOX: 'true' }, async (b) => {
    const ui = label((await pageLang(`${b}/`)).html);
    assert.match(ui || '', /only one password/);
    const enc = (await encryptSecret('hi')).payload;
    for (const [path, base] of /** @type {[string, any][]} */ ([['/api/v1/secrets', enc], ['/api/v1/share', { secret: 'hi' }]])) {
      for (const confirmed of [undefined, false, 'true', 1]) {
        const r = await post(b, path, { ...base, ...(confirmed === undefined ? {} : { confirmed }) });
        assert.equal(r.status, 400, `${path} ${confirmed}`);
        assert.equal(r.data.error, 'confirmation_required');
        assert.equal(r.data.rule, ui);
        assert.ok(r.data.message.startsWith(ui), r.data.message);
        assert.match(r.data.message, /Send "confirmed": true to confirm\.$/);
      }
      assert.equal((await post(b, path, { ...base, confirmed: true })).status, 201);
    }
    // German request: the German label of the form, a German hint.
    const de = label((await pageLang(`${b}/`, { 'Accept-Language': 'de' })).html);
    const rde = await post(b, '/api/v1/share', { secret: 'hi' }, { 'Accept-Language': 'de' });
    assert.equal(rde.data.rule, de);
    assert.match(rde.data.message, /^Ich bestätige.*"confirmed": true/);
  });
  await withApp({ CONFIRM_CHECKBOX: 'true', CONFIRM_TEXT: 'Only one password, no user names.' }, async (b) => {
    assert.equal(label((await pageLang(`${b}/`)).html), 'Only one password, no user names.');
    const r = await post(b, '/api/v1/share', { secret: 'hi' });
    assert.equal(r.data.rule, 'Only one password, no user names.');
    assert.equal(r.data.message, 'Only one password, no user names. Send "confirmed": true to confirm.');
  });
  await withApp({ CONFIRM_CHECKBOX: 'true', LANGUAGES: 'en' }, async (b) => {
    const r = await post(b, '/api/v1/share', { secret: 'hi' }, { 'Accept-Language': 'de' });
    assert.match(r.data.message, /^I confirm/); // English only, whatever the browser asks
  });
});

test('GET /api and /api/v1: an index of the switched-on endpoints, browsers to the docs', opts, async () => {
  await withApp({}, async (b) => {
    for (const p of ['/api', '/api/', '/api/v1', '/api/v1/']) {
      const r = await fetch(b + p, { redirect: 'manual' });
      assert.equal(r.status, 200, p);
      const j = await r.json();
      assert.deepEqual([j.name, j.version, j.api, j.docs, j.openapi], ['Vanishly API', 'test', 'v1', '/api/docs', '/api/openapi.json'], p);
      assert.ok(j.endpoints.includes('POST /api/v1/secrets') && j.endpoints.includes('GET /api/v1/secrets/{id}'));
    }
    const html = await fetch(`${b}/api`, { headers: { Accept: 'text/html,application/xhtml+xml' }, redirect: 'manual' });
    assert.deepEqual([html.status, html.headers.get('location')], [302, '/api/docs']);
    const spec = await (await fetch(`${b}/api/openapi.json`)).json();
    assert.ok(spec.paths['/'] && spec.paths['/v1']);
  });
  await withApp({ ENABLE_API_DOCS: 'false', ENABLE_SECRET_META_API: 'false', ENABLE_SHARE_API: 'false', ENABLE_OPEN_API: 'false', ENABLE_CONFIG_API: 'false' }, async (b) => {
    const r = await fetch(`${b}/api`, { headers: { Accept: 'text/html' }, redirect: 'manual' });
    assert.equal(r.status, 200); // no docs: JSON for browsers too
    const j = await r.json();
    assert.equal(j.docs, undefined);
    assert.deepEqual(j.endpoints, ['POST /api/v1/secrets', 'POST /api/v1/secrets/{id}/reveal', 'GET /api/v1/receipts/{id}', 'POST /api/v1/receipts/{id}/burn']);
  });
  await withApp({ ENABLE_API: 'false' }, async (b) => {
    const r = await fetch(`${b}/api`);
    assert.deepEqual([r.status, (await r.json()).error], [404, 'endpoint_disabled']); // no public API
    assert.equal((await (await fetch(`${b}/api/v1/typo`)).json()).error, 'not_found');
  });
});

test('served OpenAPI document: only the switched-on endpoints, the same as the /api index', opts, async () => {
  /** @param {any} spec */
  const ops = (spec) => Object.entries(spec.paths).flatMap(([p, item]) => Object.keys(/** @type {any} */ (item)).map((m) => `${m.toUpperCase()} /api${p}`)).filter((e) => !/ \/api(\/v1)?\/?$/.test(e)).sort();
  for (const env of /** @type {Record<string, string>[]} */ ([
    {},
    { ENABLE_SHARE_API: 'false', ENABLE_OPEN_API: 'false', ENABLE_SECRET_META_API: 'false', ENABLE_CONFIG_API: 'false', ENABLE_ME_API: 'false' },
    { ENABLE_RECEIPTS: 'false' },
    { ENABLE_BURN: 'false', ENABLE_API_DOCS: 'false' },
  ])) {
    await withApp(env, async (b) => {
      const spec = await (await fetch(`${b}/api/openapi.json`)).json();
      const index = await (await fetch(`${b}/api`)).json();
      assert.deepEqual(ops(spec), [...index.endpoints].sort(), JSON.stringify(env));
      assert.equal(spec.info.version, 'test');
      // No schema or tag is left that nothing uses.
      const text = JSON.stringify(spec.paths) + JSON.stringify(spec.components);
      for (const name of Object.keys(spec.components.schemas)) assert.ok(text.includes(`#/components/schemas/${name}"`), `${name} unused`);
      const tags = new Set(Object.values(spec.paths).flatMap((i) => Object.values(/** @type {any} */ (i)).flatMap((o) => o.tags || [])));
      assert.deepEqual(spec.tags.map((/** @type {any} */ t) => t.name).sort(), [...tags].sort());
    });
  }
  await withApp({ ENABLE_SHARE_API: 'false', ENABLE_OPEN_API: 'false', ENABLE_SECRET_META_API: 'false', ENABLE_CONFIG_API: 'false', ENABLE_ME_API: 'false', ENABLE_RECEIPTS: 'false' }, async (b) => {
    const spec = await (await fetch(`${b}/api/openapi.json`)).json();
    assert.deepEqual(Object.keys(spec.paths), ['/', '/v1', '/v1/secrets', '/v1/secrets/{id}/reveal']);
    assert.deepEqual(Object.keys(spec.paths['/v1/secrets/{id}']?.get ? {} : {}), []);
    assert.equal(spec.components.schemas.PlainSecret, undefined); // only /v1/share used it
    assert.equal(spec.components.schemas.Receipt, undefined);
    assert.ok(spec.components.schemas.EncryptedSecret && spec.components.schemas.Error);
  });
  // The file itself stays complete.
  const { readFileSync } = await import('node:fs');
  const file = JSON.parse(readFileSync(new URL('../openapi/openapi.json', import.meta.url), 'utf8'));
  assert.ok(file.paths['/v1/share'] && file.paths['/v1/open'] && file.paths['/v1/secrets/{id}']);
});

test('ENABLE_CREATE_API / REVEAL / RECEIPT / API_INDEX=false: 404 for scripts, the own pages keep working', opts, async () => {
  await withApp({ ENABLE_CREATE_API: 'false', ENABLE_REVEAL_API: 'false', ENABLE_RECEIPT_API: 'false', ENABLE_API_INDEX: 'false' }, async (b) => {
    const page = { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' };
    const script = { 'Content-Type': 'application/json' };
    const { key, payload } = await encryptSecret('hi');
    /** @param {string} p @param {Record<string, string>} h @param {any} [body] */
    const call = (p, h, body) => fetch(b + p, { method: body === undefined ? 'GET' : 'POST', headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    assert.equal((await call('/api/v1/secrets', script, payload)).status, 404);
    const c = await (await call('/api/v1/secrets', page, payload)).json();
    assert.ok(c.id);
    assert.equal((await call(`/api/v1/receipts/${c.receiptId}`, script)).status, 404);
    assert.equal((await call(`/api/v1/receipts/${c.receiptId}`, page)).status, 200);
    assert.equal((await call(`/api/v1/secrets/${c.id}/reveal`, script, {})).status, 404);
    const r = await call(`/api/v1/secrets/${c.id}/reveal`, page, {});
    assert.equal(await decryptSecret(await r.json(), key), 'hi');
    assert.equal((await call(`/api/v1/receipts/${c.receiptId}/burn`, script, {})).status, 404);
    for (const p of ['/api', '/api/v1']) assert.equal((await call(p, script)).status, 404, p);
    const spec = await (await call('/api/openapi.json', script)).json();
    assert.deepEqual(Object.keys(spec.paths).filter((p) => /^\/(v1)?$/.test(p) || /secrets$|reveal$|receipts/.test(p)), []);
  });
});

test('API switches: meta, config and me answer 404 when off; the reveal page still works', opts, async () => {
  await withApp({}, async (b) => {
    for (const p of ['/api/v1/config', '/api/v1/me']) assert.equal((await fetch(b + p)).status, 200, p);
    const cfg = await (await fetch(`${b}/api/v1/config`)).json();
    assert.deepEqual([cfg.features.secretMetaApi, cfg.features.configApi, cfg.features.meApi, cfg.passphraseRule], [true, true, true, 'off']);
  });
  await withApp({ ENABLE_SECRET_META_API: 'false', ENABLE_CONFIG_API: 'false', ENABLE_ME_API: 'false', ENABLE_SHARE_API: 'false', ENABLE_OPEN_API: 'false' }, async (b) => {
    for (const p of ['/api/v1/config', '/api/v1/me', `/api/v1/secrets/${'a'.repeat(22)}`]) {
      const r = await fetch(b + p);
      assert.equal(r.status, 404, p);
      assert.deepEqual(await r.json(), { error: 'endpoint_disabled', message: 'This endpoint is disabled on this server' });
    }
    // A wrong path stays not_found, so the two can be told apart.
    assert.equal((await (await fetch(`${b}/api/v1/nope`)).json()).error, 'not_found');
    for (const p of ['/api/v1/share', '/api/v1/open']) {
      const r = await fetch(b + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      assert.deepEqual([r.status, (await r.json()).error], [404, 'endpoint_disabled'], p);
    }
    /** @param {string} pass */
    const roundTrip = async (pass) => {
      const { key, payload } = await encryptSecret(`secret ${pass}`, pass);
      const c = await (await fetch(`${b}/api/v1/secrets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })).json();
      const html = await (await fetch(`${b}/s/${c.id}`)).text();
      const salt = /data-salt="([^"]*)"/.exec(html)?.[1] || '';
      const iterations = Number(/data-iterations="([^"]*)"/.exec(html)?.[1] || 0);
      assert.equal(Boolean(salt), Boolean(pass));
      /** @type {Uint8Array | undefined} */ let pk;
      /** @type {Record<string, string>} */ const body = {};
      if (pass) {
        pk = await unlockKey(pass, { salt, iterations });
        body.verifier = await verifierFor(pk, { salt });
      }
      const r = await fetch(`${b}/api/v1/secrets/${c.id}/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      assert.equal(r.status, 200);
      return decryptSecret(await r.json(), key, pk);
    };
    assert.equal(await roundTrip(''), 'secret ');
    assert.equal(await roundTrip('Pass phrase 1'), 'secret Pass phrase 1');
  });
});

test('open a secret from a script with link and passphrase', opts, async () => {
  const { key, payload } = await encryptSecret('db password', 'Sunflower-42');
  const c = (await call('/api/v1/secrets', { ...payload, views: 2 })).data;
  const link = `https://ots.example.com/s/${c.id}#${key}`;
  assert.equal((await call('/api/v1/open', { link: 'https://ots.example.com/s/nope' })).status, 400);
  assert.equal((await call('/api/v1/open', { link })).data.error, 'passphrase_required');
  const wrong = await call('/api/v1/open', { link, passphrase: 'wrong' });
  assert.equal(wrong.status, 403);
  assert.equal(wrong.data.attemptsLeft, 2);
  const ok = await call('/api/v1/open', { link, passphrase: 'Sunflower-42' });
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.data, { secret: 'db password', viewsLeft: 1 });
  // a wrong key uses the view and says so
  const bad = await call('/api/v1/open', { link: `https://x/s/${c.id}#${'A'.repeat(43)}`, passphrase: 'Sunflower-42' });
  assert.equal(bad.status, 422);
  assert.equal((await call('/api/v1/open', { link, passphrase: 'Sunflower-42' })).status, 404);
});

test('Redis refuses writes: nothing is handed out, burn fails, health is 503', opts, async () => {
  const { key, payload } = await encryptSecret('still here', 'pass phrase');
  const c = await call('/api/v1/secrets', { ...payload, ttl: 600 });
  assert.equal(c.status, 201);
  const meta = (await call(`/api/v1/secrets/${c.data.id}`)).data;
  const pk = await unlockKey('pass phrase', meta);
  const verifier = await verifierFor(pk, meta);
  const shareUrl = `${base}/s/${c.data.id}#${key}`;

  // A replica of an unreachable primary keeps its data but refuses writes,
  // like a failed-over or read-only Redis.
  const admin = await Store.connect(redisUrl, loadConfig({ REDIS_URL: redisUrl }));
  await admin.redis.sendCommand(['REPLICAOF', '127.0.0.1', '1']);
  try {
    const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { verifier });
    assert.equal(r.status, 500);
    assert.ok(!JSON.stringify(r.data).includes(payload.ciphertext), 'no ciphertext in the error');
    const wrong = await call(`/api/v1/secrets/${c.data.id}/reveal`, { verifier: 'A'.repeat(43) });
    assert.equal(wrong.status, 500); // the wrong try cannot be counted, so it is refused
    const o = await call('/api/v1/open', { link: shareUrl, passphrase: 'pass phrase' });
    assert.equal(o.status, 500);
    assert.ok(!JSON.stringify(o.data).includes('still here'));
    const b = await call(`/api/v1/receipts/${c.data.receiptId}/burn`, {});
    assert.equal(b.status, 500); // never reports "burned" when it is not
    const h = await fetch(`${base}/healthz`);
    assert.equal(h.status, 503);
    // The same below the rate limiter: the reveal script itself refuses.
    await assert.rejects(store.reveal(c.data.id, verifier), /READONLY/);
    await assert.rejects(store.reveal(c.data.id, 'A'.repeat(43)), /READONLY/);
    await assert.rejects(store.burn(c.data.receiptId), /READONLY/);
  } finally {
    await admin.redis.sendCommand(['REPLICAOF', 'NO', 'ONE']);
    await admin.close();
  }

  // Writable again: the secret was not used up by the failed tries.
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  const r = await call(`/api/v1/secrets/${c.data.id}/reveal`, { verifier });
  assert.equal(r.status, 200);
  assert.equal(await decryptSecret(r.data, key, pk), 'still here');
});

test('rate limits: 429 with Retry-After, per client IP, shared Redis counter, 0 = off', opts, async () => {
  /** @param {Record<string, string>} env */
  const serve = async (env) => {
    const config = loadConfig({ REDIS_URL: redisUrl, RATE_LIMIT_WINDOW: '60', ACCESS_LOG: 'false', ...env });
    const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
    const srv = app.listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    return { srv, b: `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}` };
  };
  const id = 'AAAAAAAAAAAAAAAAAAAAAA';
  const one = await serve({ RATE_LIMIT_READ: '3', RATE_LIMIT_CREATE: '1000' });
  // A second replica on the same Redis shares the counter.
  const two = await serve({ RATE_LIMIT_READ: '3', RATE_LIMIT_CREATE: '1000' });
  const off = await serve({ RATE_LIMIT_READ: '0', RATE_LIMIT_CREATE: '1000' });
  try {
    await store.resetHits('read', Store.ipKey('127.0.0.1'));
    // TRUST_PROXY=false: a forged X-Forwarded-For changes nothing.
    /** @param {string} b @param {number} i */
    const get = (b, i) => fetch(`${b}/api/v1/secrets/${id}`, { headers: { 'X-Forwarded-For': `198.51.100.${i}` } });
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push((await get(i % 2 ? two.b : one.b, i)).status);
    assert.ok(!codes.includes(429), codes.join(','));
    const r = await get(two.b, 9);
    assert.equal(r.status, 429);
    assert.deepEqual(await r.json(), { error: 'rate_limited', message: 'Too many requests' });
    const retry = Number(r.headers.get('retry-after'));
    assert.ok(retry >= 1 && retry <= 60, String(retry));
    assert.equal(r.headers.get('ratelimit'), null);
    assert.equal(r.headers.get('x-ratelimit-limit'), null);
    // The counter is the one store.rateLimit() uses (same Redis key).
    assert.equal((await store.rateLimit('read', '127.0.0.1', 3, 60)).ok, false);
    for (let i = 0; i < 5; i++) assert.notEqual((await get(off.b, i)).status, 429);
  } finally {
    await store.resetHits('read', Store.ipKey('127.0.0.1'));
    for (const s of [one, two, off]) s.srv.close();
  }
});
