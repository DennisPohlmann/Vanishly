// The download page, GET /api/v1/downloads, the checksum files and the
// client version rules (src/downloads.js); also the new defaults of the
// server-side endpoints. Needs Redis (REDIS_URL or a local redis-server).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { clientStatus, compareVersions, loadDownloads, parseVersion } from '../src/downloads.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: haveRedis ? false : 'no Redis' };
/** @type {any} */ let redisProc;
let redisUrl = '';

const dir = mkdtempSync(join(tmpdir(), 'vanishly-dl-'));
writeFileSync(join(dir, 'vanishly-linux-amd64'), 'linux binary');
writeFileSync(join(dir, 'vanishly-windows-arm64.exe'), 'windows binary');
writeFileSync(join(dir, 'notes.txt'), 'not offered');
writeFileSync(join(dir, '.vanishly-linux-386'), 'hidden');

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
after(() => redisProc?.kill());

/** @param {Record<string, string>} env @param {(base: string) => Promise<void>} fn @param {string} [downloadsDir] */
async function withApp(env, fn, downloadsDir = dir) {
  const config = loadConfig({ REDIS_URL: redisUrl, REDIS_PREFIX: `testdl${process.pid}:`, ACCESS_LOG: 'false', ...env });
  const store = await Store.connect(redisUrl, config);
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: '3.4.5', downloadsDir });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  try {
    await fn(`http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`);
  } finally {
    srv.close();
    await store.close();
  }
}

test('versions and the client rules', () => {
  assert.deepEqual(parseVersion('3.10.2'), [3, 10, 2]);
  assert.deepEqual(parseVersion('v1.2.3-rc.1'), [1, 2, 3]);
  for (const v of ['dev', '3.1', '', 'edge+abc', '1.2.3.4']) assert.equal(parseVersion(v), null, v);
  assert.ok(compareVersions([3, 10, 0], [3, 9, 9]) > 0);
  const rules = { min: '3.1.0', recommended: '3.2.0' };
  assert.equal(clientStatus(undefined, rules), 'ok'); // curl, own code
  assert.equal(clientStatus('go/dev', rules), 'ok'); // a development build
  assert.equal(clientStatus('go/3.0.9', rules), 'refused');
  assert.equal(clientStatus('python/3.1.5', rules), 'outdated');
  assert.equal(clientStatus('cli/3.2.0', rules), 'ok');
  assert.equal(clientStatus('cli/1.0.0', { min: '', recommended: '' }), 'ok');
});

test('the files of the folder, with every checksum', () => {
  const { files, sums } = loadDownloads(dir);
  assert.deepEqual(files.map((f) => f.name), ['vanishly-linux-amd64', 'vanishly-windows-arm64.exe']);
  const l = files[0];
  assert.deepEqual([l.os, l.arch, l.platform, l.size], ['linux', 'amd64', 'Linux x86-64', 12]);
  for (const [key, algo] of [['sha256', 'sha256'], ['sha512', 'sha512'], ['sha3_256', 'sha3-256'], ['sha3_512', 'sha3-512'], ['blake2b_512', 'blake2b512']]) {
    assert.equal(l.checksums[key], createHash(algo).update('linux binary').digest('hex'), key);
  }
  assert.equal(sums.SHA256SUMS, `${l.checksums.sha256}  vanishly-linux-amd64\n${files[1].checksums.sha256}  vanishly-windows-arm64.exe\n`);
  assert.deepEqual(Object.keys(sums), ['SHA256SUMS', 'SHA512SUMS', 'SHA3-256SUMS', 'SHA3-512SUMS', 'B2SUMS']);
  assert.deepEqual(loadDownloads(join(dir, 'missing')).files, []);
});

test('download page, files, checksum files and the API', opts, async () => {
  await withApp({}, async (b) => {
    const home = await (await fetch(`${b}/`)).text();
    assert.match(home, /<a class="downloads-link" href="\/downloads">Downloads<\/a>/);
    assert.doesNotMatch(home, /no-downloads-link/);
    const html = await (await fetch(`${b}/downloads`)).text();
    assert.match(html, /data-page="downloads"/);
    assert.match(html, /vanishly-windows-arm64\.exe/);
    assert.ok(html.includes(createHash('blake2b512').update('linux binary').digest('hex')));
    assert.match(html, /gh attestation verify vanishly-linux-amd64 --repo DennisPohlmann\/vanishly/);
    assert.match(html, /releases\/tag\/v3\.4\.5/);
    const de = await (await fetch(`${b}/downloads?lang=de`)).text();
    assert.match(de, /Prüfsummen/);
    const file = await fetch(`${b}/downloads/vanishly-linux-amd64`);
    assert.equal(file.status, 200);
    assert.match(String(file.headers.get('content-disposition')), /^attachment; filename="?vanishly-linux-amd64"?$/);
    assert.equal(await file.text(), 'linux binary');
    const sums = await fetch(`${b}/downloads/B2SUMS`);
    assert.match(String(sums.headers.get('content-type')), /^text\/plain/);
    assert.match(await sums.text(), /^[0-9a-f]{128} {2}vanishly-linux-amd64\n/);
    for (const p of ['notes.txt', '.vanishly-linux-386', '..%2Fpackage.json', 'vanishly-linux-amd64%00']) {
      assert.equal((await fetch(`${b}/downloads/${p}`)).status, 404, p);
    }
    const api = await (await fetch(`${b}/api/v1/downloads`)).json();
    assert.equal(api.version, '3.4.5');
    assert.deepEqual([api.minVersion, api.recommendedVersion], [null, null]);
    assert.equal(api.files[0].url, `${b}/downloads/vanishly-linux-amd64`);
    assert.equal(api.files[1].checksums.sha256, createHash('sha256').update('windows binary').digest('hex'));
    assert.equal(api.checksumFiles.sha3_512, `${b}/downloads/SHA3-512SUMS`);
    assert.equal(api.signatures.release, 'https://github.com/DennisPohlmann/vanishly/releases/tag/v3.4.5');
    const spec = await (await fetch(`${b}/api/openapi.json`)).json();
    assert.ok(spec.paths['/v1/downloads'] && spec.components.schemas.Downloads);
  });
  // An empty folder: the page says so, no footer link.
  await withApp({}, async (b) => {
    assert.match(await (await fetch(`${b}/`)).text(), /no-downloads-link/);
    assert.match(await (await fetch(`${b}/downloads`)).text(), /no clients to download/);
    assert.deepEqual((await (await fetch(`${b}/api/v1/downloads`)).json()).files, []);
  }, join(dir, 'missing'));
  // ENABLE_DOWNLOADS_LINK=false: no footer link, the page stays.
  await withApp({ ENABLE_DOWNLOADS_LINK: 'false' }, async (b) => {
    assert.match(await (await fetch(`${b}/`)).text(), /no-downloads-link/);
    assert.equal((await fetch(`${b}/downloads`)).status, 200);
  });
  await withApp({ ENABLE_DOWNLOADS: 'false' }, async (b) => {
    assert.equal((await fetch(`${b}/downloads`)).status, 404);
    assert.equal((await fetch(`${b}/downloads/vanishly-linux-amd64`)).status, 404);
    assert.equal((await (await fetch(`${b}/api/v1/downloads`)).json()).error, 'endpoint_disabled');
    assert.match(await (await fetch(`${b}/`)).text(), /no-downloads-link/);
  });
});

test('CLIENT_MIN_VERSION refuses old clients, CLIENT_RECOMMENDED_VERSION shows a notice', opts, async () => {
  await withApp({ CLIENT_MIN_VERSION: '3.1.0', CLIENT_RECOMMENDED_VERSION: '3.2.0' }, async (b) => {
    const old = await fetch(`${b}/api/v1/config`, { headers: { 'X-Vanishly-Client': 'go/3.0.0' } });
    assert.equal(old.status, 426);
    assert.deepEqual(await old.json(), {
      error: 'client_outdated',
      message: 'This client is too old for this server; version 3.1.0 or newer is needed',
      minVersion: '3.1.0',
      downloadUrl: `${b}/downloads`,
    });
    const mid = await fetch(`${b}/api/v1/config`, { headers: { 'X-Vanishly-Client': 'python/3.1.9' } });
    assert.deepEqual([mid.status, mid.headers.get('x-vanishly-client-recommended')], [200, '3.2.0']);
    const now = await fetch(`${b}/api/v1/config`, { headers: { 'X-Vanishly-Client': 'python/3.2.0' } });
    assert.deepEqual([now.status, now.headers.get('x-vanishly-client-recommended')], [200, null]);
    // curl and own code send no client header: not affected.
    assert.equal((await fetch(`${b}/api/v1/config`)).status, 200);
    const page = await (await fetch(`${b}/downloads`)).text();
    assert.match(page, /needs clients of version 3\.1\.0 or newer/);
    const api = await (await fetch(`${b}/api/v1/downloads`)).json();
    assert.deepEqual([api.minVersion, api.recommendedVersion], ['3.1.0', '3.2.0']);
  });
});

test('end to end by default: /v1/share, /v1/open and the MCP tools on them are off unless switched on', opts, async () => {
  /** @param {string} b */
  const tools = async (b) => {
    const r = await fetch(`${b}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'MCP-Protocol-Version': '2025-06-18' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    return (await r.json()).result.tools.map((/** @type {any} */ t) => t.name);
  };
  await withApp({}, async (b) => {
    for (const p of ['/api/v1/share', '/api/v1/open']) {
      const r = await fetch(b + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      assert.deepEqual([r.status, (await r.json()).error], [404, 'endpoint_disabled'], p);
    }
    // MCP is on, but only shows and burns.
    assert.deepEqual(await tools(b), ['get_secret_status', 'burn_secret']);
  });
  await withApp({ ENABLE_SHARE_API: 'true', ENABLE_OPEN_API: 'true' }, async (b) => {
    const r = await fetch(`${b}/api/v1/share`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: 'hi' }) });
    assert.equal(r.status, 201);
    const o = await fetch(`${b}/api/v1/open`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ link: (await r.json()).shareUrl }) });
    assert.equal((await o.json()).secret, 'hi');
    assert.deepEqual(await tools(b), ['create_secret', 'open_secret', 'get_secret_status', 'burn_secret']);
  });
});
