// MCP server (src/mcp.js): the protocol against a stand-in API, then the
// whole app against a real Redis (REDIS_URL, or a redis-server started here).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import express from 'express';
import { flatSchema, mcpRouter, PROTOCOL_VERSIONS, receiptId } from '../src/mcp.js';

const spec = JSON.parse(readFileSync(new URL('../openapi/openapi.json', import.meta.url), 'utf8'));
const ID = 'A'.repeat(22);
const ON = { shareApi: true, receipts: true, receiptApi: true, burn: true };

/** @param {string} base @param {any} msg @param {Record<string, string>} [headers] */
async function rpc(base, msg, headers = {}) {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
    body: typeof msg === 'string' ? msg : JSON.stringify(msg),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

/** @param {any} features @returns {Promise<{ base: string, close: () => void, seen: any[] }>} */
async function fake(features = ON) {
  /** @type {any[]} */
  const seen = [];
  const api = express.Router();
  api.use(express.json());
  api.post('/v1/share', (req, res) => {
    seen.push({ method: req.method, path: req.path, body: req.body, route: `${req.baseUrl}${req.route.path}` });
    if (req.body.secret === 'bad') return void res.status(400).json({ error: 'too_short', message: 'too short' });
    res.status(201).json({ id: ID, shareUrl: `http://x/s/${ID}#key` });
  });
  api.get('/v1/receipts/:id', (req, res) => res.json({ state: 'new', id: req.params.id }));
  api.post('/v1/receipts/:id/burn', (req, res) => {
    seen.push({ body: req.body });
    res.json({ state: 'burned' });
  });
  const app = express();
  app.use('/mcp', mcpRouter({ api, spec, features, version: 't', origin: () => 'http://vanishly.test/sub', bodyLimit: 65536 }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  return { base: `http://127.0.0.1:${/** @type {any} */ (server.address()).port}`, close: () => server.close(), seen };
}

test('flatSchema merges the allOf of /v1/share into one object schema', () => {
  const s = flatSchema(spec.paths['/v1/share'].post.requestBody.content['application/json'].schema, spec);
  assert.equal(s.type, 'object');
  assert.deepEqual(s.required, ['secret']);
  for (const k of ['secret', 'passphrase', 'ttl', 'views', 'recipients', 'comment']) assert.ok(s.properties[k], k);
});

test('receiptId takes the id or the receipt link', () => {
  assert.equal(receiptId(ID), ID);
  assert.equal(receiptId(`https://ots.example.com/r/${ID}#key`), ID);
  assert.equal(receiptId(`/r/${ID}`), ID);
  for (const v of ['', 'x', `${ID}A`, `https://x/s/${ID}/../r`, 42, null]) assert.equal(receiptId(v), '', String(v));
});

test('initialize, ping, tools/list, notifications', async () => {
  const f = await fake();
  try {
    let r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    assert.equal(r.status, 200);
    assert.equal(r.body.result.protocolVersion, '2025-03-26');
    assert.deepEqual(r.body.result.capabilities, { tools: {} });
    r = await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } });
    assert.equal(r.body.result.protocolVersion, PROTOCOL_VERSIONS[0]);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', method: 'notifications/initialized' })).status, 202);
    assert.deepEqual((await rpc(f.base, { jsonrpc: '2.0', id: 3, method: 'ping' })).body.result, {});
    r = await rpc(f.base, { jsonrpc: '2.0', id: 4, method: 'tools/list' });
    assert.deepEqual(r.body.result.tools.map((/** @type {any} */ t) => t.name), ['create_secret', 'get_secret_status', 'burn_secret']);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 5, method: 'nope' })).body.error.code, -32601);
    assert.equal((await rpc(f.base, [{ jsonrpc: '2.0', id: 6, method: 'ping' }])).status, 400);
    assert.equal((await rpc(f.base, '{"jsonrpc":')).status, 400);
    assert.equal((await fetch(`${f.base}/mcp`)).status, 405);
  } finally {
    f.close();
  }
});

test('only the tools whose endpoints are on', async () => {
  const f = await fake({ shareApi: false, receipts: true, receiptApi: true, burn: false });
  try {
    const r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.deepEqual(r.body.result.tools.map((/** @type {any} */ t) => t.name), ['get_secret_status']);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: {} } })).body.error.code, -32602);
  } finally {
    f.close();
  }
});

test('tools/call runs the API endpoint and wraps its answer', async () => {
  const f = await fake();
  try {
    let r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'hunter22', ttl: 3600 } } });
    assert.equal(r.status, 200);
    assert.equal(r.body.result.isError, undefined);
    assert.equal(r.body.result.structuredContent.shareUrl, `http://x/s/${ID}#key`);
    assert.deepEqual(f.seen[0], { method: 'POST', path: '/v1/share', body: { secret: 'hunter22', ttl: 3600 }, route: '/api/v1/share' });
    // An API error is a tool error (isError), not a protocol error.
    r = await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'bad' } } });
    assert.equal(r.status, 200);
    assert.equal(r.body.result.isError, true);
    assert.match(r.body.result.content[0].text, /^too_short: /);
    r = await rpc(f.base, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_secret_status', arguments: { receipt: `https://x/r/${ID}` } } });
    assert.deepEqual(r.body.result.structuredContent, { state: 'new', id: ID });
    r = await rpc(f.base, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: ID, comment: 'leaked' } } });
    assert.equal(r.body.result.structuredContent.state, 'burned');
    assert.deepEqual(f.seen[2].body, { comment: 'leaked' });
    r = await rpc(f.base, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: '../../v1/share' } } });
    assert.equal(r.body.result.isError, true);
    assert.equal(f.seen.length, 3);
  } finally {
    f.close();
  }
});

test('a foreign Origin is refused, the own one (without the BASE_URL path) taken', async () => {
  const f = await fake();
  try {
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'ping' }, { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'ping' }, { Origin: 'http://vanishly.test' })).status, 200);
  } finally {
    f.close();
  }
});

// ------------------------------------------------------------ the whole app
const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };
/** @type {any} */ let redisProc;
/** @type {any[]} */ const servers = [];
/** @type {any[]} */ const stores = [];
let redisUrl = '';

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
  for (const s of servers) s.close();
  for (const s of stores) await s.close();
  redisProc?.kill();
});

/** @param {Record<string, string>} env */
async function vanishly(env) {
  const { createApp } = await import('../src/app.js');
  const { loadConfig } = await import('../src/config.js');
  const { Store } = await import('../src/store.js');
  const { loadTheme } = await import('../src/theme.js');
  const config = loadConfig({ REDIS_URL: redisUrl, REDIS_PREFIX: `mcp${process.pid}${servers.length}:`, ACCESS_LOG: 'false', ...env });
  const store = await Store.connect(redisUrl, config);
  stores.push(store);
  const server = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' }).listen(0, '127.0.0.1');
  servers.push(server);
  await new Promise((r) => server.once('listening', r));
  return `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
}

test('standalone: create, status and burn over MCP, like the open API', opts, async () => {
  const base = await vanishly({});
  let r = await rpc(base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'hunter22' } } });
  assert.equal(r.body.result.isError, undefined, JSON.stringify(r.body));
  const made = r.body.result.structuredContent;
  assert.match(made.shareUrl, /\/s\/[A-Za-z0-9_-]{22}#/);
  r = await rpc(base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'get_secret_status', arguments: { receipt: made.receiptUrl } } });
  assert.equal(r.body.result.structuredContent.state, 'new');
  r = await rpc(base, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: made.receiptId } } });
  assert.equal(r.body.result.structuredContent.state, 'burned');
  r = await rpc(base, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: made.receiptId } } });
  assert.equal(r.body.result.isError, true);
  // The answers of the API still work after MCP calls on the same app.
  assert.equal((await fetch(`${base}/api/v1/receipts/${made.receiptId}`)).status, 200);
});

test('ENABLE_MCP=false: /mcp is gone, the API stays', opts, async () => {
  const base = await vanishly({ ENABLE_MCP: 'false' });
  assert.equal((await rpc(base, { jsonrpc: '2.0', id: 1, method: 'ping' })).status, 404);
  const res = await fetch(`${base}/api/v1/share`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: 'hunter22' }) });
  assert.equal(res.status, 201);
});

test('ENABLE_API=false: no MCP either', opts, async () => {
  const base = await vanishly({ ENABLE_API: 'false' });
  assert.equal((await rpc(base, { jsonrpc: '2.0', id: 1, method: 'ping' })).status, 404);
});
