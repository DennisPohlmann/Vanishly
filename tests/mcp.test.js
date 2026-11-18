// MCP server (src/mcp.js): the protocol against a stand-in API, then the
// whole app against a real Redis (REDIS_URL, or a redis-server started here).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import express from 'express';
import { flatSchema, headerValue, mcpRouter, PROTOCOL_VERSIONS, receiptId, schemaError, secretHints } from '../src/mcp.js';

const spec = JSON.parse(readFileSync(new URL('../openapi/openapi.json', import.meta.url), 'utf8'));
const ID = 'A'.repeat(22);
const NOSCOPE = 'S'.repeat(22);
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

const LEGACY = { 'MCP-Protocol-Version': '2025-06-18' };
const META = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientInfo': { name: 'test-client', version: '1.0' }, 'io.modelcontextprotocol/clientCapabilities': {} };

/**
 * A 2026-07-28 request: _meta in the body, mirrored in the headers.
 * @param {string} base @param {string} method @param {any} [params] @param {Record<string, string>} [headers] @param {any} [id]
 */
function modern(base, method, params = {}, headers = {}, id = 1) {
  const h = { 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method, ...(typeof params.name === 'string' ? { 'Mcp-Name': params.name } : {}), ...headers };
  return rpc(base, { jsonrpc: '2.0', id, method, params: { ...params, _meta: { ...META, ...params._meta } } }, h);
}

/** @param {any} features @param {any} [more] @returns {Promise<{ base: string, close: () => void, seen: any[], events: any[] }>} */
async function fake(features = ON, more = {}) {
  /** @type {any[]} */
  const seen = [];
  const api = express.Router();
  api.use(express.json());
  api.post('/v1/share', (req, res) => {
    seen.push({ method: req.method, path: req.path, body: req.body, route: `${req.baseUrl}${req.route.path}` });
    if (req.body.secret === 'bad') return void res.status(400).json({ error: 'too_short', message: 'too short' });
    res.status(201).json({ id: ID, shareUrl: `http://x/s/${ID}#key` });
  });
  api.get('/v1/receipts/:id', (req, res) => {
    if (req.params.id === NOSCOPE) return void res.status(403).json({ error: 'insufficient_scope', message: 'This token lacks the scope "status"' });
    res.json({ state: 'new', id: req.params.id });
  });
  api.post('/v1/receipts/:id/burn', (req, res) => {
    seen.push({ body: req.body });
    res.json({ state: 'burned' });
  });
  /** @type {any[]} */
  const events = [];
  const app = express();
  const ev = async (/** @type {any} */ _req, /** @type {any} */ _res, /** @type {string} */ type, /** @type {any} */ e = {}) => void events.push({ type, ...e });
  app.use('/mcp', mcpRouter({ api, spec, features, version: 't', origin: () => 'http://vanishly.test/sub', bodyLimit: 65536, ev, ...more }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  return { base: `http://127.0.0.1:${/** @type {any} */ (server.address()).port}`, close: () => server.close(), seen, events };
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

test('initialize (2025-11-25, 2025-06-18), ping, tools/list, notifications', async () => {
  const f = await fake();
  try {
    let r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    assert.equal(r.status, 200);
    assert.equal(r.body.result.protocolVersion, '2025-06-18');
    assert.deepEqual(r.body.result.capabilities, { tools: {} });
    // An older or unknown version: the newest older one this server speaks.
    for (const v of ['2025-03-26', '2024-11-05', '1999-01-01']) {
      r = await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: v } });
      assert.equal(r.body.result.protocolVersion, '2025-11-25', v);
    }
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', method: 'notifications/initialized' })).status, 202);
    assert.deepEqual((await rpc(f.base, { jsonrpc: '2.0', id: 3, method: 'ping' }, LEGACY)).body.result, {});
    r = await rpc(f.base, { jsonrpc: '2.0', id: 4, method: 'tools/list' }, LEGACY);
    assert.deepEqual(r.body.result.tools.map((/** @type {any} */ t) => t.name), ['create_secret', 'get_secret_status', 'burn_secret']);
    for (const t of r.body.result.tools) assert.equal(t.inputSchema.additionalProperties, false, t.name);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 5, method: 'nope' }, LEGACY)).body.error.code, -32601);
    assert.equal((await rpc(f.base, [{ jsonrpc: '2.0', id: 6, method: 'ping' }])).status, 400);
    assert.equal((await rpc(f.base, '{"jsonrpc":')).status, 400);
    const get = await fetch(`${f.base}/mcp`);
    assert.equal(get.status, 405);
    assert.equal((await fetch(`${f.base}/mcp`, { method: 'DELETE' })).status, 405);
    assert.equal(get.headers.get('cache-control'), 'no-store');
    assert.equal(get.headers.get('mcp-session-id'), null);
  } finally {
    f.close();
  }
});

test('MCP-Protocol-Version: required after initialize, only allowed versions (CIS 1.1)', async () => {
  const f = await fake();
  try {
    // No header: no silent fallback to 2025-03-26.
    let r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.equal(r.status, 400);
    assert.equal(r.body.error.code, -32020);
    for (const v of ['2025-03-26', '2024-11-05', 'x']) {
      r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, { 'MCP-Protocol-Version': v });
      assert.equal(r.status, 400, v);
      assert.equal(r.body.error.code, -32022, v);
      assert.deepEqual(r.body.error.data.supported, PROTOCOL_VERSIONS);
    }
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, { 'MCP-Protocol-Version': '2025-11-25' })).status, 200);
    // Refusals are audit events with the asserted version.
    const d = f.events.filter((e) => e.type === 'mcp.request_denied');
    assert.deepEqual(d.map((e) => e.reason), ['header_mismatch', 'unsupported_protocol_version', 'unsupported_protocol_version', 'unsupported_protocol_version']);
    assert.equal(d[1].details.protocol_version, '2025-03-26');
    assert.equal(d[1].details.request_id, '1');
    assert.equal(d[1].details.method, 'tools/list');
  } finally {
    f.close();
  }
  // MCP_PROTOCOL_VERSIONS=2026-07-28: no initialize at all, the error names the versions.
  const g = await fake(ON, { versions: ['2026-07-28'] });
  try {
    const r = await rpc(g.base, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
    assert.equal(r.status, 400);
    assert.equal(r.body.error.code, -32022);
    assert.match(r.body.error.message, /2026-07-28/);
    assert.equal((await rpc(g.base, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, LEGACY)).body.error.code, -32022);
    assert.equal((await modern(g.base, 'tools/list')).status, 200);
  } finally {
    g.close();
  }
});

test('2026-07-28: server/discover, _meta, resultType, caching hints, serverInfo', async () => {
  const f = await fake();
  try {
    let r = await modern(f.base, 'server/discover');
    assert.equal(r.status, 200);
    assert.equal(r.body.result.resultType, 'complete');
    assert.deepEqual(r.body.result.supportedVersions, PROTOCOL_VERSIONS);
    assert.deepEqual(r.body.result.capabilities, { tools: {} });
    assert.equal(r.body.result.cacheScope, 'public');
    assert.ok(r.body.result.ttlMs >= 0);
    assert.deepEqual(r.body.result._meta['io.modelcontextprotocol/serverInfo'], { name: 'vanishly', title: 'Vanishly', version: 't' });
    r = await modern(f.base, 'tools/list');
    assert.equal(r.body.result.resultType, 'complete');
    assert.equal(r.body.result.tools.length, 3);
    assert.equal(r.body.result.cacheScope, 'public');
    r = await modern(f.base, 'tools/call', { name: 'get_secret_status', arguments: { receipt: ID } });
    assert.equal(r.body.result.resultType, 'complete');
    assert.equal(r.body.result.structuredContent.state, 'new');
    // ping is gone; an unknown method is a 404 with -32601.
    r = await modern(f.base, 'ping');
    assert.equal(r.status, 404);
    assert.equal(r.body.error.code, -32601);
    // The audit log has the claimed client and version of every request.
    const call = f.events.find((e) => e.type === 'mcp.tool_called');
    assert.equal(call.details.tool, 'get_secret_status');
    assert.equal(call.details.scope, 'status');
    assert.equal(call.details.protocol_version, '2026-07-28');
    assert.deepEqual(call.details.client, { name: 'test-client', version: '1.0' });
    assert.ok(f.events.some((e) => e.type === 'mcp.request' && e.details.method === 'server/discover'));
  } finally {
    f.close();
  }
});

test('2026-07-28: headers must be there and match the body (CIS 2.4)', async () => {
  const f = await fake();
  try {
    const call = { name: 'get_secret_status', arguments: { receipt: ID } };
    /** @param {Promise<{ status: number, body: any }>} p @param {number} code */
    const refused = async (p, code) => {
      const r = await p;
      assert.equal(r.status, 400, JSON.stringify(r.body));
      assert.equal(r.body.error.code, code);
    };
    await refused(modern(f.base, 'tools/list', {}, { 'MCP-Protocol-Version': '2025-06-18' }), -32020);
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: META } }, { 'Mcp-Method': 'tools/list' }), -32020);
    await refused(modern(f.base, 'tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } }), -32022);
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, { 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/list' }), -32602);
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } }, { 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/list' }), -32602);
    await refused(modern(f.base, 'tools/list', {}, { 'Mcp-Method': 'tools/call' }), -32020);
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: META } }, { 'MCP-Protocol-Version': '2026-07-28' }), -32020);
    await refused(modern(f.base, 'tools/call', call, { 'Mcp-Name': 'burn_secret' }), -32020);
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { ...call, _meta: META } }, { 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call' }), -32020);
    // An older client's header that disagrees is refused too.
    await refused(rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, { ...LEGACY, 'Mcp-Method': 'ping' }), -32020);
    // Base64 sentinel form of Mcp-Name.
    const r = await modern(f.base, 'tools/call', call, { 'Mcp-Name': `=?base64?${Buffer.from('get_secret_status').toString('base64')}?=` });
    assert.equal(r.status, 200);
    assert.equal(f.events.filter((e) => e.type === 'mcp.request_denied').length, 10);
  } finally {
    f.close();
  }
});

test('headerValue: plain ASCII or the Base64 sentinel form', () => {
  assert.equal(headerValue('get_weather'), 'get_weather');
  assert.equal(headerValue('=?base64?SGVsbG8sIOS4lueVjA==?='), 'Hello, 世界');
  assert.equal(headerValue(`a${String.fromCharCode(1)}b`), null);
  assert.equal(headerValue('café'), null);
});

test('request ids: a string or an integer, never null (CIS 7.1.2)', async () => {
  const f = await fake();
  try {
    for (const id of [null, 1.5, true, { a: 1 }, [1]]) {
      const r = await rpc(f.base, { jsonrpc: '2.0', id, method: 'tools/list' }, LEGACY);
      assert.equal(r.status, 400, JSON.stringify(id));
      assert.equal(r.body.error.code, -32600);
      assert.equal(r.body.id, null);
    }
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 'abc', method: 'tools/list' }, LEGACY)).body.id, 'abc');
    assert.equal(f.events.filter((e) => e.reason === 'invalid_request_id').length, 5);
  } finally {
    f.close();
  }
});

test('only the tools whose endpoints are on', async () => {
  const f = await fake({ shareApi: false, receipts: true, receiptApi: true, burn: false });
  try {
    const r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, LEGACY);
    assert.deepEqual(r.body.result.tools.map((/** @type {any} */ t) => t.name), ['get_secret_status']);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: {} } }, LEGACY)).body.error.code, -32602);
  } finally {
    f.close();
  }
});

test('tools/call runs the API endpoint and wraps its answer', async () => {
  const f = await fake();
  try {
    let r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'hunter22', ttl: 3600 } } }, LEGACY);
    assert.equal(r.status, 200);
    assert.equal(r.body.result.isError, undefined);
    assert.equal(r.body.result.structuredContent.shareUrl, `http://x/s/${ID}#key`);
    assert.deepEqual(f.seen[0], { method: 'POST', path: '/v1/share', body: { secret: 'hunter22', ttl: 3600 }, route: '/api/v1/share' });
    // An API error is a tool error (isError), not a protocol error.
    r = await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'bad' } } }, LEGACY);
    assert.equal(r.status, 200);
    assert.equal(r.body.result.isError, true);
    assert.match(r.body.result.content[0].text, /^too_short: /);
    r = await rpc(f.base, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_secret_status', arguments: { receipt: `https://x/r/${ID}` } } }, LEGACY);
    assert.deepEqual(r.body.result.structuredContent, { state: 'new', id: ID });
    r = await rpc(f.base, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: ID, comment: 'leaked' } } }, LEGACY);
    assert.equal(r.body.result.structuredContent.state, 'burned');
    assert.deepEqual(f.seen[2].body, { comment: 'leaked' });
    r = await rpc(f.base, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: '../../v1/share' } } }, LEGACY);
    assert.equal(r.body.result.isError, true);
    assert.equal(f.seen.length, 3);
  } finally {
    f.close();
  }
});

test('tools/call: arguments checked against the input schema before the API runs (CIS 5.1.1)', async () => {
  const f = await fake();
  try {
    /** @param {any} args @param {RegExp} text */
    const toolError = async (args, text, name = 'create_secret') => {
      const r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, LEGACY);
      assert.equal(r.status, 200);
      assert.equal(r.body.result.isError, true, JSON.stringify(args));
      assert.match(r.body.result.content[0].text, text);
    };
    await toolError({}, /^invalid_arguments: arguments\.secret is required/);
    await toolError({ secret: 'x', ttl: '3600' }, /arguments\.ttl must be an integer/);
    await toolError({ secret: 'x', ttl: 1.5 }, /arguments\.ttl must be an integer/);
    await toolError({ secret: 'x', ttl: 10 }, /arguments\.ttl must be at least 60/);
    await toolError({ secret: 'x', recipients: ['a@example.com', 7] }, /arguments\.recipients\[1\] must be a string/);
    await toolError({ secret: 'x', evil: true }, /arguments\.evil is not a known argument/);
    await toolError({ receipt: ID, comment: 'x'.repeat(2001) }, /at most 2000 characters/, 'burn_secret');
    assert.equal(f.seen.length, 0, 'the API never ran');
    // arguments that are no object: a protocol error (malformed CallToolRequest).
    const r = await rpc(f.base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: ['x'] } }, LEGACY);
    assert.equal(r.body.error.code, -32602);
    assert.ok(f.events.filter((e) => e.type === 'mcp.tool_called').every((e) => e.outcome === 'denied'));
  } finally {
    f.close();
  }
});

test('secretHints: the kinds of extra access data, never the text', () => {
  assert.deepEqual(secretHints('hunter22'), []);
  assert.deepEqual(secretHints('correct horse battery staple'), []);
  assert.deepEqual(secretHints('Tr0ub4dor&3!'), []);
  assert.deepEqual(secretHints('https://db.example.com/admin'), ['url']);
  assert.deepEqual(secretHints('admin@example.com'), ['email']);
  assert.deepEqual(secretHints('admin:hunter22'), ['pair']);
  assert.deepEqual(secretHints('User: admin'), ['user']);
  assert.deepEqual(secretHints('db01.corp.example.com'), ['host']);
  assert.deepEqual(secretHints('203.0.113.10'), ['host']);
  assert.deepEqual(secretHints('one\ntwo'), ['lines']);
  assert.deepEqual(secretHints('Login = root\nhunter22 @ srv.example.org'), ['user', 'host', 'lines']);
});

test('CONFIRM_CHECKBOX: the person confirms every create_secret by elicitation; the model cannot', async () => {
  const f = await fake(ON, { confirm: () => ({ rule: 'Only one password.', t: (/** @type {string} */ k) => `<${k}>` }) });
  const EL = { 'io.modelcontextprotocol/clientCapabilities': { elicitation: {} } };
  const call = (/** @type {any} */ params, id = 1) => modern(f.base, 'tools/call', { name: 'create_secret', ...params }, {}, id);
  try {
    // "confirmed" is no argument of the tool: the model cannot confirm.
    const listed = (await modern(f.base, 'tools/list')).body.result.tools.find((/** @type {any} */ t) => t.name === 'create_secret');
    assert.equal(listed.inputSchema.properties.confirmed, undefined);
    let r = await call({ arguments: { secret: 'x', confirmed: true }, _meta: EL });
    assert.match(r.body.result.content[0].text, /^invalid_arguments: arguments\.confirmed is not a known argument/);
    // No elicitation, or an older protocol: refused, nothing stored (fail closed).
    r = await call({ arguments: { secret: 'hunter22' } });
    assert.match(r.body.result.content[0].text, /^confirmation_unavailable: /);
    r = await call({ arguments: { secret: 'hunter22' }, _meta: { 'io.modelcontextprotocol/clientCapabilities': { elicitation: { url: {} } } } });
    assert.match(r.body.result.content[0].text, /^confirmation_unavailable: /);
    r = await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'hunter22' }, inputResponses: { confirm: { action: 'accept', content: { confirm: true } } } } }, LEGACY);
    assert.match(r.body.result.content[0].text, /^confirmation_unavailable: /);
    // First call: the question, with the warnings by kind and never the secret.
    const secret = 'admin:Sup3rS3cret https://db.example.com';
    r = await call({ arguments: { secret }, _meta: EL });
    assert.equal(r.body.result.resultType, 'input_required');
    const q = r.body.result.inputRequests.confirm;
    assert.equal(q.method, 'elicitation/create');
    assert.equal(q.params.mode, 'form');
    assert.equal(q.params.message, '<mcp.warn>\n\nOnly one password.');
    assert.deepEqual(q.params.requestedSchema.properties.confirm, { type: 'boolean', title: '<mcp.confirm>', description: 'Only one password.' });
    assert.ok(!JSON.stringify(r.body).includes('Sup3rS3cret'));
    // Declined, cancelled, or no real yes: nothing stored.
    for (const answer of [{ action: 'decline' }, { action: 'cancel' }]) {
      r = await call({ arguments: { secret }, inputResponses: { confirm: answer }, _meta: EL }, 2);
      assert.match(r.body.result.content[0].text, /^confirmation_declined: /);
    }
    r = await call({ arguments: { secret }, inputResponses: { confirm: { action: 'accept', content: { confirm: false } } }, _meta: EL }, 3);
    assert.equal(r.body.result.resultType, 'input_required');
    assert.equal(f.seen.length, 0);
    // The retry with the person's yes: stored, with "confirmed": true set by the server.
    r = await call({ arguments: { secret }, inputResponses: { confirm: { action: 'accept', content: { confirm: true } } }, _meta: EL }, 4);
    assert.equal(r.body.result.resultType, 'complete');
    assert.deepEqual(f.seen[0].body, { secret, confirmed: true });
    const calls = f.events.filter((e) => e.type === 'mcp.tool_called');
    assert.equal(calls.find((e) => e.details.confirmation === 'requested').details.warned, true);
    assert.equal(calls.at(-1).details.confirmation, 'accepted');
  } finally {
    f.close();
  }
});

test('schemaError covers the keywords of the tool schemas', () => {
  const s = { type: 'object', properties: { a: { type: 'string', enum: ['x'] }, n: { type: 'number', maximum: 2 }, l: { type: 'array', maxItems: 1 } }, additionalProperties: false };
  assert.equal(schemaError({ a: 'x', n: 2, l: [1] }, s), '');
  assert.match(schemaError({ a: 'y' }, s), /one of x/);
  assert.match(schemaError({ n: 3 }, s), /at most 2/);
  assert.match(schemaError({ l: [1, 2] }, s), /at most 1 entries/);
  assert.match(schemaError(null, s), /must be an object/);
});

test('MCP_OAUTH: a missing scope is a 403 with an insufficient_scope challenge (step-up, CIS 3.3.4)', async () => {
  const msg = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_secret_status', arguments: { receipt: NOSCOPE } } };
  const f = await fake(ON, { challenge: (/** @type {any} */ _req, /** @type {string} */ scope) => `Bearer error="insufficient_scope", scope="${scope}"` });
  try {
    const r = await rpc(f.base, msg, LEGACY);
    assert.equal(r.status, 403);
    assert.equal(r.body.id, 1);
    assert.ok(r.body.error);
  } finally {
    f.close();
  }
  // Without MCP_OAUTH there is nobody to sign in with: a tool error.
  const g = await fake();
  try {
    const r = await rpc(g.base, msg, LEGACY);
    assert.equal(r.status, 200);
    assert.match(r.body.result.content[0].text, /^insufficient_scope: /);
  } finally {
    g.close();
  }
});

test('a foreign Origin is refused, the own one (without the BASE_URL path) taken', async () => {
  const f = await fake();
  try {
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'ping' }, { ...LEGACY, Origin: 'https://evil.example' })).status, 403);
    assert.equal((await rpc(f.base, { jsonrpc: '2.0', id: 1, method: 'ping' }, { ...LEGACY, Origin: 'http://vanishly.test' })).status, 200);
    // The refusal is a security event (CIS 2.5).
    assert.deepEqual(f.events.map((e) => [e.type, e.reason]), [['mcp.request_denied', 'origin_not_allowed']]);
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
  let r = await rpc(base, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 'hunter22' } } }, LEGACY);
  assert.equal(r.body.result.isError, undefined, JSON.stringify(r.body));
  const made = r.body.result.structuredContent;
  assert.match(made.shareUrl, /\/s\/[A-Za-z0-9_-]{22}#/);
  r = await rpc(base, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'get_secret_status', arguments: { receipt: made.receiptUrl } } }, LEGACY);
  assert.equal(r.body.result.structuredContent.state, 'new');
  r = await rpc(base, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: made.receiptId } } }, LEGACY);
  assert.equal(r.body.result.structuredContent.state, 'burned');
  r = await rpc(base, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'burn_secret', arguments: { receipt: made.receiptId } } }, LEGACY);
  assert.equal(r.body.result.isError, true);
  // The answers of the API still work after MCP calls on the same app.
  assert.equal((await fetch(`${base}/api/v1/receipts/${made.receiptId}`)).status, 200);
});

test('CONFIRM_CHECKBOX over MCP: the rule of the form in the question, the API gets the yes', opts, async () => {
  const base = await vanishly({ CONFIRM_CHECKBOX: 'true', CONFIRM_TEXT_DE: 'Nur ein Passwort.' });
  const _meta = { 'io.modelcontextprotocol/clientCapabilities': { elicitation: { form: {} } } };
  const params = { name: 'create_secret', arguments: { secret: 'root@srv.example.com' }, _meta };
  let r = await modern(base, 'tools/call', params, { 'Accept-Language': 'de' });
  assert.equal(r.body.result.inputRequests.confirm.params.message, 'Achtung: Das Geheimnis scheint eine E-Mail-Adresse zu enthalten. Teilen Sie nur ein Passwort pro Link.\n\nNur ein Passwort.');
  r = await modern(base, 'tools/call', { ...params, inputResponses: { confirm: { action: 'accept', content: { confirm: true } } } }, { 'Accept-Language': 'de' }, 2);
  assert.equal(r.body.result.isError, undefined, JSON.stringify(r.body));
  assert.match(r.body.result.structuredContent.shareUrl, /\/s\/[A-Za-z0-9_-]{22}#/);
});

test('ENABLE_MCP=false: /mcp is gone, the API stays', opts, async () => {
  const base = await vanishly({ ENABLE_MCP: 'false' });
  assert.equal((await rpc(base, { jsonrpc: '2.0', id: 1, method: 'ping' }, LEGACY)).status, 404);
  const res = await fetch(`${base}/api/v1/share`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: 'hunter22' }) });
  assert.equal(res.status, 201);
});

test('ENABLE_API=false: no MCP either', opts, async () => {
  const base = await vanishly({ ENABLE_API: 'false' });
  assert.equal((await rpc(base, { jsonrpc: '2.0', id: 1, method: 'ping' }, LEGACY)).status, 404);
});
