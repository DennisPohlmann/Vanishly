// Browser sign-in of MCP clients (MCP_OAUTH, src/oauth.js): discovery,
// registration, authorization code with PKCE and a loopback redirect, the
// token, and /mcp with it; against a real Redis with local accounts (the
// flow is the same for every AUTH_PROVIDER: it only needs a session).
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';
import { loadConfig } from './defaults.js';
import { loopbackUri, redirectMatches, s256 } from '../src/oauth.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';

const haveRedis = Boolean(process.env.REDIS_URL) || spawnSync('redis-server', ['--version']).status === 0;
const opts = { skip: !haveRedis && 'no Redis (set REDIS_URL or install redis-server)' };
const ADMIN = 'admin@example.com';
const PW = 'change-me-admin-password';
const CB = 'http://127.0.0.1:33418/callback';

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
    REDIS_PREFIX: `oauthtest${process.pid}-${n++}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ACCESS_LOG: 'false',
    BASE_URL: base,
    AUTH_PROVIDER: 'local',
    AUTH_SECRET: 'x'.repeat(40),
    LOCAL_ADMIN_USERNAME: ADMIN,
    LOCAL_ADMIN_PASSWORD: PW,
    API_TOKENS: 'true',
    AUDIT_LOG: 'true',
    AUDIT_LOG_REDIS: 'true',
    ...env,
  });
  const store = await Store.connect(redisUrl, config);
  const app = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
  handler = app;
  closers.push(async () => {
    server.closeAllConnections();
    server.close();
    await store.close();
  });
  await app.locals.users.bootstrap();
  /** @param {string} path @param {RequestInit} [init] */
  const req = (path, init = {}) => fetch(base + path, { redirect: 'manual', ...init });
  /** @param {any} msg @param {string} [token] */
  const mcp = (msg, token) =>
    req('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(msg) });
  /** A form post of the browser on this site. @param {string} path @param {Record<string, string>} fields @param {string} [cookie] */
  const form = (path, fields, cookie = '') =>
    req(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(fields).toString() });
  const login = async () => String((await form('/auth/login', { user: ADMIN, password: PW, return: '/' })).headers.get('set-cookie')).split(';')[0];
  return { base, req, mcp, form, login, app };
}

/**
 * What an MCP client does up to the consent page: register, open the
 * authorization URL. @param {Awaited<ReturnType<typeof startApp>>} a
 */
async function begin(a, { scope = 'create status burn', state = 'st-1' } = {}) {
  const reg = await a.req('/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude Code', redirect_uris: [CB] }) });
  assert.equal(reg.status, 201);
  const { client_id: clientId } = await reg.json();
  const verifier = randomBytes(32).toString('base64url');
  const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: CB.replace('33418', '50123'), code_challenge: s256(verifier), code_challenge_method: 'S256', state, scope, resource: `${a.base}/mcp` });
  const start = await a.req(`/oauth/authorize?${q}`);
  assert.equal(start.status, 303);
  const consent = String(start.headers.get('location'));
  assert.match(consent, /^\/oauth\/[\w-]{22}$/);
  return { clientId, verifier, consent, redirectUri: CB.replace('33418', '50123') };
}

test('loopback redirect URIs: only http on a loopback address, any port, same path', () => {
  assert.ok(loopbackUri('http://127.0.0.1:1234/cb'));
  assert.ok(loopbackUri('http://localhost/cb'));
  assert.ok(loopbackUri('http://[::1]:9/'));
  for (const bad of ['https://evil.example/cb', 'http://127.0.0.2/cb', 'http://127.0.0.1.evil.example/', 'http://u:p@127.0.0.1/', 'http://127.0.0.1/#x', 'javascript:alert(1)', 42]) {
    assert.equal(loopbackUri(bad), null, String(bad));
  }
  assert.equal(redirectMatches('http://127.0.0.1:5555/callback', ['http://127.0.0.1:1/callback']), true);
  assert.equal(redirectMatches('http://127.0.0.1:5555/other', ['http://127.0.0.1:1/callback']), false);
  assert.equal(redirectMatches('http://localhost:5555/callback', ['http://127.0.0.1:1/callback']), false);
});

test('MCP_OAUTH needs sign-in, API_TOKENS and MCP; off without them', () => {
  assert.throws(() => loadConfig({ MCP_OAUTH: 'true' }), /MCP_OAUTH=true needs/);
  assert.equal(loadConfig({}).mcpOauth, false);
  assert.equal(loadConfig({ AUTH_PROVIDER: 'local', AUTH_SECRET: 'x'.repeat(40), BASE_URL: 'https://ots.example.com', API_TOKENS: 'true' }).mcpOauth, true);
  assert.equal(loadConfig({ AUTH_PROVIDER: 'local', AUTH_SECRET: 'x'.repeat(40), BASE_URL: 'https://ots.example.com', API_TOKENS: 'true', MCP_OAUTH: 'false' }).mcpOauth, false);
});

test('discovery: 401 with resource metadata, then the authorization server metadata', opts, async () => {
  const a = await startApp({ ENABLE_SERVER_OPEN_MCP: 'false' });
  const r = await a.mcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('www-authenticate'), `Bearer resource_metadata="${a.base}/.well-known/oauth-protected-resource/mcp", scope="create status burn"`);
  const prm = await (await a.req('/.well-known/oauth-protected-resource/mcp')).json();
  assert.equal(prm.resource, `${a.base}/mcp`);
  assert.deepEqual(prm.authorization_servers, [a.base]);
  // Only the scopes the MCP tools need (CIS MCP 3.3.4): "read" only with open_secret (ENABLE_SERVER_OPEN_MCP).
  assert.deepEqual(prm.scopes_supported, ['create', 'status', 'burn']);
  const open = await startApp({ ENABLE_SERVER_OPEN_MCP: 'true' });
  assert.deepEqual((await (await open.req('/.well-known/oauth-protected-resource/mcp')).json()).scopes_supported, ['create', 'read', 'status', 'burn']);
  const as = await (await a.req('/.well-known/oauth-authorization-server')).json();
  assert.equal(as.issuer, a.base);
  assert.equal(as.token_endpoint, `${a.base}/oauth/token`);
  assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
  // An unknown or revoked token: 401 with invalid_token, so the client signs in again.
  const bad = await a.mcp({ jsonrpc: '2.0', id: 1, method: 'ping' }, `vnly_${'0'.repeat(16)}_${'A'.repeat(43)}`);
  assert.equal(bad.status, 401);
  assert.match(String(bad.headers.get('www-authenticate')), /error="invalid_token"/);
});

test('registration: loopback redirect URIs only, public clients only', opts, async () => {
  const a = await startApp();
  /** @param {any} body */
  const reg = (body) => a.req('/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await reg({ redirect_uris: ['https://evil.example/cb'] })).status, 400);
  assert.equal((await reg({ redirect_uris: [] })).status, 400);
  assert.equal((await reg({ redirect_uris: [CB], token_endpoint_auth_method: 'client_secret_basic' })).status, 400);
  assert.equal((await reg({ redirect_uris: [CB], application_type: 'web' })).status, 400);
  assert.equal((await (await reg({ redirect_uris: [CB], application_type: 'native' })).json()).application_type, 'native');
  const ok = await (await reg({ redirect_uris: [CB], client_name: 'x'.repeat(200) })).json();
  assert.equal(ok.client_name.length, 50);
  // A changed client_id (another redirect) is refused before any redirect.
  const [body] = ok.client_id.split('.');
  const forged = `${Buffer.from(JSON.stringify({ n: 'x', r: ['http://127.0.0.1/evil'] })).toString('base64url')}.${ok.client_id.split('.')[1]}`;
  assert.notEqual(forged.split('.')[0], body);
  const q = new URLSearchParams({ response_type: 'code', client_id: forged, redirect_uri: 'http://127.0.0.1/evil', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256' });
  assert.equal((await a.req(`/oauth/authorize?${q}`)).status, 400);
  // No PKCE: back to the client with an error.
  const q2 = new URLSearchParams({ response_type: 'code', client_id: ok.client_id, redirect_uri: CB, state: 's' });
  const r2 = await a.req(`/oauth/authorize?${q2}`);
  assert.equal(r2.status, 303);
  assert.match(String(r2.headers.get('location')), /^http:\/\/127\.0\.0\.1:33418\/callback\?error=invalid_request&.*state=s/);
});

test('the whole flow: sign-in, consent, code, token, MCP call as the person', opts, async () => {
  const a = await startApp();
  const f = await begin(a);
  // Not signed in: to the sign-in, which comes back to the consent page.
  const toLogin = await a.req(f.consent);
  assert.equal(toLogin.status, 303);
  assert.equal(toLogin.headers.get('location'), `/auth/login?return=${encodeURIComponent(f.consent)}`);
  const cookie = await a.login();
  const page = await a.req(f.consent, { headers: { Cookie: cookie } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Claude Code/);
  assert.match(html, new RegExp(`action="${f.consent}"`));
  assert.match(String(page.headers.get('content-security-policy')), /form-action 'self' http:\/\/127\.0\.0\.1:50123/);
  // Only from this site.
  const cross = await a.req(f.consent, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'cross-site', Cookie: cookie }, body: 'decision=allow' });
  assert.equal(cross.status, 403);
  const ok = await a.form(f.consent, { decision: 'allow' }, cookie);
  assert.equal(ok.status, 303);
  const cb = new URL(String(ok.headers.get('location')));
  assert.equal(cb.origin + cb.pathname, 'http://127.0.0.1:50123/callback');
  assert.equal(cb.searchParams.get('state'), 'st-1');
  assert.equal(cb.searchParams.get('iss'), a.base);
  const code = String(cb.searchParams.get('code'));
  // The request is used up.
  assert.equal((await a.form(f.consent, { decision: 'allow' }, cookie)).status, 400);

  /** @param {Record<string, string>} fields */
  const token = (fields) => a.req('/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
  const fields = { grant_type: 'authorization_code', code, client_id: f.clientId, redirect_uri: f.redirectUri, code_verifier: f.verifier };
  const tr = await token(fields);
  assert.equal(tr.status, 200);
  const t = await tr.json();
  assert.match(t.access_token, /^vnly_[0-9a-f]{16}_[\w-]{43}$/);
  assert.equal(t.token_type, 'Bearer');
  assert.equal(t.scope, 'create status burn');
  assert.ok(t.expires_in > 86000 && t.expires_in <= 86400, 'MCP_OAUTH_TOKEN_EXPIRY (1d)');
  // A code works once.
  assert.equal((await (await token(fields)).json()).error, 'invalid_grant');

  // /mcp with the token acts as the person.
  const init = await a.mcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }, t.access_token);
  assert.equal(init.status, 200);
  const call = await (await a.mcp({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'create_secret', arguments: { secret: 's3cret', ttl: 3600 } } }, t.access_token)).json();
  assert.equal(call.result.isError, undefined, JSON.stringify(call));
  assert.match(call.result.structuredContent.shareUrl, /\/s\/[\w-]{22}#/);
  // It is an ordinary API token: listed on the token page as "MCP: Claude Code".
  const list = await (await a.req('/api/v1/tokens', { headers: { Cookie: cookie, 'Sec-Fetch-Site': 'same-origin' } })).json();
  assert.equal(list.tokens[0].name, 'MCP: Claude Code');
  assert.deepEqual(list.tokens[0].scopes, ['create', 'status', 'burn']);
  // Audience /mcp: the rest of the API refuses it, and the audit log says why (CIS MCP 3.3.1, 7.2.1).
  const api = await a.req('/api/v1/me', { headers: { Authorization: `Bearer ${t.access_token}` } });
  assert.equal(api.status, 401);
  assert.equal((await api.json()).error, 'invalid_token');
  const { normalize } = await import('../src/audit.js');
  const events = (await a.app.locals.audit.query({ limit: 200 })).records.map(normalize);
  const wrong = events.find((/** @type {any} */ e) => e.type === 'api.token_audience_denied');
  assert.ok(wrong, 'api.token_audience_denied');
  assert.equal(wrong.reason, 'wrong_audience');
  const called = events.find((/** @type {any} */ e) => e.type === 'mcp.tool_called');
  assert.ok(called, 'mcp.tool_called');
  assert.equal(called.details.tool, 'create_secret');
  assert.equal(called.actor.type, 'api_token');
});

test('token request: another resource (RFC 8707) is refused', opts, async () => {
  const a = await startApp();
  const cookie = await a.login();
  const f = await begin(a);
  const code = new URL(String((await a.form(f.consent, { decision: 'allow' }, cookie)).headers.get('location'))).searchParams.get('code');
  const tr = await a.req('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: String(code), client_id: f.clientId, redirect_uri: f.redirectUri, code_verifier: f.verifier, resource: 'https://other.example/mcp' }).toString(),
  });
  assert.equal(tr.status, 400);
  assert.equal((await tr.json()).error, 'invalid_target');
});

test('wrong verifier, wrong redirect, deny: no token', opts, async () => {
  const a = await startApp();
  const cookie = await a.login();
  const f = await begin(a);
  const code = new URL(String((await a.form(f.consent, { decision: 'allow' }, cookie)).headers.get('location'))).searchParams.get('code');
  const tr = await a.req('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: String(code), client_id: f.clientId, redirect_uri: f.redirectUri, code_verifier: randomBytes(32).toString('base64url') }).toString(),
  });
  assert.equal(tr.status, 400);
  assert.equal((await tr.json()).error, 'invalid_grant');

  const g = await begin(a, { state: 'st-2' });
  const no = await a.form(g.consent, { decision: 'deny' }, cookie);
  const loc = new URL(String(no.headers.get('location')));
  assert.equal(loc.searchParams.get('error'), 'access_denied');
  assert.equal(loc.searchParams.get('state'), 'st-2');
  assert.equal(loc.searchParams.get('code'), null);
});

test('MCP_OAUTH=false: /mcp without a token as before, no OAuth endpoints', opts, async () => {
  const a = await startApp({ MCP_OAUTH: 'false' });
  assert.equal((await a.mcp({ jsonrpc: '2.0', id: 1, method: 'ping' })).status, 200);
  assert.equal((await a.req('/.well-known/oauth-authorization-server')).status, 404);
});
