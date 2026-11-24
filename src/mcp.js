// Vanishly - MCP server (ENABLE_MCP) at /mcp: AI clients (Claude, Copilot,
// Cursor, ...) create secrets and check or burn them. Streamable HTTP without
// sessions or streams: every POST is one JSON-RPC message, answered as JSON.
// Each tool runs the matching API endpoint in this process, so sign-in, API
// tokens and their scopes, ENABLE_* switches, rate limits and the audit log
// apply exactly as for a script.
//
// Protocol versions (MCP_PROTOCOL_VERSIONS, the operator's allow list):
//   2026-07-28              stateless: version, client and capabilities in each
//                           request's _meta, mirrored in the MCP-Protocol-Version,
//                           Mcp-Method and Mcp-Name headers; server/discover
//   2025-11-25, 2025-06-18  initialize handshake, then the MCP-Protocol-Version header
// Older ones (2025-03-26, 2024-11-05: no version header) are not served
// (CIS MCP Server Benchmark 1.1). Hardening notes: docs/SECURITY.md.

import express from 'express';
import { sanitizeText } from './audit.js';
import { MCP_VERSIONS } from './config.js';

/** Every version this server can speak, newest first. */
export const PROTOCOL_VERSIONS = MCP_VERSIONS;
export const MODERN = '2026-07-28';
export const LEGACY = MCP_VERSIONS.filter((v) => v !== MODERN);

const META = 'io.modelcontextprotocol/';
// MCP error codes (2026-07-28 basic/index#error-codes).
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_VERSION = -32022;
// Freshness hint of server/discover and tools/list: the tool set changes only with a restart.
const TTL_MS = 300000;
// A header value as RFC 9110 allows it unencoded: visible ASCII, inner spaces and tabs.
const PLAIN_HEADER = /^[\x21-\x7e](?:[\x20-\x7e\t]*[\x21-\x7e])?$/;
const SENTINEL = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/;

/**
 * A schema of the OpenAPI document as one plain object schema: $ref resolved,
 * allOf merged (MCP clients expect "type": "object" at the top).
 * @param {any} s @param {any} spec
 * @returns {any}
 */
export function flatSchema(s, spec) {
  if (s?.$ref) return flatSchema(s.$ref.split('/').slice(1).reduce((o, k) => o[k], spec), spec);
  if (!s?.allOf) return s;
  const parts = s.allOf.map((/** @type {any} */ p) => flatSchema(p, spec));
  return {
    type: 'object',
    properties: Object.assign({}, ...parts.map((/** @type {any} */ p) => p.properties || {})),
    required: parts.flatMap((/** @type {any} */ p) => p.required || []),
  };
}

/**
 * Checks a value against the JSON Schema keywords the tool schemas use
 * (type, properties, required, additionalProperties: false, enum,
 * min/maxLength, minimum/maximum, items, maxItems). Other keywords (format)
 * are left to the API. The schemas are this server's own, so no $ref and no
 * depth limit is needed.
 * @param {any} v @param {any} s @param {string} [at]
 * @returns {string} the first problem, '' when it fits
 */
export function schemaError(v, s, at = 'arguments') {
  const t = s.type;
  const is =
    t === 'object' ? v !== null && typeof v === 'object' && !Array.isArray(v)
    : t === 'array' ? Array.isArray(v)
    : t === 'integer' ? Number.isSafeInteger(v)
    : t === 'number' ? typeof v === 'number' && Number.isFinite(v)
    : t === undefined || typeof v === t;
  if (!is) return `${at} must be ${t === 'integer' ? 'an integer' : t === 'object' || t === 'array' ? `an ${t}` : `a ${t}`}`;
  if (s.enum && !s.enum.includes(v)) return `${at} must be one of ${s.enum.join(', ')}`;
  if (typeof v === 'string') {
    if (s.minLength !== undefined && v.length < s.minLength) return `${at} must have at least ${s.minLength} characters`;
    if (s.maxLength !== undefined && v.length > s.maxLength) return `${at} must have at most ${s.maxLength} characters`;
    if (s.pattern !== undefined && !new RegExp(s.pattern).test(v)) return `${at} has characters it may not have`;
  }
  if (typeof v === 'number') {
    if (s.minimum !== undefined && v < s.minimum) return `${at} must be at least ${s.minimum}`;
    if (s.maximum !== undefined && v > s.maximum) return `${at} must be at most ${s.maximum}`;
  }
  if (Array.isArray(v)) {
    if (s.maxItems !== undefined && v.length > s.maxItems) return `${at} must have at most ${s.maxItems} entries`;
    for (let i = 0; s.items && i < v.length; i++) {
      const e = schemaError(v[i], s.items, `${at}[${i}]`);
      if (e) return e;
    }
  }
  if (t === 'object') {
    for (const k of s.required || []) if (!(k in v)) return `${at}.${k} is required`;
    for (const [k, x] of Object.entries(v)) {
      const p = s.properties?.[k];
      if (!p) {
        if (s.additionalProperties === false) return `${at}.${k} is not a known argument`;
        continue;
      }
      const e = schemaError(x, p, `${at}.${k}`);
      if (e) return e;
    }
  }
  return '';
}

// A secret's ref from list_my_secrets (audit ref): a path segment, nothing else.
const REF = { type: 'string', maxLength: 64, pattern: '^[A-Za-z0-9_-]+$', description: 'The ref of the secret, from list_my_secrets' };

const RECEIPT = {
  type: 'string',
  maxLength: 2000,
  description: 'The receipt: its id or its link (receiptUrl from create_secret, …/r/<id>)',
};

/**
 * The receipt id of "abc…" or "https://host/r/abc…#key".
 * @param {unknown} v
 */
export function receiptId(v) {
  const m = typeof v === 'string' ? /(?:^|\/r\/)([A-Za-z0-9_-]{22})(?:[#?].*)?$/.exec(v.trim()) : null;
  return m ? m[1] : '';
}

/**
 * Hints that a secret holds more than one password (CONFIRM_CHECKBOX): the
 * kinds found, never the matched text. Heuristics; they only warn.
 * @param {string} v
 * @returns {('url' | 'email' | 'user' | 'pair' | 'host' | 'lines')[]}
 */
export function secretHints(v) {
  const url = /(?<![a-z0-9]|[a-z0-9][+.-])[a-z][a-z0-9+.-]*:\/\/\S+|\bwww\.\S+/gi;
  const email = /(?<![^\s@:])[^\s@:]+@[^\s@]+\.[a-z]{2,}/gi;
  const rest = v.replace(url, ' ').replace(email, ' ');
  /** @type {('url' | 'email' | 'user' | 'pair' | 'host' | 'lines')[]} */
  const found = [];
  if (url.test(v)) found.push('url');
  if (email.test(v)) found.push('email');
  if (/\b(?:user(?:name)?|login|benutzer(?:name)?|account|konto|uid)\s*[:=]/i.test(v)) found.push('user');
  if (/(?:^|\s)[\w.-]{1,64}:[^\s/:]\S*/.test(rest)) found.push('pair');
  if (/(?<![a-z0-9]|[a-z0-9][.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b/i.test(rest)) found.push('host');
  if (v.split(/\r?\n/).filter((l) => l.trim()).length > 1) found.push('lines');
  return found;
}

/**
 * @typedef {{ shareApi: boolean, openApi?: boolean, receipts: boolean, receiptApi: boolean, burn: boolean, mySecrets?: boolean, mySecretDetails?: boolean }} ToolFeatures
 *   shareApi / openApi: ENABLE_SERVER_CREATE / ENABLE_SERVER_OPEN, the same switches as for the API;
 *   mySecrets / mySecretDetails: MY_SECRETS / SECRET_DETAILS as the app has them on
 */

/**
 * The API token scopes the MCP tools of these features need: create
 * (create_secret), read (open_secret), status (get_secret_status,
 * list_my_secrets), burn (burn_secret, burn_my_secret).
 * @param {ToolFeatures} f
 */
export function toolScopes(f) {
  const receipts = f.receipts && f.receiptApi;
  return [
    ...(f.shareApi ? ['create'] : []),
    ...(f.openApi ? ['read'] : []),
    ...(receipts || f.mySecrets ? ['status'] : []),
    ...(f.burn && (receipts || f.mySecretDetails) ? ['burn'] : []),
  ];
}

/**
 * A header that mirrors a body value (Mcp-Name): the value, decoded from the
 * Base64 sentinel form; null when it has characters a header may not carry.
 * @param {string} h
 */
export function headerValue(h) {
  const m = SENTINEL.exec(h);
  if (m) return Buffer.from(m[1], 'base64').toString('utf8');
  return PLAIN_HEADER.test(h) ? h : null;
}

/**
 * @param {{
 *   api: import('express').Router,
 *   spec: any,
 *   features: ToolFeatures,
 *   version: string,
 *   origin: (req: import('express').Request) => string,
 *   bodyLimit: number,
 *   versions?: string[],
 *   ev?: (req: import('express').Request, res: import('express').Response, type: string, e?: any) => Promise<void>,
 *   challenge?: (req: import('express').Request, scope: string) => string,
 *   confirm?: (res: import('express').Response) => { rule: string, t: (key: string) => string },
 * }} o
 *   versions: MCP_PROTOCOL_VERSIONS (default all); ev: the audit log;
 *   challenge: with MCP_OAUTH the WWW-Authenticate value for a missing scope (step-up sign-in);
 *   confirm: with CONFIRM_CHECKBOX the rule and the texts, in the language of the request:
 *   create_secret then asks the person by elicitation every time
 */
export function mcpRouter({ api, spec, features, version, origin, bodyLimit, versions = PROTOCOL_VERSIONS, ev = async () => {}, challenge, confirm }) {
  const legacy = versions.filter((v) => LEGACY.includes(v));
  const serverInfo = { name: 'vanishly', title: 'Vanishly', version };
  const instructions =
    'Share secrets as one-time links: create_secret returns shareUrl for the recipient and receiptUrl for you; check or burn a secret with its receipt, or list your own secrets with list_my_secrets and burn one by its ref.';

  /** @type {{ name: string, description: string, inputSchema: any, scope: string, run: (a: any) => [string, string, any] }[]} */
  const tools = [];
  if (features.shareApi) {
    // "confirmed" never comes from the model: with CONFIRM_CHECKBOX the person confirms by elicitation.
    const { confirmed: _, ...share } = flatSchema(spec.paths['/v1/share'].post.requestBody.content['application/json'].schema, spec).properties;
    tools.push({
      name: 'create_secret',
      description:
        'Store a secret (password, key, note) on this Vanishly server and get a one-time link (shareUrl) to send to the recipient, and a receipt link (receiptUrl) to check or burn it. The secret is encrypted on the server; the key is only in the links.',
      inputSchema: { ...flatSchema(spec.paths['/v1/share'].post.requestBody.content['application/json'].schema, spec), properties: share, additionalProperties: false },
      scope: 'create',
      run: (a) => ['POST', '/v1/share', a],
    });
  }
  if (features.openApi) {
    const schema = flatSchema(spec.paths['/v1/open'].post.requestBody.content['application/json'].schema, spec);
    tools.push({
      name: 'open_secret',
      description:
        'Open a secret by its link (…/s/<id>#<key>) and return its text. Uses up one view: a one-time secret is gone afterwards. The secret is decrypted on the server and passes through this AI client.',
      inputSchema: { ...schema, additionalProperties: false },
      scope: 'read',
      run: (a) => ['POST', '/v1/open', a],
    });
  }
  if (features.mySecrets) {
    tools.push({
      name: 'list_my_secrets',
      description:
        'The secrets of the signed-in person: the ones they created and the ones for them or their groups, newest first, with state (open, opened, expired, burned), recipients, comment and expiry. Never the content. Each has a ref for burn_my_secret.',
      inputSchema: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['open', 'partly_opened', 'opened', 'expired', 'burned'], description: 'Only secrets in this state' },
          limit: { type: 'integer', minimum: 1, maximum: 500, description: 'At most this many' },
        },
        additionalProperties: false,
      },
      scope: 'status',
      run: (a) => ['GET', `/v1/me/secrets${a.status || a.limit ? `?${new URLSearchParams({ ...(a.status ? { status: a.status } : {}), ...(a.limit ? { limit: String(a.limit) } : {}) })}` : ''}`, {}],
    });
    if (features.mySecretDetails && features.burn) {
      tools.push({
        name: 'burn_my_secret',
        description: 'Destroy a secret the signed-in person created, by its ref from list_my_secrets, before it is opened. Cannot be undone.',
        inputSchema: {
          type: 'object',
          properties: { ref: REF, comment: { type: 'string', maxLength: 2000, description: 'Why (goes into the audit log)' } },
          required: ['ref'],
          additionalProperties: false,
        },
        scope: 'burn',
        run: (a) => ['POST', `/v1/me/secrets/${a.ref}/burn`, a.comment === undefined ? {} : { comment: a.comment }],
      });
    }
  }
  if (features.receipts && features.receiptApi) {
    tools.push({
      name: 'get_secret_status',
      description: 'The status of a secret by its receipt: new, viewed, burned or expired, with views left and expiry. Never shows the secret.',
      inputSchema: { type: 'object', properties: { receipt: RECEIPT }, required: ['receipt'], additionalProperties: false },
      scope: 'status',
      run: (a) => ['GET', `/v1/receipts/${receiptId(a.receipt)}`, {}],
    });
    if (features.burn) {
      tools.push({
        name: 'burn_secret',
        description: 'Destroy a secret before it is opened, by its receipt. Cannot be undone.',
        inputSchema: {
          type: 'object',
          properties: { receipt: RECEIPT, comment: { type: 'string', maxLength: 2000, description: 'Why (goes into the audit log)' } },
          required: ['receipt'],
          additionalProperties: false,
        },
        scope: 'burn',
        run: (a) => ['POST', `/v1/receipts/${receiptId(a.receipt)}/burn`, a.comment === undefined ? {} : { comment: a.comment }],
      });
    }
  }
  const listed = tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema }));

  /**
   * Runs one API endpoint for this request and returns its answer instead of
   * sending it. The request keeps its headers (Authorization, X-Audit-Comment,
   * traceparent), its address and its signed-in user.
   * @param {import('express').Request} req @param {import('express').Response} res
   * @param {string} method @param {string} url @param {any} body
   * @returns {Promise<{ status: number, body: any }>}
   */
  const call = (req, res, method, url, body) =>
    new Promise((resolve, reject) => {
      const json = res.json;
      res.json = (b) => {
        res.json = json;
        // For the audit event "api.token_used" (sent when the MCP answer finishes).
        res.locals.apiStatus = res.statusCode;
        resolve({ status: res.statusCode, body: b });
        res.statusCode = 200;
        return res;
      };
      // The route as the audit log shows it: /api/v1/...
      Object.assign(req, { method, url, body, baseUrl: '/api' });
      api(req, res, (/** @type {any} */ err) => {
        res.json = json;
        reject(err || new Error(`no API route for ${method} ${url}`));
      });
    });

  /** @param {any} id @param {any} result */
  const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
  /** @param {any} id @param {number} code @param {string} message @param {any} [data] */
  const fail = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id === undefined ? {} : { id }), error: { code, message, ...(data ? { data } : {}) } });

  /** What the audit log keeps of a request: its id, version and client (as they claim). @param {any} m @param {string} pv */
  const about = (m, pv) => {
    const meta = m?.params?._meta;
    const ci = meta && typeof meta === 'object' ? meta[`${META}clientInfo`] : m?.method === 'initialize' ? m?.params?.clientInfo : undefined;
    return {
      method: sanitizeText(m?.method, 100),
      request_id: typeof m?.id === 'string' || typeof m?.id === 'number' ? sanitizeText(String(m.id), 100) : undefined,
      protocol_version: sanitizeText(pv, 20),
      client: ci && typeof ci === 'object' ? { name: sanitizeText(ci.name, 100), version: sanitizeText(ci.version, 50) } : undefined,
    };
  };
  /**
   * A refused message: HTTP status, JSON-RPC error and the audit event "mcp.request_denied".
   * @param {import('express').Request} req @param {import('express').Response} res
   * @param {number} status @param {any} m @param {string} pv @param {string} reason @param {any} body
   */
  const deny = async (req, res, status, m, pv, reason, body) => {
    await ev(req, res, 'mcp.request_denied', { outcome: 'denied', reason, details: about(m, pv), http: { method: 'POST', route: '/mcp', status } });
    res.status(status).json(body);
  };

  const router = express.Router();
  // Answers depend on the caller: never kept by a shared cache (CIS 10.1).
  router.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  // Streamable HTTP: POST only; no GET stream, no sessions to DELETE (CIS 5.2.3).
  router.all('/', (req, res, next) => (req.method === 'POST' ? next() : void res.set('Allow', 'POST').status(405).json(fail(null, -32000, 'Use POST'))));
  // Against DNS rebinding and other sites: a browser's Origin must be this server (CIS 2.5).
  router.post('/', async (req, res, next) => {
    const o = req.get('origin');
    if (o && o !== new URL(origin(req)).origin) return void (await deny(req, res, 403, null, '', 'origin_not_allowed', fail(undefined, -32000, 'Origin not allowed')));
    next();
  });
  router.post('/', express.json({ limit: bodyLimit }), async (req, res) => {
    const m = req.body;
    if (!m || typeof m !== 'object' || Array.isArray(m) || m.jsonrpc !== '2.0' || typeof m.method !== 'string') {
      return void (await deny(req, res, 400, null, '', 'invalid_request', fail(null, -32600, 'One JSON-RPC 2.0 request or notification per POST')));
    }
    const h = req.get('mcp-protocol-version');
    // A notification of the client: nothing to process, nothing to answer.
    if (!('id' in m)) return void res.status(202).end();
    // A request id is a string or an integer, never null (CIS 7.1.2).
    if (!(typeof m.id === 'string' || Number.isSafeInteger(m.id))) {
      return void (await deny(req, res, 400, m, h || '', 'invalid_request_id', fail(null, -32600, 'The request id must be a string or an integer, not null')));
    }
    const id = m.id;
    const p = m.params && typeof m.params === 'object' && !Array.isArray(m.params) ? m.params : {};
    const meta = p._meta && typeof p._meta === 'object' && !Array.isArray(p._meta) ? p._meta : null;
    const pv = meta?.[`${META}protocolVersion`];
    // initialize starts the handshake of 2025-11-25 and earlier; per-request _meta (or the header) is 2026-07-28.
    const modern = m.method !== 'initialize' && (pv !== undefined || h === MODERN || m.method === 'server/discover');
    const asserted = typeof pv === 'string' ? pv : h || '';

    // ------------------------------------------------ version and headers (CIS 1.1, 2.4)
    if (m.method !== 'initialize') {
      const allowed = modern ? (versions.includes(MODERN) ? [MODERN] : []) : legacy;
      if (asserted && !allowed.includes(asserted)) {
        return void (await deny(req, res, 400, m, asserted, 'unsupported_protocol_version', fail(id, UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: versions, requested: sanitizeText(asserted, 50) })));
      }
      if (!h) return void (await deny(req, res, 400, m, asserted, 'header_mismatch', fail(id, HEADER_MISMATCH, 'Header mismatch: the MCP-Protocol-Version header is required')));
      if (modern && typeof pv === 'string' && h !== pv) {
        return void (await deny(req, res, 400, m, asserted, 'header_mismatch', fail(id, HEADER_MISMATCH, 'Header mismatch: MCP-Protocol-Version does not match _meta')));
      }
      if (modern && (typeof pv !== 'string' || !meta?.[`${META}clientCapabilities`] || typeof meta[`${META}clientCapabilities`] !== 'object')) {
        return void (await deny(req, res, 400, m, asserted, 'invalid_params', fail(id, -32602, `Invalid params: _meta needs ${META}protocolVersion and ${META}clientCapabilities`)));
      }
    }
    // Mcp-Method and Mcp-Name: required in 2026-07-28; where an older client sends them they must match too.
    const hm = req.get('mcp-method');
    const named = ['tools/call', 'resources/read', 'prompts/get'].includes(m.method);
    const hn = req.get('mcp-name');
    const want = m.method === 'resources/read' ? p.uri : p.name;
    if ((modern && !hm) || (hm !== undefined && hm !== m.method)) {
      return void (await deny(req, res, 400, m, asserted, 'header_mismatch', fail(id, HEADER_MISMATCH, `Header mismatch: Mcp-Method must be ${sanitizeText(m.method, 100)}`)));
    }
    if (named && ((modern && hn === undefined) || (hn !== undefined && headerValue(hn) !== want))) {
      return void (await deny(req, res, 400, m, asserted, 'header_mismatch', fail(id, HEADER_MISMATCH, 'Header mismatch: Mcp-Name must match the name in the body')));
    }

    /** Result of 2026-07-28: resultType and the server's identity in _meta. @param {any} r */
    const result = (r) => (modern ? { resultType: 'complete', ...r, _meta: { [`${META}serverInfo`]: serverInfo } } : r);
    const audit = (/** @type {Partial<import('./audit.js').AuditEvent>} */ e) => ev(req, res, m.method === 'tools/call' ? 'mcp.tool_called' : 'mcp.request', { http: { method: 'POST', route: '/mcp' }, ...e, details: { ...about(m, asserted), ...e.details } });

    switch (m.method) {
      case 'initialize': {
        // Older clients: the handshake, within the allowed versions.
        if (!legacy.length) {
          return void (await deny(req, res, 400, m, sanitizeText(p.protocolVersion, 20), 'unsupported_protocol_version', fail(id, UNSUPPORTED_VERSION, `Unsupported protocol version: this server speaks ${versions.join(', ')} (no initialize)`, { supported: versions, requested: sanitizeText(p.protocolVersion, 50) })));
        }
        const v = legacy.includes(p.protocolVersion) ? p.protocolVersion : legacy[0];
        await audit({ details: { protocol_version: v } });
        return void res.json(ok(id, { protocolVersion: v, capabilities: { tools: {} }, serverInfo, instructions }));
      }
      case 'server/discover':
        await audit({});
        return void res.json(ok(id, result({ supportedVersions: versions, capabilities: { tools: {} }, instructions, ttlMs: TTL_MS, cacheScope: 'public' })));
      case 'ping':
        // Gone in 2026-07-28.
        if (modern) break;
        return void res.json(ok(id, {}));
      case 'tools/list':
        await audit({});
        return void res.json(ok(id, result(modern ? { tools: listed, ttlMs: TTL_MS, cacheScope: 'public' } : { tools: listed })));
      case 'tools/call': {
        const tool = tools.find((t) => t.name === p.name);
        if (!tool) {
          await audit({ outcome: 'denied', reason: 'unknown_tool', details: { tool: sanitizeText(p.name, 100) } });
          return void res.json(fail(id, -32602, `Unknown tool: ${sanitizeText(p.name, 100)}`));
        }
        if (p.arguments !== undefined && (p.arguments === null || typeof p.arguments !== 'object' || Array.isArray(p.arguments))) {
          await audit({ outcome: 'denied', reason: 'invalid_params', details: { tool: tool.name } });
          return void res.json(fail(id, -32602, 'Invalid params: arguments must be an object'));
        }
        const args = p.arguments || {};
        /** A tool error: a result with isError, for the model to correct (CIS 5.1.1). @param {string} code @param {string} text */
        const toolError = async (code, text, outcome = 'denied') => {
          await audit({ outcome: /** @type {'denied' | 'error'} */ (outcome), reason: code, details: { tool: tool.name, scope: tool.scope } });
          res.json(ok(id, result({ isError: true, content: [{ type: 'text', text: `${code}: ${text}` }] })));
        };
        const bad = schemaError(args, tool.inputSchema) || ('receipt' in tool.inputSchema.properties && !receiptId(args.receipt) ? 'arguments.receipt: give the receipt id or the receipt link' : '');
        if (bad) return void (await toolError(bad.startsWith('arguments.receipt:') ? 'invalid_receipt' : 'invalid_arguments', bad));
        let confirmed = false;
        // CONFIRM_CHECKBOX: the person confirms every secret through the client (elicitation, form
        // mode); only 2026-07-28 can ask without a stream. No way to ask: refused (fail closed).
        if (confirm && tool.name === 'create_secret') {
          const el = meta?.[`${META}clientCapabilities`]?.elicitation;
          const form = el && typeof el === 'object' && (!('url' in el) || 'form' in el);
          if (!modern || !form) {
            return void (await toolError('confirmation_unavailable', 'This server needs the confirmation of a person for every secret (CONFIRM_CHECKBOX). Use an MCP client with protocol 2026-07-28 and elicitation in form mode. No secret was stored.'));
          }
          const answer = p.inputResponses && typeof p.inputResponses === 'object' ? p.inputResponses.confirm : undefined;
          if (answer?.action === 'decline' || answer?.action === 'cancel') {
            return void (await toolError('confirmation_declined', 'The person did not confirm. No secret was stored.'));
          }
          if (answer?.action !== 'accept' || answer.content?.confirm !== true) {
            const { rule, t } = confirm(res);
            const hints = secretHints(args.secret);
            const warn = hints.length ? `${t('mcp.warn').replace('{found}', hints.map((h) => t(`mcp.found.${h}`)).join(', '))}\n\n` : '';
            // The audit log keeps no trace of the content: only whether a warning was shown.
            await audit({ details: { tool: tool.name, scope: tool.scope, confirmation: 'requested', warned: hints.length > 0 } });
            return void res.json(ok(id, result({
              resultType: 'input_required',
              inputRequests: {
                confirm: {
                  method: 'elicitation/create',
                  params: {
                    mode: 'form',
                    message: `${warn}${rule}`,
                    requestedSchema: { type: 'object', properties: { confirm: { type: 'boolean', title: t('mcp.confirm'), description: rule } }, required: ['confirm'] },
                  },
                },
              },
            })));
          }
          confirmed = true;
        }
        try {
          const [method, url, body] = tool.run(confirmed ? { ...args, confirmed: true } : args);
          const r = await call(req, res, method, url, body);
          if (r.status >= 400) {
            const code = String(r.body?.error || 'error');
            // MCP_OAUTH: a missing scope asks the client to sign in again with it (step-up, CIS 3.3.4).
            if (challenge && r.status === 403 && code === 'insufficient_scope') {
              await audit({ outcome: 'denied', reason: code, details: { tool: tool.name, scope: tool.scope } });
              res.set('WWW-Authenticate', challenge(req, tool.scope));
              return void res.status(403).json(fail(id, -32001, `This token lacks the scope "${tool.scope}"; sign in again to grant it`));
            }
            return void (await toolError(code, r.body?.message || `HTTP ${r.status}`, r.status >= 500 ? 'error' : 'denied'));
          }
          await audit({ details: { tool: tool.name, scope: tool.scope, ...(confirmed ? { confirmation: 'accepted' } : {}) } });
          return void res.json(ok(id, result({ content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }], structuredContent: r.body })));
        } catch (err) {
          console.error(`mcp error: ${/** @type {Error} */ (err)?.message || err}`);
          await audit({ outcome: 'error', reason: 'internal', details: { tool: tool.name, scope: tool.scope } });
          return void res.status(500).json(fail(id, -32603, 'Internal error'));
        }
      }
    }
    // An unknown method: 2026-07-28 answers 404, older revisions a JSON-RPC error.
    await audit({ outcome: 'denied', reason: 'unknown_method' });
    res.status(modern ? 404 : 200).json(fail(id, -32601, `Unknown method: ${sanitizeText(m.method, 100)}`));
  });
  // body-parser errors (bad JSON, too large) as JSON-RPC errors, not the HTML error page
  router.use((/** @type {any} */ err, /** @type {any} */ req, /** @type {any} */ res, /** @type {any} */ next) => {
    if (res.headersSent || !err?.type) return next(err);
    res.status(err.status || 400).json(fail(null, err.type === 'entity.parse.failed' ? -32700 : -32600, err.type === 'entity.parse.failed' ? 'Parse error' : 'Invalid request'));
  });
  return router;
}
