// Vanishly - MCP server (ENABLE_MCP) at /mcp: AI clients (Claude, Copilot,
// Cursor, ...) create secrets and check or burn them. Streamable HTTP without
// sessions: every POST is one JSON-RPC message, answered as JSON. Each tool
// runs the matching API endpoint in this process, so sign-in, API tokens and
// their scopes, ENABLE_* switches, rate limits and the audit log apply
// exactly as for a script.

import express from 'express';

// The newest first; a client asking for another one gets the newest.
export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

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

const RECEIPT = {
  type: 'string',
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
 * @param {{
 *   api: import('express').Router,
 *   spec: any,
 *   features: { shareApi: boolean, receipts: boolean, receiptApi: boolean, burn: boolean },
 *   version: string,
 *   origin: (req: import('express').Request) => string,
 *   bodyLimit: number,
 * }} o
 */
export function mcpRouter({ api, spec, features, version, origin, bodyLimit }) {
  /** @type {{ name: string, description: string, inputSchema: any, run: (a: any) => [string, string, any] }[]} */
  const tools = [];
  if (features.shareApi) {
    tools.push({
      name: 'create_secret',
      description:
        'Store a secret (password, key, note) on this Vanishly server and get a one-time link (shareUrl) to send to the recipient, and a receipt link (receiptUrl) to check or burn it. The secret is encrypted on the server; the key is only in the links.',
      inputSchema: flatSchema(spec.paths['/v1/share'].post.requestBody.content['application/json'].schema, spec),
      run: (a) => ['POST', '/v1/share', a],
    });
  }
  if (features.receipts && features.receiptApi) {
    tools.push({
      name: 'get_secret_status',
      description: 'The status of a secret by its receipt: new, viewed, burned or expired, with views left and expiry. Never shows the secret.',
      inputSchema: { type: 'object', properties: { receipt: RECEIPT }, required: ['receipt'] },
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
        },
        run: (a) => ['POST', `/v1/receipts/${receiptId(a.receipt)}/burn`, a.comment === undefined ? {} : { comment: a.comment }],
      });
    }
  }

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
  /** @param {any} id @param {number} code @param {string} message */
  const fail = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  const router = express.Router();
  // Streamable HTTP: no server-sent events, no sessions to end.
  router.all('/', (req, res, next) => (req.method === 'POST' ? next() : void res.set('Allow', 'POST').status(405).json(fail(null, -32000, 'Use POST'))));
  // Against DNS rebinding and other sites: a browser's Origin must be this server.
  router.post('/', (req, res, next) => {
    const o = req.get('origin');
    if (o && o !== new URL(origin(req)).origin) return void res.status(403).json(fail(null, -32000, 'Origin not allowed'));
    next();
  });
  router.post('/', express.json({ limit: bodyLimit }), async (req, res) => {
    const m = req.body;
    if (!m || typeof m !== 'object' || Array.isArray(m) || m.jsonrpc !== '2.0' || typeof m.method !== 'string') {
      return void res.status(400).json(fail(null, -32600, 'One JSON-RPC 2.0 message per request'));
    }
    // A notification or a response of the client: nothing to answer.
    if (m.id === undefined || m.id === null) return void res.status(202).end();
    const id = m.id;
    const p = m.params && typeof m.params === 'object' ? m.params : {};
    switch (m.method) {
      case 'initialize':
        return void res.json(
          ok(id, {
            protocolVersion: PROTOCOL_VERSIONS.includes(p.protocolVersion) ? p.protocolVersion : PROTOCOL_VERSIONS[0],
            capabilities: { tools: {} },
            serverInfo: { name: 'vanishly', title: 'Vanishly', version },
            instructions: 'Share secrets as one-time links: create_secret returns shareUrl for the recipient and receiptUrl for you; check or burn a secret with its receipt.',
          }),
        );
      case 'ping':
        return void res.json(ok(id, {}));
      case 'tools/list':
        return void res.json(ok(id, { tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) }));
      case 'tools/call': {
        const tool = tools.find((t) => t.name === p.name);
        if (!tool) return void res.json(fail(id, -32602, `Unknown tool: ${String(p.name).slice(0, 100)}`));
        const args = p.arguments && typeof p.arguments === 'object' && !Array.isArray(p.arguments) ? p.arguments : {};
        if ('receipt' in tool.inputSchema.properties && !receiptId(args.receipt)) {
          return void res.json(ok(id, { isError: true, content: [{ type: 'text', text: 'invalid_receipt: give the receipt id or the receipt link' }] }));
        }
        try {
          const [method, url, body] = tool.run(args);
          const r = await call(req, res, method, url, body);
          if (r.status >= 400) {
            const text = `${r.body?.error || 'error'}: ${r.body?.message || `HTTP ${r.status}`}`;
            return void res.json(ok(id, { isError: true, content: [{ type: 'text', text }] }));
          }
          return void res.json(ok(id, { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }], structuredContent: r.body }));
        } catch (err) {
          console.error(`mcp error: ${/** @type {Error} */ (err)?.message || err}`);
          return void res.status(500).json(fail(id, -32603, 'Internal error'));
        }
      }
      default:
        return void res.json(fail(id, -32601, `Unknown method: ${m.method.slice(0, 100)}`));
    }
  });
  // body-parser errors (bad JSON, too large) as JSON-RPC errors, not the HTML error page
  router.use((/** @type {any} */ err, /** @type {any} */ req, /** @type {any} */ res, /** @type {any} */ next) => {
    if (res.headersSent || !err?.type) return next(err);
    res.status(err.status || 400).json(fail(null, err.type === 'entity.parse.failed' ? -32700 : -32600, err.type === 'entity.parse.failed' ? 'Parse error' : 'Invalid request'));
  });
  return router;
}
