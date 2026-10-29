// A small stand-in for Microsoft Entra ID / an OpenID provider in tests:
// discovery, authorize (signs in `mock.user` at once), token (code with
// PKCE, client credentials), keys, and the two Graph calls Vanishly uses.
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

/**
 * @param {{ tenant?: string, clientId: string, clientSecret: string, path?: string, logout?: boolean }} opts
 *   path: the issuer path (default "/<tenant>/v2.0", like Entra); logout: offer an end_session_endpoint
 */
export async function startMock(opts) {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  /** @type {Map<string, { claims: any, nonce: string, challenge: string, redirect: string }>} */
  const codes = new Map();
  const mock = {
    base: '',
    issuer: '',
    /** @type {Record<string, any>} claims of the next sign-in */
    user: {},
    /** @type {Record<string, string[]>} Graph: oid -> group ids */
    memberGroups: {},
    /** @type {{ id: string, displayName: string }[]} Graph: all groups */
    groups: [],
    /** @type {Record<string, { displayName: string, mail?: string | null, userPrincipalName: string }[]>} Graph: group id -> users (transitive) */
    members: {},
    /** @type {URLSearchParams | null} */
    lastAuthorize: null,
    /** @type {URLSearchParams | null} */
    lastSearch: null,
    /** @type {URLSearchParams | null} */
    lastLogout: null,
    /** false: nobody is signed in at the provider, prompt=none answers login_required */
    session: true,
    graphCalls: 0,
    /**
     * @param {Record<string, any>} claims
     * @param {{ aud?: string, iss?: string, key?: any }} [o]
     */
    async sign(claims, o = {}) {
      return new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer(o.iss || mock.issuer)
        .setAudience(o.aud || opts.clientId)
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(o.key || privateKey);
    },
    close: () => new Promise((r) => server.close(r)),
  };

  /** @param {import('node:http').ServerResponse} res @param {number} status @param {any} body */
  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url || '/', mock.base);
    let body = '';
    for await (const chunk of req) body += chunk;
    const p = url.pathname;
    if (p === `${new URL(mock.issuer).pathname}/.well-known/openid-configuration`) {
      return json(res, 200, {
        issuer: mock.issuer,
        authorization_endpoint: `${mock.base}/authorize`,
        token_endpoint: `${mock.base}/token`,
        jwks_uri: `${mock.base}/keys`,
        response_types_supported: ['code'],
        subject_types_supported: ['pairwise'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256'],
        ...(opts.logout ? { end_session_endpoint: `${mock.base}/logout` } : {}),
      });
    }
    if (p === '/keys') return json(res, 200, { keys: [jwk] });
    if (p === '/logout') {
      mock.lastLogout = url.searchParams;
      return json(res, 200, {});
    }
    if (p === '/authorize') {
      mock.lastAuthorize = url.searchParams;
      const q = url.searchParams;
      if (q.get('client_id') !== opts.clientId || q.get('code_challenge_method') !== 'S256') return json(res, 400, { error: 'invalid_request' });
      if (q.get('prompt') === 'none' && !mock.session) {
        const to = new URL(q.get('redirect_uri') || '');
        to.searchParams.set('error', 'login_required');
        to.searchParams.set('state', q.get('state') || '');
        res.writeHead(302, { Location: to.href });
        return res.end();
      }
      const code = randomBytes(16).toString('hex');
      codes.set(code, {
        claims: { ...mock.user },
        nonce: q.get('nonce') || '',
        challenge: q.get('code_challenge') || '',
        redirect: q.get('redirect_uri') || '',
      });
      const to = new URL(q.get('redirect_uri') || '');
      to.searchParams.set('code', code);
      to.searchParams.set('state', q.get('state') || '');
      res.writeHead(302, { Location: to.href });
      return res.end();
    }
    if (p === '/token' && req.method === 'POST') {
      const f = new URLSearchParams(body);
      const basic = Buffer.from(String(req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString();
      const [id, secret] = basic.split(':').map(decodeURIComponent);
      if ((id || f.get('client_id')) !== opts.clientId || (secret || f.get('client_secret')) !== opts.clientSecret) {
        return json(res, 401, { error: 'invalid_client' });
      }
      if (f.get('grant_type') === 'client_credentials') {
        return json(res, 200, { access_token: 'graph-app-token', token_type: 'Bearer', expires_in: 3600 });
      }
      const c = codes.get(f.get('code') || '');
      codes.delete(f.get('code') || '');
      const challenge = createHash('sha256').update(f.get('code_verifier') || '').digest('base64url');
      if (!c || c.challenge !== challenge || c.redirect !== f.get('redirect_uri')) return json(res, 400, { error: 'invalid_grant' });
      const idToken = await mock.sign({ sub: 'sub-1', nonce: c.nonce, ...c.claims });
      return json(res, 200, { access_token: 'user-token', token_type: 'Bearer', expires_in: 3600, id_token: idToken });
    }
    if (p.startsWith('/v1.0/')) {
      mock.graphCalls++;
      if (req.headers.authorization !== 'Bearer graph-app-token') return json(res, 401, { error: { code: 'InvalidAuthenticationToken' } });
      const m = /^\/v1\.0\/users\/([0-9a-f-]{36})\/getMemberGroups$/.exec(p);
      if (m && req.method === 'POST') return json(res, 200, { value: mock.memberGroups[m[1]] || [] });
      const t = /^\/v1\.0\/groups\/([0-9a-f-]{36})\/transitiveMembers\/microsoft\.graph\.user$/.exec(p);
      if (t) {
        mock.lastSearch = url.searchParams;
        if (req.headers.consistencylevel !== 'eventual') return json(res, 400, { error: { code: 'Request_UnsupportedQuery' } });
        const terms = [...(url.searchParams.get('$search') || '').matchAll(/"(\w+):([^"]*)"/g)];
        const hit = (/** @type {any} */ u) => terms.some(([, f, v]) => String(u[f] || '').toLowerCase().startsWith(v.toLowerCase()));
        return json(res, 200, { value: (mock.members[t[1]] || []).filter(hit) });
      }
      if (p === '/v1.0/groups') {
        const term = /displayName:([^"]*)/.exec(url.searchParams.get('$search') || '')?.[1]?.toLowerCase() || '';
        return json(res, 200, { value: mock.groups.filter((g) => g.displayName.toLowerCase().startsWith(term)) });
      }
    }
    json(res, 404, { error: 'not_found' });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(undefined)));
  mock.base = `http://127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
  mock.issuer = `${mock.base}${opts.path || `/${opts.tenant}/v2.0`}`;
  return mock;
}
