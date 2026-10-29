// Directory backends (src/directory/): the people and group search and the
// groups from the directory, per provider against a stand-in of its API.
// No Redis needed: these call Auth directly.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { Auth } from '../src/auth.js';
import { loadConfig } from '../src/config.js';
import { startMock } from './oidc-mock.js';

const SECRET = 'client-secret-for-tests';
/** @type {Awaited<ReturnType<typeof startMock>>} */ let kc;
/** @type {Awaited<ReturnType<typeof startMock>>} */ let ping;
const PING_ENV = '11111111-2222-3333-4444-555555555555';

before(async () => {
  kc = await startMock({ clientId: 'vanishly', clientSecret: SECRET, path: '/realms/vanishly' });
  ping = await startMock({ clientId: 'vanishly', clientSecret: SECRET, path: `/${PING_ENV}/as` });
});
after(async () => {
  await kc?.close();
  await ping?.close();
});

/**
 * A stand-in for a provider's API: routes by method and path, records calls.
 * @param {(url: URL, init: RequestInit) => { status?: number, body: any, headers?: Record<string, string> } | undefined} route
 */
function fakeFetch(route) {
  /** @type {{ url: URL, init: RequestInit }[]} */
  const calls = [];
  /** @type {typeof fetch} */
  const f = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url, init });
    const r = route(url, init);
    if (!r) return new Response('{"error":"not found"}', { status: 404 });
    const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
    return new Response(body, { status: r.status || 200, headers: { 'Content-Type': 'application/json', ...r.headers } });
  };
  return { f, calls };
}

/**
 * @param {Record<string, string>} env
 * @param {typeof fetch} f
 */
function auth(env, f) {
  const cfg = loadConfig({ BASE_URL: 'https://ots.example.com', OIDC_CLIENT_ID: 'vanishly', OIDC_CLIENT_SECRET: SECRET, AUTH_SECRET: 'z'.repeat(32), DIRECTORY_API: 'true', ...env });
  return new Auth(/** @type {any} */ (cfg.auth), { redis: null, p: 't:' }, { fetch: f });
}

/** @param {string} h @param {RequestInit} init */
const header = (h, init) => new Headers(init.headers).get(h);

test('keycloak: members of a group path, group search as paths, claim values without path', async () => {
  const { f, calls } = fakeFetch((url, init) => {
    if (header('authorization', init) !== 'Bearer graph-app-token') return { status: 401, body: {} };
    const p = url.pathname;
    if (p === '/admin/realms/vanishly/group-by-path/staff/finance') return { body: { id: 'g-1', path: '/staff/finance' } };
    if (p === '/admin/realms/vanishly/groups/g-1/members') {
      return {
        body: [
          { username: 'alice', firstName: 'Alice', lastName: 'Example', email: 'Alice@Example.com', emailVerified: true },
          { username: 'carl', firstName: 'Carl', email: 'carl@example.com', enabled: false },
          { username: 'nomail' },
        ],
      };
    }
    if (p === '/admin/realms/vanishly/groups') {
      assert.equal(url.searchParams.get('search'), 'fin');
      return { body: [{ name: 'staff', path: '/staff', subGroups: [{ name: 'finance', path: '/staff/finance', subGroups: [] }] }] };
    }
  });
  const a = auth({ AUTH_PROVIDER: 'keycloak', OIDC_ISSUER: kc.issuer, RECIPIENT_USER_GROUP: '/staff/finance', RECIPIENT_GROUPS: '*' }, f);
  assert.deepEqual(await a.searchPeople('ali'), [{ name: 'Alice Example', user: 'alice@example.com', mail: 'alice@example.com' }]);
  assert.deepEqual(await a.searchPeople('exam'), [{ name: 'Alice Example', user: 'alice@example.com', mail: 'alice@example.com' }]);
  assert.deepEqual(await a.searchPeople('carl'), []); // disabled
  // The member list is loaded once and searched locally.
  assert.equal(calls.filter((c) => c.url.pathname.endsWith('/members')).length, 1);
  assert.deepEqual(await a.searchGroups('fin'), [{ id: '/staff/finance', name: '/staff/finance' }]);
  // A mapper without "full group path" sends "finance"; it counts as "/finance".
  const list = auth({ AUTH_PROVIDER: 'keycloak', OIDC_ISSUER: kc.issuer, DIRECTORY_API: 'false', RECIPIENT_GROUPS: 'Finance=finance' }, f);
  assert.deepEqual(list.c.groups.list, [{ name: 'Finance', id: '/finance' }]);
  assert.deepEqual(await list.groupsOf({ sub: 's', groups: ['finance', 'it'] }), ['/finance']);
  assert.equal(list.hash('g', 'finance'), list.hash('g', '/finance'));
  assert.ok(list.groupAllowed('finance'));
  // A separate service-account client must be accepted by the provider.
  const other = auth({ AUTH_PROVIDER: 'keycloak', OIDC_ISSUER: kc.issuer, RECIPIENT_USER_GROUP: '/staff/finance', DIRECTORY_CLIENT_ID: 'search', DIRECTORY_CLIENT_SECRET: 'wrong-one' }, f);
  await assert.rejects(other.searchPeople('ali'));
});

test('okta: API token, paging only on the same server, group names', async () => {
  const { f, calls } = fakeFetch((url, init) => {
    if (header('authorization', init) !== 'SSWS change-me-token') return { status: 401, body: {} };
    if (url.pathname === '/api/v1/groups/00g1abcdefghijklmnop/users') {
      if (!url.searchParams.get('after')) {
        return {
          body: [{ status: 'ACTIVE', profile: { firstName: 'Bob', lastName: 'Builder', email: 'bob@example.com' } }],
          headers: { link: '<https://example.okta.com/api/v1/groups/00g1abcdefghijklmnop/users?after=2&limit=200>; rel="next"' },
        };
      }
      return {
        body: [
          { status: 'SUSPENDED', profile: { displayName: 'Bea', email: 'bea@example.com' } },
          { status: 'ACTIVE', profile: { displayName: 'Bert', email: 'bert@example.com' } },
        ],
        headers: { link: '<https://evil.example.net/steal>; rel="next"' },
      };
    }
    if (url.pathname === '/api/v1/groups') return { body: [{ profile: { name: 'IT Admins' } }] };
  });
  const a = auth({ AUTH_PROVIDER: 'okta', OIDC_ISSUER: 'https://example.okta.com/oauth2/default', DIRECTORY_API_TOKEN: 'change-me-token', RECIPIENT_USER_GROUP: '00g1abcdefghijklmnop', RECIPIENT_GROUPS: '*' }, f);
  assert.deepEqual((await a.searchPeople('b')).map((p) => p.user), []); // 2 characters at least
  assert.deepEqual((await a.searchPeople('be')).map((p) => p.user), ['bert@example.com']);
  assert.deepEqual((await a.searchPeople('bui')).map((p) => p.name), ['Bob Builder']);
  assert.ok(!calls.some((c) => c.url.hostname === 'evil.example.net'));
  assert.deepEqual(await a.searchGroups('it'), [{ id: 'IT Admins', name: 'IT Admins' }]);
});

test('auth0: management token for the tenant, users of a role', async () => {
  const { f, calls } = fakeFetch((url, init) => {
    if (url.pathname === '/oauth/token') {
      const b = JSON.parse(String(init.body));
      assert.equal(b.audience, 'https://example.eu.auth0.com/api/v2/');
      assert.equal(b.client_id, 'm2m');
      return { body: { access_token: 'mgmt', expires_in: 86400 } };
    }
    if (header('authorization', init) !== 'Bearer mgmt') return { status: 401, body: {} };
    if (url.pathname === '/api/v2/roles/rol_abcdefghijklmnop/users') return { body: [{ email: 'dana@example.com', name: 'Dana Doe' }] };
  });
  const a = auth(
    { AUTH_PROVIDER: 'auth0', OIDC_ISSUER: 'https://login.example.com/', DIRECTORY_URL: 'https://example.eu.auth0.com', DIRECTORY_CLIENT_ID: 'm2m', DIRECTORY_CLIENT_SECRET: 'change-me', RECIPIENT_USER_GROUP: 'rol_abcdefghijklmnop' },
    f,
  );
  assert.deepEqual(await a.searchPeople('doe'), [{ name: 'Dana Doe', user: 'dana@example.com', mail: 'dana@example.com' }]);
  await a.searchPeople('dan');
  assert.equal(calls.filter((c) => c.url.pathname === '/oauth/token').length, 1); // token kept
});

test('google: service account for an admin, members and groups from the directory, hd checked', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vanishly-google-'));
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyFile = join(dir, 'sa.json');
  writeFileSync(
    keyFile,
    JSON.stringify({ type: 'service_account', client_email: 'sa@example.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), private_key_id: 'k1', token_uri: 'https://oauth2.example.com/token' }),
  );
  const { f } = fakeFetch((url, init) => {
    if (url.hostname === 'oauth2.example.com') {
      const assertion = new URLSearchParams(String(init.body)).get('assertion') || '';
      const claims = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString());
      assert.equal(claims.sub, 'admin@example.com');
      assert.match(claims.scope, /admin\.directory\.group\.member\.readonly/);
      return { body: { access_token: 'g-token', expires_in: 3600 } };
    }
    if (header('authorization', init) !== 'Bearer g-token') return { status: 401, body: {} };
    const p = url.pathname;
    if (p === '/admin/directory/v1/groups/staff%40example.com/members' || p === '/admin/directory/v1/groups/staff@example.com/members') {
      return { body: { members: [{ type: 'USER', status: 'ACTIVE', email: 'erin@example.com' }, { type: 'GROUP', email: 'sub@example.com' }] } };
    }
    if (p === '/admin/directory/v1/users') {
      const q = url.searchParams.get('query') || '';
      const users = [
        { primaryEmail: 'erin@example.com', name: { fullName: 'Erin Example' } },
        { primaryEmail: 'eve@example.com', name: { fullName: 'Eve Outsider' } },
      ];
      return { body: { users: q.startsWith('givenName') ? users : [] } };
    }
    if (p === '/admin/directory/v1/groups') {
      if (url.searchParams.get('userKey') === 'erin@example.com') return { body: { groups: [{ email: 'Ops@Example.com' }, { email: 'other@example.com' }] } };
      return { body: { groups: [{ email: 'ops@example.com', name: 'Operations' }] } };
    }
  });
  const a = auth(
    {
      AUTH_PROVIDER: 'google',
      OIDC_ISSUER: 'https://accounts.google.com',
      AUTH_ALLOWED_DOMAINS: 'example.com',
      DIRECTORY_GOOGLE_CREDENTIALS_FILE: keyFile,
      DIRECTORY_GOOGLE_ADMIN: 'admin@example.com',
      RECIPIENT_USER_GROUP: 'staff@example.com',
      RECIPIENT_GROUPS: 'Ops=ops@example.com',
    },
    f,
  );
  // Only members of the group, though the user search finds more.
  assert.deepEqual(await a.searchPeople('er'), [{ name: 'Erin Example', user: 'erin@example.com', mail: 'erin@example.com' }]);
  const who = await a.identity({ sub: 'g1', email: 'erin@example.com', email_verified: true, hd: 'example.com', name: 'Erin' });
  assert.ok(who.ids.includes(a.hash('g', 'ops@example.com')));
  assert.ok(!who.ids.includes(a.hash('g', 'other@example.com')));
  // A private Google account (no hd) or another domain does not sign in.
  await assert.rejects(a.identity({ sub: 'g2', email: 'erin@example.com', email_verified: true }), /domain/);
  await assert.rejects(a.identity({ sub: 'g3', email: 'x@example.net', email_verified: true, hd: 'example.com' }), /domain/);
  const search = auth(
    { AUTH_PROVIDER: 'google', OIDC_ISSUER: 'https://accounts.google.com', AUTH_ALLOWED_DOMAINS: 'example.com', DIRECTORY_GOOGLE_CREDENTIALS_FILE: keyFile, DIRECTORY_GOOGLE_ADMIN: 'admin@example.com', RECIPIENT_GROUPS: '*' },
    f,
  );
  assert.deepEqual(await search.searchGroups('op'), [{ id: 'ops@example.com', name: 'Operations (ops@example.com)' }]);
});

test('ping: worker token, members by filter, links to other servers ignored', async () => {
  const { f } = fakeFetch((url, init) => {
    if (header('authorization', init) !== 'Bearer graph-app-token') return { status: 401, body: {} };
    if (url.pathname === `/v1/environments/${PING_ENV}/users`) {
      assert.equal(url.searchParams.get('filter'), 'memberOfGroups[id eq "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]');
      return {
        body: {
          _embedded: { users: [{ email: 'finn@example.com', name: { given: 'Finn', family: 'Fisher' } }, { email: 'fay@example.com', enabled: false }] },
          _links: { next: { href: 'https://evil.example.net/next' } },
        },
      };
    }
  });
  const a = auth({ AUTH_PROVIDER: 'ping', OIDC_ISSUER: ping.issuer, RECIPIENT_USER_GROUP: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }, f);
  assert.deepEqual(await a.searchPeople('fi'), [{ name: 'Finn Fisher', user: 'finn@example.com', mail: 'finn@example.com' }]);
});

test('jumpcloud: API key, membership then user details', async () => {
  const ids = ['0123456789abcdef01234567', '0123456789abcdef01234568'];
  const { f } = fakeFetch((url, init) => {
    if (header('x-api-key', init) !== 'change-me-token') return { status: 401, body: {} };
    if (url.pathname === '/api/v2/usergroups/0123456789abcdef0123abcd/membership') return { body: ids.map((id) => ({ id, type: 'user' })) };
    if (url.pathname === '/api/systemusers') {
      assert.equal(url.searchParams.get('filter'), `_id:$in:${ids.join('|')}`);
      return { body: { results: [{ email: 'gus@example.com', firstname: 'Gus', lastname: 'Grey', state: 'ACTIVATED' }, { email: 'gil@example.com', suspended: true }] } };
    }
  });
  const a = auth(
    { AUTH_PROVIDER: 'jumpcloud', OIDC_ISSUER: 'https://oauth.id.jumpcloud.com/', DIRECTORY_URL: 'https://console.eu.jumpcloud.com', DIRECTORY_API_TOKEN: 'change-me-token', RECIPIENT_USER_GROUP: '0123456789abcdef0123abcd' },
    f,
  );
  assert.deepEqual(await a.searchPeople('g'), []);
  assert.deepEqual((await a.searchPeople('gu')).map((p) => p.user), ['gus@example.com']);
});

test('cognito: SigV4-signed calls, users in a group, group list, cognito:groups claim', async () => {
  const { f, calls } = fakeFetch((url, init) => {
    assert.equal(url.hostname, 'cognito-idp.eu-central-1.amazonaws.com');
    assert.match(String(header('authorization', init)), /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/eu-central-1\/cognito-idp\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=[0-9a-f]{64}$/);
    const target = header('x-amz-target', init);
    const body = JSON.parse(String(init.body));
    assert.equal(body.UserPoolId, 'eu-central-1_AbC123');
    if (target === 'AWSCognitoIdentityProviderService.ListUsersInGroup') {
      return { body: { Users: [{ Username: 'h1', Attributes: [{ Name: 'email', Value: 'hana@example.com' }, { Name: 'name', Value: 'Hana Hill' }] }] } };
    }
    if (target === 'AWSCognitoIdentityProviderService.ListGroups') return { body: { Groups: [{ GroupName: 'helpdesk' }, { GroupName: 'hr' }] } };
  });
  const a = auth(
    {
      AUTH_PROVIDER: 'cognito',
      OIDC_ISSUER: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_AbC123',
      AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE',
      AWS_SECRET_ACCESS_KEY: 'change-me',
      RECIPIENT_USER_GROUP: 'staff',
      RECIPIENT_GROUPS: '*',
    },
    f,
  );
  assert.deepEqual(await a.searchPeople('hill'), [{ name: 'Hana Hill', user: 'hana@example.com', mail: 'hana@example.com' }]);
  assert.deepEqual(await a.searchGroups('help'), [{ id: 'helpdesk', name: 'helpdesk' }]);
  assert.equal(calls.length, 2);
  assert.deepEqual(await a.groupsOf({ sub: 'c1', 'cognito:groups': ['hr'] }), ['hr']);
});

test('errors name only the status, never the request', async () => {
  const { f } = fakeFetch(() => ({ status: 403, body: { error: 'forbidden' } }));
  const a = auth({ AUTH_PROVIDER: 'okta', OIDC_ISSUER: 'https://example.okta.com', DIRECTORY_API_TOKEN: 'change-me-token', RECIPIENT_USER_GROUP: '00g1abcdefghijklmnop' }, f);
  await assert.rejects(a.searchPeople('secret-term'), (err) => /** @type {Error} */ (err).message === 'Okta answered 403');
});
