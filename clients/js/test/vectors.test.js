import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { Client, decryptSecret, parseLink, unlockKey, verifierFor } from '../index.js';

const { vectors } = JSON.parse(readFileSync(new URL('../../testvectors.json', import.meta.url), 'utf8'));

test('crypto.js is the server module, unchanged', () => {
  assert.equal(readFileSync(new URL('../crypto.js', import.meta.url), 'utf8'), readFileSync(new URL('../../../public/js/vanishly-crypto.js', import.meta.url), 'utf8'));
});

test('decrypts the vectors', async () => {
  for (const v of vectors) {
    const pk = v.passphrase ? await unlockKey(v.passphrase, v) : undefined;
    if (pk) assert.equal(await verifierFor(pk, v), v.verifier);
    assert.equal(await decryptSecret(v, v.key, pk), v.plaintext, v.name);
  }
});

test('parseLink and the client headers', async () => {
  const id = 'A'.repeat(22);
  const key = 'b'.repeat(43);
  assert.deepEqual(parseLink(`https://x.example/ots/s/${id}#${key}`), { base: 'https://x.example/ots', id, key });
  assert.throws(() => parseLink('https://x.example/s/short#k'));
  /** @type {any[]} */
  const calls = [];
  const c = new Client('https://x.example/', {
    token: 'vnly_t',
    fetch: async (url, init) => {
      calls.push([url, init]);
      return new Response(JSON.stringify({ ok: 1 }), { headers: { 'X-Vanishly-Client-Recommended': '9.0.0' } });
    },
  });
  assert.deepEqual(await c.groups('a b'), { ok: 1 });
  assert.equal(calls[0][0], 'https://x.example/api/v1/groups?q=a+b');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer vnly_t');
  assert.match(calls[0][1].headers['X-Vanishly-Client'], /^js\/\d/);
  assert.equal(c.recommendedVersion, '9.0.0');
});
