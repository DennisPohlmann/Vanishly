import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decryptSecret,
  encryptSecret,
  fromB64url,
  randomBytes,
  toB64url,
  unlockKey,
  verifierFor,
} from '../public/js/vanishly-crypto.js';

test('base64url matches Buffer for all lengths', () => {
  for (let n = 0; n < 70; n++) {
    const b = randomBytes(n);
    const s = toB64url(b);
    assert.equal(s, Buffer.from(b).toString('base64url'));
    assert.deepEqual(Buffer.from(fromB64url(s)), Buffer.from(b));
  }
  assert.throws(() => fromB64url('a+b/'));
  assert.throws(() => fromB64url('abcde'));
});

test('round trip without passphrase', async () => {
  const { key, payload } = await encryptSecret('hällo 🔐\nline 2');
  assert.equal(payload.verifier, undefined);
  assert.equal(key.length, 43);
  assert.equal(await decryptSecret(payload, key), 'hällo 🔐\nline 2');
});

test('round trip with passphrase; the verifier matches, wrong ones do not', async () => {
  const { key, payload } = await encryptSecret('s3cret', 'correct horse');
  const pk = await unlockKey('correct horse', payload);
  assert.equal(await verifierFor(pk, payload), payload.verifier);
  assert.equal(await decryptSecret(payload, key, pk), 's3cret');
  const bad = await unlockKey('wrong', payload);
  assert.notEqual(await verifierFor(bad, payload), payload.verifier);
  await assert.rejects(decryptSecret(payload, key, bad));
  // The key alone is not enough when a passphrase was set.
  await assert.rejects(decryptSecret(payload, key));
});

test('a wrong key or tampered ciphertext fails', async () => {
  const { key, payload } = await encryptSecret('abc');
  await assert.rejects(decryptSecret(payload, toB64url(randomBytes(32))));
  const ct = fromB64url(payload.ciphertext);
  ct[0] ^= 1;
  await assert.rejects(decryptSecret({ ...payload, ciphertext: toB64url(ct) }, key));
});
