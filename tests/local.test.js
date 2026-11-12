// Local accounts (AUTH_PROVIDER=local): password hashing.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hashPassword, verifyPassword } from '../src/users.js';

test('password hashes: scrypt with salt and parameters, constant-time check, tampered parameters refused', async () => {
  const a = await hashPassword('correct horse battery');
  const b = await hashPassword('correct horse battery');
  assert.match(a, /^scrypt\$32768\$8\$3\$[\w-]{22}\$[\w-]{43}$/);
  assert.notEqual(a, b, 'a fresh salt each time');
  assert.equal(await verifyPassword('correct horse battery', a), true);
  assert.equal(await verifyPassword('correct horse batterz', a), false);
  assert.equal(await verifyPassword('', a), false);
  assert.equal(await verifyPassword('x', 'garbage'), false);
  // A record pointing at huge parameters is refused without hashing.
  assert.equal(await verifyPassword('correct horse battery', a.replace('$32768$', '$4194304$')), false);
  assert.equal(await verifyPassword('correct horse battery', a.replace('$32768$', '$30000$')), false);
});
