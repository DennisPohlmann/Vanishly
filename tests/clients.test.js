// The client libraries in clients/: the shared test vectors still come from
// public/js/vanishly-crypto.js, and every library has the app's version
// (clients/set-version.sh, called by semantic-release). Each library checks
// itself against the vectors with its own tests (docs/CLIENTS.md).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { decryptSecret, unlockKey } from '../public/js/vanishly-crypto.js';

const read = (/** @type {string} */ p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('clients/testvectors.json is what clients/testvectors.mjs makes from the JavaScript module', async () => {
  const fresh = execFileSync(process.execPath, [new URL('../clients/testvectors.mjs', import.meta.url).pathname], { encoding: 'utf8' });
  assert.equal(read('clients/testvectors.json'), fresh);
  for (const v of JSON.parse(fresh).vectors) {
    const pk = v.passphrase ? await unlockKey(v.passphrase, v) : undefined;
    assert.equal(await decryptSecret(v, v.key, pk), v.plaintext, v.name);
  }
});

test('every client library has the version of the app', () => {
  const v = read('VERSION').trim();
  const found = {
    go: /^var Version = "([^"]+)"/m.exec(read('clients/go/client.go'))?.[1],
  };
  for (const [k, got] of Object.entries(found)) assert.equal(got, v, k);
  // Go: from v2 on, the module path ends in the major version.
  assert.match(read('clients/go/go.mod'), new RegExp(`^module github\\.com/DennisPohlmann/vanishly/clients/go/v${v.split('.')[0]}$`, 'm'));
});
