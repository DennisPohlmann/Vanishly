// Vanishly - end-to-end encryption of a secret, shared by the browser
// (public/js/app.js) and the server (POST /api/v1/share).
//
// Format v1:
//   key        32 random bytes, only ever in the URL fragment (#...), which
//              browsers never send to the server.
//   passphrase optional: pk = PBKDF2-SHA256(passphrase, salt, iterations).
//   encKey     HKDF-SHA256(ikm = key || pk, salt, info "vanishly v1 enc")
//   verifier   HKDF-SHA256(ikm = pk, salt, info "vanishly v1 auth"); the
//              server stores only SHA-256(verifier) and checks it before it
//              hands out (and deletes) the ciphertext, so a wrong passphrase
//              does not burn the secret.
//   ciphertext AES-256-GCM(encKey, iv 12 bytes, aad "vanishly v1").
// The server holds the ciphertext and the verifier hash, never the key, so
// it cannot read a secret even with the passphrase.

export const VERSION = 1;
export const PBKDF2_ITERATIONS = 600000;

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** @param {Uint8Array} bytes */
export function toB64url(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}

/** @param {string} str */
export function fromB64url(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) {
    throw new Error('invalid base64url');
  }
  const out = new Uint8Array(Math.floor((str.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < str.length; i += 4) {
    const c = [0, 1, 2, 3].map((k) => (i + k < str.length ? B64.indexOf(str[i + k]) : 0));
    const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

/** @param {number} n */
export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** @param {Uint8Array[]} parts */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * @param {Uint8Array} ikm
 * @param {Uint8Array} salt
 * @param {string} info
 * @param {boolean} asKey
 */
async function hkdf(ikm, salt, info, asKey) {
  const base = await subtle().importKey('raw', /** @type {BufferSource} */ (ikm), 'HKDF', false, ['deriveBits', 'deriveKey']);
  const params = { name: 'HKDF', hash: 'SHA-256', salt: /** @type {BufferSource} */ (salt), info: enc.encode(info) };
  if (asKey) {
    return subtle().deriveKey(params, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  return new Uint8Array(await subtle().deriveBits(params, base, 256));
}

/**
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} iterations
 */
async function passKey(passphrase, salt, iterations) {
  const base = await subtle().importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(
    await subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: /** @type {BufferSource} */ (salt), iterations }, base, 256),
  );
}

/**
 * Derives the encryption key and, with a passphrase key, the verifier.
 * @param {Uint8Array} key
 * @param {Uint8Array} salt
 * @param {Uint8Array} pk empty without a passphrase
 */
async function derive(key, salt, pk) {
  const encKey = /** @type {CryptoKey} */ (await hkdf(concat(key, pk), salt, 'vanishly v1 enc', true));
  const verifier = pk.length
    ? toB64url(/** @type {Uint8Array} */ (await hkdf(pk, salt, 'vanishly v1 auth', false)))
    : '';
  return { encKey, verifier };
}

/**
 * Encrypts a secret. Returns what goes to the server (payload) and the key
 * for the URL fragment.
 * @param {string} plaintext
 * @param {string} [passphrase]
 */
export async function encryptSecret(plaintext, passphrase = '') {
  const key = randomBytes(32);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const iterations = PBKDF2_ITERATIONS;
  const pk = passphrase ? await passKey(passphrase, salt, iterations) : new Uint8Array(0);
  const { encKey, verifier } = await derive(key, salt, pk);
  const ct = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode('vanishly v1') },
      encKey,
      enc.encode(plaintext),
    ),
  );
  return {
    key: toB64url(key),
    payload: {
      v: VERSION,
      ciphertext: toB64url(ct),
      iv: toB64url(iv),
      salt: toB64url(salt),
      iterations,
      verifier: verifier || undefined,
    },
  };
}

/**
 * Stretches a passphrase once; the result unlocks (verifierFor) and
 * decrypts (decryptSecret) a passphrase-protected secret.
 * @param {string} passphrase
 * @param {{ salt: string, iterations: number }} meta
 */
export async function unlockKey(passphrase, meta) {
  return passKey(passphrase, fromB64url(meta.salt), meta.iterations);
}

/**
 * The verifier the reveal API checks for a passphrase-protected secret.
 * @param {Uint8Array} pk from unlockKey
 * @param {{ salt: string }} meta
 */
export async function verifierFor(pk, meta) {
  return toB64url(/** @type {Uint8Array} */ (await hkdf(pk, fromB64url(meta.salt), 'vanishly v1 auth', false)));
}

/**
 * Decrypts a payload returned by the reveal API.
 * @param {{ ciphertext: string, iv: string, salt: string }} payload
 * @param {string} key base64url key from the URL fragment
 * @param {Uint8Array} [pk] from unlockKey, for a passphrase-protected secret
 */
export async function decryptSecret(payload, key, pk = new Uint8Array(0)) {
  const { encKey } = await derive(fromB64url(key), fromB64url(payload.salt), pk);
  const pt = await subtle().decrypt(
    { name: 'AES-GCM', iv: fromB64url(payload.iv), additionalData: enc.encode('vanishly v1') },
    encKey,
    fromB64url(payload.ciphertext),
  );
  return dec.decode(pt);
}
