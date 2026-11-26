// Vanishly - the command line clients offered for download (/downloads,
// GET /api/v1/downloads) and the client version rules (CLIENT_MIN_VERSION,
// CLIENT_RECOMMENDED_VERSION).
//
// The binaries are in downloads/ of the app (the Dockerfile builds them in
// its "clients" stage with clients/go/build.sh). They are read once at the
// start: name, platform, size and the checksums, so a request never touches
// a path that came from the client.
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The repository whose GitHub Actions build and sign the binaries. */
export const SIGNER_REPO = 'DennisPohlmann/vanishly';

/** Checksums per file: [key in the API, node:crypto name, checksum file, name shown]. MD5 and SHA-1 are broken and left out. */
export const ALGORITHMS = /** @type {const} */ ([
  ['sha256', 'sha256', 'SHA256SUMS', 'SHA-256'],
  ['sha512', 'sha512', 'SHA512SUMS', 'SHA-512'],
  ['sha3_256', 'sha3-256', 'SHA3-256SUMS', 'SHA3-256'],
  ['sha3_512', 'sha3-512', 'SHA3-512SUMS', 'SHA3-512'],
  ['blake2b_512', 'blake2b512', 'B2SUMS', 'BLAKE2b-512'],
]);

const NAME = /^vanishly-(linux|windows|macos|freebsd)-(amd64|386|arm64|armv7|armv6)(\.exe)?$/;
// In the order of the download page: the most used first.
export const OS = { windows: 'Windows', macos: 'macOS', linux: 'Linux', freebsd: 'FreeBSD' };
export const ARCH = { amd64: 'x86-64', 386: 'x86 (32-bit)', arm64: 'ARM64', armv7: 'ARMv7 (32-bit)', armv6: 'ARMv6 (32-bit)' };

/**
 * @typedef {{ name: string, os: string, arch: string, platform: string, size: number,
 *   checksums: Record<string, string> }} Download
 */

/**
 * Reads the binaries of a folder; a missing or empty folder gives none.
 * @param {string} dir
 * @returns {{ files: Download[], sums: Record<string, string> }}
 */
export function loadDownloads(dir) {
  /** @type {Download[]} */
  const files = [];
  if (existsSync(dir)) {
    for (const name of readdirSync(dir).sort()) {
      const m = NAME.exec(name);
      if (!m) continue;
      // Check and read through one descriptor, so the file cannot be swapped in between.
      const fd = openSync(join(dir, name), 'r');
      let data;
      try {
        if (!fstatSync(fd).isFile()) continue;
        data = readFileSync(fd);
      } finally {
        closeSync(fd);
      }
      const checksums = Object.fromEntries(ALGORITHMS.map(([key, algo]) => [key, createHash(algo).update(data).digest('hex')]));
      const [, os, arch] = m;
      files.push({ name, os, arch, platform: `${OS[/** @type {keyof typeof OS} */ (os)]} ${ARCH[/** @type {keyof typeof ARCH} */ (arch)]}`, size: data.length, checksums });
    }
  }
  // The checksum files in the format of sha256sum and friends ("<hex>  <name>"), checked with -c.
  const sums = Object.fromEntries(ALGORITHMS.map(([key, , file]) => [file, files.map((f) => `${f.checksums[key]}  ${f.name}\n`).join('')]));
  return { files, sums };
}

/** "1.2.3" (also "v1.2.3", "1.2.3-rc.1"): [1, 2, 3], otherwise null. @param {string} v */
export function parseVersion(v) {
  const m = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+][0-9A-Za-z.+-]*)?$/.exec(String(v || '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** <0, 0 or >0. @param {number[]} a @param {number[]} b */
export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * The version rules for a request's X-Vanishly-Client ("<name>/<version>").
 * Without the header (curl, own code) or with a version that is no x.y.z
 * (a development build) nothing applies: this keeps clients compatible, it
 * is no access control.
 * @param {string | undefined} header
 * @param {{ min: string, recommended: string }} rules
 * @returns {'ok' | 'outdated' | 'refused'}
 */
export function clientStatus(header, rules) {
  const v = parseVersion(String(header || '').split('/')[1] || '');
  if (!v) return 'ok';
  const min = parseVersion(rules.min);
  if (min && compareVersions(v, min) < 0) return 'refused';
  const rec = parseVersion(rules.recommended);
  if (rec && compareVersions(v, rec) < 0) return 'outdated';
  return 'ok';
}
