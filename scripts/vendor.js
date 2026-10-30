// Vanishly - copies the browser bundle of the API reference (Scalar) to
// vendor/scalar.js, served at /api/docs/assets/scalar.js. The @font-face
// rules for fonts.scalar.com are taken out: the page loads nothing from other
// servers (the Content Security Policy would block them anyway).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const from = join(root, 'node_modules', '@scalar', 'api-reference', 'dist', 'browser', 'standalone.js');
const js = readFileSync(from, 'utf8').replace(/@font-face\s*\{[^{}]*?fonts\.scalar\.com[^{}]*\}/g, '');
// Every host the bundle names in a URL (https://host, //host), compared exactly.
const hosts = new Set([...js.matchAll(/(?:https?:)?\/\/([\w.-]+)/g)].map((m) => m[1].toLowerCase()));
if (hosts.has('fonts.scalar.com')) throw new Error('vendor: fonts.scalar.com still referenced');
mkdirSync(join(root, 'vendor'), { recursive: true });
writeFileSync(join(root, 'vendor', 'scalar.js'), js);
console.log('vendor/scalar.js');
