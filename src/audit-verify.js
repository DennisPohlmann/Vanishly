#!/usr/bin/env node
// Vanishly - checks the hash chain of an audit log file (AUDIT_LOG_FILE),
// in any format (ecs, otel, plain; one per line or pretty-printed).
//
//   node src/audit-verify.js <file> [<file> ...] [--key-file <file>] [--json] [--expect-head <instance>=<hash>]
//   npm run audit:verify -- /var/log/vanishly/audit.jsonl
//
// The HMAC key (AUDIT_LOG_HMAC_KEY) checks the signatures too: from
// --key-file or the environment (AUDIT_LOG_HMAC_KEY, AUDIT_LOG_HMAC_KEY_FILE).
// --expect-head compares the last hash of an instance with one kept
// elsewhere (a checkpoint in syslog/OTLP): this finds a cut-off end.
// Exit code: 0 intact, 1 broken, 2 usage or read error.

import { readFileSync } from 'node:fs';
import { verifyText } from './audit.js';

const args = process.argv.slice(2);
/** @type {string[]} */ const files = [];
let json = false;
let key = '';
/** @type {Record<string, string>} */ const expect = {};
try {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') json = true;
    else if (a === '--key-file') key = readFileSync(args[++i] || '', 'utf8').split(/\r?\n/)[0].trim();
    else if (a === '--expect-head') {
      const m = /^([\w.-]+)=([0-9a-f]{64})$/.exec(args[++i] || '');
      if (!m) throw new Error('--expect-head <instance>=<64 hex>');
      expect[m[1]] = m[2];
    } else if (a === '-h' || a === '--help') {
      console.log('usage: node src/audit-verify.js <file> [...] [--key-file <file>] [--json] [--expect-head <instance>=<hash>]');
      process.exit(0);
    } else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else files.push(a);
  }
  if (!files.length) throw new Error('no file given');
  if (!key && process.env.AUDIT_LOG_HMAC_KEY_FILE) key = readFileSync(process.env.AUDIT_LOG_HMAC_KEY_FILE, 'utf8').split(/\r?\n/)[0].trim();
  if (!key && process.env.AUDIT_LOG_HMAC_KEY) key = process.env.AUDIT_LOG_HMAC_KEY;
} catch (err) {
  console.error(`audit-verify: ${/** @type {Error} */ (err).message}`);
  process.exit(2);
}

let broken = false;
for (const file of files) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    console.error(`audit-verify: cannot read ${file} (${/** @type {NodeJS.ErrnoException} */ (err).code || 'error'})`);
    process.exit(2);
  }
  const r = verifyText(text, { hmacKey: key || undefined });
  for (const [instance, hash] of Object.entries(expect)) {
    const h = r.instances.find((i) => i.instance === instance);
    if (!h) r.errors.push({ line: 0, instance, problem: 'instance not in the file' });
    else if (h.head !== hash) r.errors.push({ line: 0, instance, problem: `last hash ${h.head.slice(0, 12)}… is not the expected ${hash.slice(0, 12)}… (end cut off or replaced)` });
  }
  r.ok = r.errors.length === 0;
  if (!r.ok) broken = true;
  if (json) {
    console.log(JSON.stringify({ file, ...r, signatures: key ? 'checked' : 'not checked (no key)' }));
    continue;
  }
  console.log(`${file}: ${r.ok ? 'OK' : 'BROKEN'} - ${r.entries} events, signatures ${key ? 'checked' : 'not checked (no key)'}`);
  for (const i of r.instances) console.log(`  instance ${i.instance}: seq ${i.firstSeq}..${i.lastSeq} (${i.entries} events, ${i.signed} signed), head ${i.head}`);
  for (const e of r.errors.slice(0, 50)) console.log(`  line ${e.line}${e.seq !== undefined ? ` (seq ${e.seq})` : ''}: ${e.problem}`);
  if (r.errors.length > 50) console.log(`  ... and ${r.errors.length - 50} more`);
}
process.exit(broken ? 1 : 0);
