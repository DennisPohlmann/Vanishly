// Vanishly - audit log (AUDIT_LOG): who did what, when, for whom, with which
// comment and run id. One JSON object per event, in one of three formats
// (AUDIT_LOG_FORMAT): ecs (Elastic Common Schema, the default), otel
// (OpenTelemetry log data model) or plain (Vanishly's own schema).
//
// Tamper evidence: every event carries its place in a hash chain per
// instance (seq, prev_hash, hash = SHA-256 over the canonical JSON of the
// event without hash and sig) and, with AUDIT_LOG_HMAC_KEY, an HMAC of that
// hash (sig). src/audit-verify.js checks a file: a changed, removed, added or
// moved event breaks the chain. The chain survives restarts (the last event
// of this instance is read back from the file or Redis).
//
// Never in an event: the secret, its ciphertext, key, passphrase, verifier,
// URL fragment, a full API token, or a secret/receipt id (only HMAC refs).
//
// Sinks: file (append-only, fsync), stdout, Redis stream (also feeds the
// admin view); exporters, best effort with retry: syslog (RFC 5424 over
// UDP, TCP or TLS), OTLP/HTTP logs, HTTP webhook (also Splunk HEC).
//
// Keys (below REDIS_PREFIX, only with AUDIT_LOG_REDIS=true):
//   audit                      stream  e = the event as written (JSON)
//   audit:head:<instance>      string  {"seq":n,"hash":"..."} of the last event

import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, openSync, readSync, writeSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { createSocket } from 'node:dgram';
import { connect as netConnect } from 'node:net';
import { hostname } from 'node:os';
import { connect as tlsConnect } from 'node:tls';

export const SCHEMA = 1;
export const GENESIS = '0'.repeat(64);
const ECS_VERSION = '8.11.0';

/**
 * @typedef {{ type: 'user' | 'api_token' | 'service_account' | 'app' | 'anonymous' | 'system', user?: string, name?: string,
 *   token?: { id: string, name: string }, onBehalfOf?: string }} Actor
 * @typedef {{ users?: string[], groups?: string[] }} People
 * @typedef {{
 *   id?: string, ts?: Date, type: string, outcome?: 'success' | 'denied' | 'error', reason?: string,
 *   actor?: Actor, secret?: { ref?: string, receiptRef?: string }, recipients?: People, responsible?: People,
 *   details?: Record<string, any>, comment?: string, runId?: string, traceId?: string, spanId?: string,
 *   source?: { ip?: string, userAgent?: string }, http?: { method?: string, route?: string, status?: number },
 * }} AuditEvent
 * @typedef {NonNullable<import('./config.js').Config['audit']>} AuditConfig
 */

// ------------------------------------------------------------------ JSON
/**
 * JSON with the keys of every object sorted: the input of the chain hash,
 * so the key order of a written event does not matter.
 * @param {any} v
 * @returns {string}
 */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

/**
 * Drops undefined, null, "" and empty arrays and objects (no noise in the
 * log); keeps false and 0. Key order stays as built.
 * @param {any} v
 * @returns {any}
 */
export function clean(v) {
  if (Array.isArray(v)) {
    const a = v.map(clean).filter((x) => x !== undefined);
    return a.length ? a : undefined;
  }
  if (v instanceof Date) return v.toISOString();
  if (v && typeof v === 'object') {
    /** @type {Record<string, any>} */
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      const c = clean(x);
      if (c !== undefined) o[k] = c;
    }
    return Object.keys(o).length ? o : undefined;
  }
  return v === null || v === '' || v === undefined ? undefined : v;
}

/**
 * Text from a caller (comment, on-behalf-of) as it may enter the log:
 * Unicode NFC, no control characters, single spaces, at most max characters.
 * @param {unknown} v @param {number} max
 */
export function sanitizeText(v, max) {
  if (typeof v !== 'string') return '';
  return v
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

/**
 * The size of a secret as a bucket, never the exact length.
 * @param {number} bytes
 */
export function sizeBucket(bytes) {
  for (const [limit, name] of /** @type {const} */ ([[64, '<=64B'], [256, '<=256B'], [1024, '<=1KB'], [4096, '<=4KB'], [16384, '<=16KB']])) {
    if (bytes <= limit) return name;
  }
  return '>16KB';
}

/**
 * W3C traceparent: "00-<trace id>-<parent id>-<flags>"; null if invalid.
 * @param {unknown} h
 */
export function parseTraceparent(h) {
  const m = typeof h === 'string' ? /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.exec(h.trim()) : null;
  if (!m || m[1] === 'ff' || /^0+$/.test(m[2]) || /^0+$/.test(m[3])) return null;
  return { traceId: m[2], parentId: m[3], flags: m[4] };
}

// ------------------------------------------------------------------ formats
/** ECS event.category / event.type per event type (prefix match). */
const ECS_KIND = /** @type {[RegExp, string, string][]} */ ([
  [/^auth\.login$/, 'authentication', 'start'],
  [/^auth\.logout$/, 'authentication', 'end'],
  [/^auth\./, 'authentication', 'info'],
  [/^api\.token_created$/, 'iam', 'creation'],
  [/^api\.token_revoked$/, 'iam', 'deletion'],
  [/^api\./, 'iam', 'access'],
  [/^admin\./, 'iam', 'admin'],
  [/^secret\.created$/, 'web', 'creation'],
  [/^secret\.burned$/, 'web', 'deletion'],
  [/^secret\./, 'web', 'access'],
  [/^receipt\./, 'web', 'access'],
  [/^system\.startup$/, 'process', 'start'],
  [/^system\.shutdown$/, 'process', 'end'],
  [/^(system|audit)\./, 'process', 'info'],
]);

/** @param {AuditEvent} e */
function level(e) {
  return e.outcome === 'error' ? 'error' : e.outcome === 'denied' ? 'warn' : 'info';
}

/** A short line for humans (message / Body). @param {AuditEvent} e */
export function message(e) {
  const who = e.actor?.type === 'api_token' || e.actor?.type === 'service_account' ? `${e.actor.user} via token ${e.actor.token?.name}` : e.actor?.user || e.actor?.name || e.actor?.type || 'system';
  const to = [...(e.recipients?.users || []), ...(e.recipients?.groups || [])];
  return `${e.type} ${e.outcome || 'success'}${e.reason ? ` (${e.reason})` : ''} by ${who}${to.length ? ` for ${to.join(', ')}` : ''}`;
}

/**
 * One event in a format, without hash and sig (added by the chain).
 * @param {AuditEvent & { id: string, ts: Date }} e
 * @param {'ecs' | 'otel' | 'plain'} format
 * @param {{ name: string, version: string, instance: string }} service
 * @param {{ seq: number, prev: string }} chain
 */
export function formatEvent(e, format, service, chain) {
  const a = e.actor || { type: 'anonymous' };
  const audit = { schema: SCHEMA, seq: chain.seq, instance: service.instance, prev_hash: chain.prev };
  const vanishly = {
    event: { type: e.type, outcome: e.outcome || 'success', reason: e.reason },
    actor: { type: a.type, token: a.token, on_behalf_of: a.onBehalfOf },
    secret: { ref: e.secret?.ref, receipt_ref: e.secret?.receiptRef },
    recipients: e.recipients,
    responsible: e.responsible,
    details: e.details,
    comment: e.comment,
    run_id: e.runId,
  };
  if (format === 'plain') {
    return clean({
      ts: e.ts,
      id: e.id,
      type: e.type,
      outcome: e.outcome || 'success',
      reason: e.reason,
      actor: { type: a.type, user: a.user, name: a.name, token: a.token, on_behalf_of: a.onBehalfOf },
      secret: vanishly.secret,
      recipients: e.recipients,
      responsible: e.responsible,
      details: e.details,
      comment: e.comment,
      run_id: e.runId,
      trace_id: e.traceId,
      source: { ip: e.source?.ip, user_agent: e.source?.userAgent },
      http: e.http,
      service: { name: service.name, version: service.version },
      message: message(e),
      audit,
    });
  }
  if (format === 'ecs') {
    const [category, type] = (ECS_KIND.find(([re]) => re.test(e.type)) || [null, 'web', 'info']).slice(1);
    const related = [...new Set([a.user, ...(e.recipients?.users || []), ...(e.responsible?.users || [])].filter(Boolean))];
    return clean({
      '@timestamp': e.ts,
      'log.level': level(e),
      message: message(e),
      'ecs.version': ECS_VERSION,
      event: {
        id: e.id,
        kind: 'event',
        dataset: 'vanishly.audit',
        action: e.type,
        category: [category],
        type: [e.outcome === 'denied' ? 'denied' : type],
        outcome: e.outcome === 'success' || !e.outcome ? 'success' : 'failure',
        reason: e.reason,
      },
      user: a.user || a.name ? { id: a.user, name: a.user || a.name, full_name: a.name, email: a.user } : undefined,
      related: { user: related },
      source: { ip: e.source?.ip },
      user_agent: { original: e.source?.userAgent },
      http: { request: { id: e.runId, method: e.http?.method }, response: { status_code: e.http?.status } },
      url: { path: e.http?.route },
      trace: { id: e.traceId },
      service: { name: service.name, version: service.version, node: { name: service.instance } },
      labels: { run_id: e.runId, actor_type: a.type, token_id: a.token?.id, token_name: a.token?.name },
      vanishly: { ...vanishly, audit },
    });
  }
  // otel: the OpenTelemetry log data model, attributes after the semantic conventions.
  const sev = level(e);
  return clean({
    Timestamp: e.ts,
    ObservedTimestamp: e.ts,
    TraceId: e.traceId,
    SpanId: e.spanId,
    SeverityText: sev === 'warn' ? 'WARN' : sev.toUpperCase(),
    SeverityNumber: sev === 'error' ? 17 : sev === 'warn' ? 13 : 9,
    Body: message(e),
    Resource: { 'service.name': service.name, 'service.version': service.version, 'service.instance.id': service.instance },
    InstrumentationScope: { Name: 'vanishly.audit' },
    Attributes: clean({
      'event.name': `vanishly.${e.type}`,
      'vanishly.event.id': e.id,
      'vanishly.event.outcome': e.outcome || 'success',
      'vanishly.event.reason': e.reason,
      'user.id': a.user,
      'user.name': a.user || a.name,
      'user.full_name': a.name,
      'user.email': a.user,
      'vanishly.actor.type': a.type,
      'vanishly.actor.token.id': a.token?.id,
      'vanishly.actor.token.name': a.token?.name,
      'vanishly.actor.on_behalf_of': a.onBehalfOf,
      'vanishly.secret.ref': e.secret?.ref,
      'vanishly.secret.receipt_ref': e.secret?.receiptRef,
      'vanishly.recipients.users': e.recipients?.users,
      'vanishly.recipients.groups': e.recipients?.groups,
      'vanishly.responsible.users': e.responsible?.users,
      'vanishly.responsible.groups': e.responsible?.groups,
      ...Object.fromEntries(Object.entries(e.details || {}).map(([k, v]) => [`vanishly.details.${k}`, v])),
      'vanishly.comment': e.comment,
      'vanishly.run_id': e.runId,
      'client.address': e.source?.ip,
      'user_agent.original': e.source?.userAgent,
      'http.request.method': e.http?.method,
      'http.route': e.http?.route,
      'http.response.status_code': e.http?.status,
      'vanishly.audit.schema': SCHEMA,
      'vanishly.audit.seq': chain.seq,
      'vanishly.audit.instance': service.instance,
      'vanishly.audit.prev_hash': chain.prev,
    }),
  });
}

/**
 * Reads and writes the chain fields of an event in any of the formats.
 * @param {any} rec
 */
export function chainOf(rec) {
  if (rec && typeof rec === 'object' && rec.Attributes && typeof rec.Attributes === 'object') {
    const at = rec.Attributes;
    /** @param {string} k */
    const key = (k) => `vanishly.audit.${k}`;
    return {
      format: 'otel',
      /** @param {string} k */ get: (k) => at[key(k)],
      /** @param {string} k @param {any} v */ set: (k, v) => void (at[key(k)] = v),
      /** @param {string} k */ del: (k) => void delete at[key(k)],
    };
  }
  const box = rec?.['@timestamp'] ? rec.vanishly?.audit : rec?.audit;
  return {
    format: rec?.['@timestamp'] ? 'ecs' : 'plain',
    /** @param {string} k */ get: (k) => box?.[k],
    /** @param {string} k @param {any} v */ set: (k, v) => void (box[k] = v),
    /** @param {string} k */ del: (k) => void (box && delete box[k]),
  };
}

/**
 * The hash of an event: SHA-256 over its canonical JSON without hash and sig.
 * @param {any} rec
 */
export function hashOf(rec) {
  const copy = structuredClone(rec);
  const c = chainOf(copy);
  c.del('hash');
  c.del('sig');
  return createHash('sha256').update(canonical(copy)).digest('hex');
}

/**
 * The same event in one shape for the admin view, whatever its format.
 * @param {any} r
 */
export function normalize(r) {
  const c = chainOf(r);
  if (c.format === 'otel') {
    const at = r.Attributes || {};
    return {
      ts: r.Timestamp,
      type: String(at['event.name'] || '').replace(/^vanishly\./, ''),
      outcome: at['vanishly.event.outcome'],
      reason: at['vanishly.event.reason'] || '',
      actor: { type: at['vanishly.actor.type'], user: at['user.id'] || '', name: at['user.full_name'] || '', token: at['vanishly.actor.token.name'] || '', onBehalfOf: at['vanishly.actor.on_behalf_of'] || '' },
      recipients: [...(at['vanishly.recipients.users'] || []), ...(at['vanishly.recipients.groups'] || [])],
      comment: at['vanishly.comment'] || '',
      runId: at['vanishly.run_id'] || '',
      ip: at['client.address'] || '',
      route: [at['http.request.method'], at['http.route']].filter(Boolean).join(' '),
      secretRef: at['vanishly.secret.ref'] || '',
      receiptRef: at['vanishly.secret.receipt_ref'] || '',
      responsible: [...(at['vanishly.responsible.users'] || []), ...(at['vanishly.responsible.groups'] || [])],
      details: Object.fromEntries(Object.entries(at).filter(([k]) => k.startsWith('vanishly.details.')).map(([k, x]) => [k.slice(17), x])),
      seq: c.get('seq'),
      instance: c.get('instance'),
    };
  }
  const v = c.format === 'ecs' ? r.vanishly || {} : r;
  const ev = c.format === 'ecs' ? v.event || {} : r;
  const actor = c.format === 'ecs' ? { ...(v.actor || {}), user: r.user?.id, name: r.user?.full_name } : r.actor || {};
  return {
    ts: c.format === 'ecs' ? r['@timestamp'] : r.ts,
    type: ev.type,
    outcome: ev.outcome,
    reason: ev.reason || '',
    actor: { type: actor.type, user: actor.user || '', name: actor.name || '', token: actor.token?.name || '', onBehalfOf: actor.on_behalf_of || '' },
    recipients: [...(v.recipients?.users || []), ...(v.recipients?.groups || [])],
    comment: v.comment || '',
    runId: v.run_id || '',
    ip: c.format === 'ecs' ? r.source?.ip || '' : r.source?.ip || '',
    route: c.format === 'ecs' ? [r.http?.request?.method, r.url?.path].filter(Boolean).join(' ') : [r.http?.method, r.http?.route].filter(Boolean).join(' '),
    secretRef: v.secret?.ref || '',
    receiptRef: v.secret?.receipt_ref || '',
    responsible: [...(v.responsible?.users || []), ...(v.responsible?.groups || [])],
    details: v.details || {},
    seq: c.get('seq'),
    instance: c.get('instance'),
  };
}

/**
 * The secrets as the audit log knows them (metadata only, never content or
 * keys): one entry per secret ref with creator, recipients, comment,
 * expiry, the openings (who, when, how) and the state, newest first.
 * @param {Iterable<any>} events normalized events, oldest first
 * @param {{ creator?: string, recipient?: string, status?: string, from?: number, to?: number, limit?: number }} [f]
 */
export function secretsOverview(events, f = {}, now = Date.now()) {
  /** @type {Map<string, any>} */
  const all = new Map();
  for (const e of events) {
    if (!e.secretRef || !/^(secret|receipt)\./.test(e.type)) continue;
    let s = all.get(e.secretRef);
    if (e.type === 'secret.created') {
      s = {
        ref: e.secretRef,
        receiptRef: e.receiptRef,
        created: e.ts,
        creator: { type: e.actor.type, user: e.actor.user, name: e.actor.name, token: e.actor.token },
        recipients: e.recipients,
        responsible: e.responsible,
        comment: e.comment,
        runId: e.runId,
        expires: e.details.expires || null,
        maxViews: Number(e.details.max_views || 1),
        passphrase: Boolean(e.details.passphrase),
        encrypted: e.details.encrypted || '',
        views: [],
        denied: 0,
        burned: null,
      };
      all.set(e.secretRef, s);
      continue;
    }
    if (!s) continue; // created before the log began
    if (e.type === 'secret.revealed') {
      s.views.push({ at: e.ts, by: e.actor.user || '', name: e.actor.name || '', type: e.actor.type, token: e.actor.token, via: e.actor.token ? 'token' : e.details.via === 'server' ? 'api' : 'browser' });
    } else if (e.type === 'secret.reveal_denied') s.denied++;
    else if (e.type === 'secret.burned') s.burned = { at: e.ts, reason: e.reason, by: e.actor.user || '' };
  }
  const t = (/** @type {string} */ v) => String(v || '').toLowerCase();
  const out = [];
  for (const s of all.values()) {
    s.status = s.burned ? 'burned' : s.views.length >= s.maxViews ? 'opened' : s.expires && Date.parse(s.expires) <= now ? 'expired' : s.views.length ? 'partly_opened' : 'open';
    const created = Date.parse(s.created);
    if (f.from && created < f.from) continue;
    if (f.to && created > f.to) continue;
    if (f.status && s.status !== f.status) continue;
    if (f.creator && !`${t(s.creator.user)} ${t(s.creator.name)} ${t(s.creator.token)}`.includes(t(f.creator))) continue;
    if (f.recipient && !s.recipients.some((/** @type {string} */ r) => t(r).includes(t(f.recipient)))) continue;
    out.push(s);
  }
  out.reverse();
  return out.slice(0, Math.min(Math.max(f.limit || 200, 1), 5000));
}

// ------------------------------------------------------------------ reading
/**
 * Splits text into the top-level JSON objects in it: one per line, or
 * pretty-printed (AUDIT_LOG_PRETTY). Yields { text, line } per object.
 * @param {string} text
 */
export function* splitObjects(text) {
  let depth = 0;
  let inStr = false;
  let esc = false;
  let start = -1;
  let line = 1;
  let startLine = 1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\n') line++;
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '{') {
      if (depth === 0) {
        start = i;
        startLine = line;
      }
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        yield { text: text.slice(start, i + 1), line: startLine };
        start = -1;
      }
      if (depth < 0) depth = 0;
    } else if (depth === 0 && !/\s/.test(ch)) {
      // Garbage between events: reported as its own entry.
      const end = text.indexOf('\n', i);
      yield { text: text.slice(i, end < 0 ? text.length : end), line };
      if (end < 0) break;
      i = end - 1;
    }
  }
  if (depth > 0 && start >= 0) yield { text: text.slice(start), line: startLine };
}

/**
 * Checks the hash chains in an audit log (any format, several instances).
 * @param {string} text
 * @param {{ hmacKey?: string }} [opts]
 */
export function verifyText(text, opts = {}) {
  /** @type {{ line: number, seq?: number, instance?: string, problem: string }[]} */
  const errors = [];
  /** @type {Map<string, { seq: number, hash: string, count: number, first: number, signed: number }>} */
  const heads = new Map();
  let count = 0;
  for (const { text: t, line } of splitObjects(text)) {
    count++;
    /** @type {any} */ let rec;
    try {
      rec = JSON.parse(t);
    } catch {
      errors.push({ line, problem: 'not valid JSON (changed or broken entry)' });
      continue;
    }
    const c = chainOf(rec);
    const seq = c.get('seq');
    const instance = c.get('instance');
    const hash = c.get('hash');
    const prev = c.get('prev_hash');
    if (!Number.isInteger(seq) || typeof instance !== 'string' || typeof hash !== 'string' || typeof prev !== 'string') {
      errors.push({ line, problem: 'no chain fields (seq, instance, prev_hash, hash)' });
      continue;
    }
    const at = { line, seq, instance };
    if (hashOf(rec) !== hash) errors.push({ ...at, problem: 'hash does not match the content (entry was changed)' });
    const sig = c.get('sig');
    if (opts.hmacKey) {
      if (typeof sig !== 'string') errors.push({ ...at, problem: 'no signature (sig), but a key was given' });
      else if (createHmac('sha256', opts.hmacKey).update(hash).digest('hex') !== sig) errors.push({ ...at, problem: 'signature does not match (entry or hash was forged)' });
    }
    const head = heads.get(instance);
    if (!head) {
      if (seq !== 1 || prev !== GENESIS) {
        errors.push({ ...at, problem: `chain starts at seq ${seq}, not 1 (earlier entries missing, or the file was cut at the front)` });
      }
      heads.set(instance, { seq, hash, count: 1, first: seq, signed: typeof sig === 'string' ? 1 : 0 });
      continue;
    }
    if (seq === 1 && prev === GENESIS) {
      errors.push({ ...at, problem: 'a new chain starts in the middle (entries before were removed, or the chain was reset)' });
    } else {
      if (seq !== head.seq + 1) errors.push({ ...at, problem: `seq ${seq} follows ${head.seq} (entries ${seq > head.seq ? 'missing' : 'moved or repeated'})` });
      if (prev !== head.hash) errors.push({ ...at, problem: 'prev_hash does not match the entry before (entry removed, inserted or moved)' });
    }
    head.seq = seq;
    head.hash = hash;
    head.count++;
    if (typeof sig === 'string') head.signed++;
  }
  return {
    ok: errors.length === 0,
    entries: count,
    instances: [...heads].map(([instance, h]) => ({ instance, entries: h.count, firstSeq: h.first, lastSeq: h.seq, head: h.hash, signed: h.signed })),
    errors,
  };
}

/**
 * The last event of an instance near the end of a file (for the restart).
 * @param {string} file
 * @param {string} instance
 */
function tailHead(file, instance) {
  /** @type {number} */ let fd;
  try {
    fd = openSync(file, 'r');
  } catch {
    return null;
  }
  try {
    const size = fstatSync(fd).size;
    let span = Math.min(size, 1 << 20);
    for (;;) {
      const buf = Buffer.alloc(span);
      readSync(fd, buf, 0, span, size - span);
      let text = buf.toString('utf8');
      // Start at an object that begins a line (JSONL and pretty output alike).
      if (span < size) text = text.slice(Math.max(0, text.indexOf('\n{') + 1));
      let found = null;
      for (const { text: t } of splitObjects(text)) {
        try {
          const rec = JSON.parse(t);
          const c = chainOf(rec);
          if (c.get('instance') === instance && Number.isInteger(c.get('seq'))) found = { seq: c.get('seq'), hash: c.get('hash') };
        } catch {}
      }
      if (found || span >= size) return found;
      span = Math.min(size, span * 4);
    }
  } finally {
    closeSync(fd);
  }
}

// ------------------------------------------------------------------ exporters
/**
 * Best-effort shipping with a bounded queue and retries (backoff up to
 * 30 s); the app never waits for it.
 */
class Shipper {
  /**
   * @param {string} name
   * @param {(batch: any[]) => Promise<void>} send
   * @param {number} [batchSize]
   */
  constructor(name, send, batchSize = 50) {
    this.name = name;
    this.send = send;
    this.batchSize = batchSize;
    /** @type {any[]} */ this.queue = [];
    this.busy = false;
    this.dropped = 0;
    this.failures = 0;
    /** @type {NodeJS.Timeout | null} */ this.timer = null;
  }

  /** @param {any} rec */
  push(rec) {
    if (this.queue.length >= 10000) {
      this.queue.shift();
      if (this.dropped++ % 1000 === 0) console.error(`audit: ${this.name} queue full, oldest events dropped`);
    }
    this.queue.push(rec);
    this.kick(0);
  }

  /** @param {number} ms */
  kick(ms) {
    if (this.busy || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush();
    }, ms);
    this.timer.unref?.();
  }

  async flush() {
    if (this.busy || !this.queue.length) return;
    this.busy = true;
    const batch = this.queue.slice(0, this.batchSize);
    try {
      await this.send(batch);
      this.queue.splice(0, batch.length);
      this.failures = 0;
    } catch (err) {
      this.failures++;
      if (this.failures === 1 || this.failures % 20 === 0) console.error(`audit: ${this.name} not reachable (${/** @type {Error} */ (err).message}), retrying`);
      if (this.failures >= 8) {
        // Give the batch up after about two minutes; the file/stdout/Redis copy stays.
        this.queue.splice(0, batch.length);
        this.dropped += batch.length;
        this.failures = 0;
        console.error(`audit: ${this.name}: ${batch.length} events not delivered`);
      }
    } finally {
      this.busy = false;
    }
    if (this.queue.length) this.kick(this.failures ? Math.min(30000, 500 * 2 ** this.failures) : 0);
  }

  /** Waits until the queue is empty or ms passed (shutdown, tests). @param {number} ms */
  async drain(ms) {
    const until = Date.now() + ms;
    while (this.queue.length && Date.now() < until) {
      await this.flush();
      if (this.queue.length) await new Promise((r) => setTimeout(r, 50));
    }
  }
}

/** @param {any} v OTLP AnyValue */
function otlpValue(v) {
  if (Array.isArray(v)) return { arrayValue: { values: v.map(otlpValue) } };
  if (typeof v === 'boolean') return { boolValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  if (v && typeof v === 'object') return { kvlistValue: { values: Object.entries(v).map(([key, x]) => ({ key, value: otlpValue(x) })) } };
  return { stringValue: String(v) };
}

/**
 * Flattens an object to dotted keys ("vanishly.audit.seq").
 * @param {any} v @param {string} [prefix] @param {Record<string, any>} [out]
 */
function flatten(v, prefix = '', out = {}) {
  for (const [k, x] of Object.entries(v || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (x && typeof x === 'object' && !Array.isArray(x)) flatten(x, key, out);
    else out[key] = x;
  }
  return out;
}

/**
 * The OTLP/HTTP JSON body for a batch of events (any format).
 * @param {{ rec: any, ev: AuditEvent & { ts: Date } }[]} batch
 * @param {{ name: string, version: string, instance: string }} service
 */
export function otlpBody(batch, service) {
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: service.name } },
            { key: 'service.version', value: { stringValue: service.version } },
            { key: 'service.instance.id', value: { stringValue: service.instance } },
          ],
        },
        scopeLogs: [
          {
            scope: { name: 'vanishly.audit' },
            logRecords: batch.map(({ rec, ev }) => {
              const sev = level(ev);
              const attrs = rec.Attributes ? rec.Attributes : flatten(rec);
              return {
                timeUnixNano: String(BigInt(ev.ts.getTime()) * 1000000n),
                observedTimeUnixNano: String(BigInt(ev.ts.getTime()) * 1000000n),
                severityNumber: sev === 'error' ? 17 : sev === 'warn' ? 13 : 9,
                severityText: sev === 'warn' ? 'WARN' : sev.toUpperCase(),
                body: { stringValue: message(ev) },
                attributes: Object.entries(attrs)
                  .filter(([k]) => !k.startsWith('Resource') && k !== 'Body')
                  .map(([key, value]) => ({ key, value: otlpValue(value) })),
                ...(ev.traceId ? { traceId: ev.traceId } : {}),
                ...(ev.spanId ? { spanId: ev.spanId } : {}),
              };
            }),
          },
        ],
      },
    ],
  };
}

/**
 * A syslog sender (RFC 5424; TCP and TLS with octet counting, RFC 6587).
 * @param {{ proto: 'udp' | 'tcp' | 'tls', host: string, port: number, ca?: string }} c
 * @param {string} instance
 */
function syslogSender(c, instance) {
  const host = hostname().replace(/[^\x21-\x7e]/g, '').slice(0, 255) || '-';
  /** @type {import('node:net').Socket | null} */ let sock = null;
  /** @type {import('node:dgram').Socket | null} */ let udp = null;
  /** @param {any} rec @param {AuditEvent & { ts: Date }} ev */
  const line = (rec, ev) => {
    // authpriv (10), severity: informational 6, warning 4, error 3.
    const sev = ev.outcome === 'error' ? 3 : ev.outcome === 'denied' ? 4 : 6;
    const msgid = ev.type.replace(/[^\x21-\x7e]/g, '').slice(0, 32);
    return `<${10 * 8 + sev}>1 ${ev.ts.toISOString()} ${host} vanishly - ${msgid} [vanishly@32473 instance="${instance.replace(/["\\\]]/g, '')}"] ${JSON.stringify(rec)}`;
  };
  const open = () =>
    new Promise((resolve, reject) => {
      const s =
        c.proto === 'tls'
          ? tlsConnect({ host: c.host, port: c.port, servername: c.host, ...(c.ca ? { ca: c.ca } : {}) }, () => resolve(s))
          : netConnect({ host: c.host, port: c.port }, () => resolve(s));
      s.setTimeout(10000, () => s.destroy(new Error('timeout')));
      s.once('error', (err) => {
        sock = null;
        reject(err);
      });
      s.on('close', () => (sock = null));
    });
  return {
    /** @param {{ rec: any, ev: AuditEvent & { ts: Date } }[]} batch */
    async send(batch) {
      if (c.proto === 'udp') {
        if (!udp) {
          udp = createSocket(c.host.includes(':') ? 'udp6' : 'udp4');
          udp.unref();
        }
        for (const { rec, ev } of batch) {
          const msg = Buffer.from(line(rec, ev));
          await new Promise((resolve, reject) => udp?.send(msg, c.port, c.host, (err) => (err ? reject(err) : resolve(undefined))));
        }
        return;
      }
      if (!sock) sock = /** @type {any} */ (await open());
      const data = batch.map(({ rec, ev }) => {
        const m = Buffer.from(line(rec, ev));
        return `${m.length} ${m.toString()}`;
      });
      await new Promise((resolve, reject) => sock?.write(data.join(''), (err) => (err ? reject(err) : resolve(undefined))));
    },
    close() {
      sock?.end();
      udp?.close();
    },
  };
}

// ------------------------------------------------------------------ the log
export class AuditError extends Error {}

export class Audit {
  /**
   * @param {AuditConfig} cfg
   * @param {{ redis?: any, p?: string, version?: string, fetch?: typeof fetch, write?: (line: string) => void }} [deps]
   *   write: stdout (tests capture it)
   */
  constructor(cfg, deps = {}) {
    this.c = cfg;
    this.redis = cfg.redis ? deps.redis : null;
    this.p = deps.p || '';
    this.fetch = deps.fetch || fetch;
    this.write = deps.write || ((/** @type {string} */ s) => void process.stdout.write(s));
    this.service = { name: 'vanishly', version: deps.version || '', instance: cfg.instance || hostname().replace(/[^\w.-]/g, '').slice(0, 64) || 'vanishly' };
    // HMAC key for refs and IP hashes: AUDIT_LOG_HMAC_KEY, else AUTH_SECRET,
    // else random (then refs change with every start).
    this.refKey = cfg.hmacKey || cfg.refKey || randomBytes(32).toString('hex');
    this.seq = 0;
    this.prev = GENESIS;
    /** @type {number | null} */ this.fd = null;
    this.failedAt = 0;
    /** @type {Promise<any>} */ this.queue = Promise.resolve();
    /** @type {Promise<void> | null} */ this.started = null;
    this.sinceCheckpoint = 0;
    /** @type {Shipper[]} */ this.shippers = [];
    /** @type {(() => void)[]} */ this.closers = [];
    if (cfg.webhook) {
      const w = cfg.webhook;
      this.shippers.push(
        new Shipper('webhook', async (batch) => {
          const body =
            w.envelope === 'splunk'
              ? batch.map(({ rec, ev }) => JSON.stringify({ time: ev.ts.getTime() / 1000, host: this.service.instance, source: 'vanishly', sourcetype: '_json', event: rec })).join('\n')
              : JSON.stringify(batch.length === 1 ? batch[0].rec : batch.map((b) => b.rec));
          const res = await this.fetch(w.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(w.auth ? { Authorization: w.auth } : {}) },
            body,
            signal: AbortSignal.timeout(10000),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
        }, cfg.webhook.envelope === 'splunk' ? 50 : 1),
      );
    }
    if (cfg.otlp) {
      const o = cfg.otlp;
      this.shippers.push(
        new Shipper('otlp', async (batch) => {
          const res = await this.fetch(o.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...o.headers },
            body: JSON.stringify(otlpBody(batch, this.service)),
            signal: AbortSignal.timeout(10000),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
        }),
      );
    }
    if (cfg.syslog) {
      const s = syslogSender(cfg.syslog, this.service.instance);
      this.closers.push(() => s.close());
      this.shippers.push(new Shipper('syslog', (batch) => s.send(batch)));
    }
  }

  /** A non-reversible reference to a secret or receipt id. @param {'s' | 'r'} kind @param {string} id */
  ref(kind, id) {
    return createHmac('sha256', this.refKey).update(`${kind}:${id}`).digest('base64url').slice(0, 22);
  }

  /** The client IP as AUDIT_LOG_IP says: full, hash or off. @param {string} ip */
  ip(ip) {
    const v = String(ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1');
    if (!v || this.c.ip === 'off') return '';
    return this.c.ip === 'hash' ? `hmac:${createHmac('sha256', this.refKey).update(`ip:${v}`).digest('base64url').slice(0, 22)}` : v;
  }

  /** Resumes the chain (file, else Redis) and logs the start. Once. */
  start() {
    if (!this.started) {
      this.started = (async () => {
        if (this.c.file) {
          this.fd = openSync(this.c.file, 'a', 0o640);
          const h = tailHead(this.c.file, this.service.instance);
          if (h) {
            this.seq = h.seq;
            this.prev = h.hash;
          }
        }
        if (!this.seq && this.redis) {
          const raw = await this.redis.get(`${this.p}audit:head:${this.service.instance}`);
          const h = raw ? JSON.parse(raw) : null;
          if (h && Number.isInteger(h.seq) && typeof h.hash === 'string') {
            this.seq = h.seq;
            this.prev = h.hash;
          }
        }
      })();
    }
    return this.started;
  }

  /**
   * AUDIT_LOG_FAIL=closed: false while the last write failed (less than 10 s
   * ago), so actions are refused before they change anything.
   */
  ready() {
    return !this.c.failClosed || !this.failedAt || Date.now() - this.failedAt > 10000;
  }

  /**
   * Writes one event. In order (one at a time, the chain needs it). Throws an
   * AuditError when a durable sink (file, Redis) fails and AUDIT_LOG_FAIL=closed.
   * @param {AuditEvent} ev
   */
  log(ev) {
    const run = this.queue.then(() => this.append(ev));
    this.queue = run.catch(() => {});
    return run;
  }

  /** @param {AuditEvent} input */
  async append(input) {
    await this.start();
    const ev = { ...input, id: input.id || randomUUID(), ts: input.ts || new Date() };
    const seq = this.seq + 1;
    const rec = formatEvent(ev, this.c.format, this.service, { seq, prev: this.prev });
    const hash = hashOf(rec);
    const c = chainOf(rec);
    c.set('hash', hash);
    if (this.c.hmacKey) c.set('sig', createHmac('sha256', this.c.hmacKey).update(hash).digest('hex'));
    const line = JSON.stringify(rec);
    const out = this.c.pretty ? `${JSON.stringify(rec, null, 2)}\n` : `${line}\n`;
    try {
      if (this.fd !== null) {
        writeSync(this.fd, out);
        if (this.c.fsync) fsyncSync(this.fd);
      }
      // The chain moves on once the event is in the file.
      this.seq = seq;
      this.prev = hash;
      if (this.redis) {
        const tx = this.redis.multi();
        tx.xAdd(`${this.p}audit`, '*', { e: line }, this.c.redisMaxLen ? { TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: this.c.redisMaxLen } } : undefined);
        tx.set(`${this.p}audit:head:${this.service.instance}`, JSON.stringify({ seq, hash }));
        await tx.exec();
      }
      this.failedAt = 0;
    } catch (err) {
      this.failedAt = Date.now();
      console.error(`audit: writing the audit log failed: ${/** @type {Error} */ (err).message}`);
      if (this.c.failClosed) throw new AuditError('audit log not writable');
    }
    if (this.c.stdout) {
      try {
        this.write(out);
      } catch {}
    }
    for (const s of this.shippers) s.push({ rec, ev });
    // AUDIT_LOG_CHECKPOINT: a checkpoint every n events, an anchor for the
    // copies in other systems (syslog, OTLP, stdout shippers).
    if (this.c.checkpoint && ev.type !== 'audit.checkpoint' && ++this.sinceCheckpoint >= this.c.checkpoint) {
      this.sinceCheckpoint = 0;
      await this.append({ type: 'audit.checkpoint', actor: { type: 'system' }, details: { head_seq: this.seq, head_hash: this.prev, events: this.c.checkpoint } });
    }
    return rec;
  }

  /**
   * Events for the admin view, newest first: from Redis (AUDIT_LOG_REDIS)
   * or the file. Filters on the normalized view.
   * @param {{ type?: string, actor?: string, recipient?: string, runId?: string, outcome?: string, from?: number, to?: number, q?: string, limit?: number }} f
   * @returns {Promise<{ records: any[], source: string }>}
   */
  async query(f) {
    const limit = Math.min(Math.max(f.limit || 200, 1), 5000);
    /** @param {any} n */
    const match = (n) => {
      const t = Date.parse(n.ts);
      if (f.from && t < f.from) return false;
      if (f.to && t > f.to) return false;
      if (f.type && !(n.type === f.type || (f.type.endsWith('.') && String(n.type).startsWith(f.type)))) return false;
      if (f.outcome && n.outcome !== f.outcome) return false;
      if (f.runId && n.runId !== f.runId) return false;
      const low = (/** @type {string} */ s) => String(s || '').toLowerCase();
      if (f.actor && !`${low(n.actor.user)} ${low(n.actor.name)} ${low(n.actor.token)}`.includes(low(f.actor))) return false;
      if (f.recipient && !n.recipients.some((/** @type {string} */ r) => low(r).includes(low(f.recipient)))) return false;
      if (f.q && !low(JSON.stringify(n)).includes(low(f.q))) return false;
      return true;
    };
    /** @type {any[]} */
    const out = [];
    if (this.redis) {
      let end = '+';
      // Newest first, in pages, at most 100 000 events scanned.
      for (let scanned = 0; out.length < limit && scanned < 100000; ) {
        const page = await this.redis.xRevRange(`${this.p}audit`, end, '-', { COUNT: 500 });
        if (!page.length) break;
        for (const m of page) {
          if (m.id === end) continue;
          scanned++;
          try {
            const rec = JSON.parse(m.message.e);
            if (match(normalize(rec))) out.push(rec);
          } catch {}
          if (out.length >= limit) break;
        }
        end = page[page.length - 1].id;
        if (page.length < 500) break;
      }
      return { records: out, source: 'redis' };
    }
    if (this.c.file) {
      const text = await readAll(this.c.file);
      const all = [];
      for (const { text: t } of splitObjects(text)) {
        try {
          const rec = JSON.parse(t);
          if (match(normalize(rec))) all.push(rec);
        } catch {}
      }
      return { records: all.slice(-limit).reverse(), source: 'file' };
    }
    return { records: [], source: '' };
  }

  /**
   * All events in the Redis stream, oldest first, normalized (at most max).
   * @param {number} [max]
   */
  async *streamEvents(max = 200000) {
    if (!this.redis) return;
    let start = '-';
    for (let n = 0; n < max; ) {
      const page = await this.redis.xRange(`${this.p}audit`, start, '+', { COUNT: 1000 });
      if (!page.length) return;
      for (const m of page) {
        if (m.id === start) continue;
        n++;
        try {
          yield normalize(JSON.parse(m.message.e));
        } catch {}
      }
      if (page.length < 1000) return;
      start = page[page.length - 1].id;
    }
  }

  /**
   * The secrets overview of the admin page (needs AUDIT_LOG_REDIS).
   * @param {Parameters<typeof secretsOverview>[1]} f
   */
  async secrets(f) {
    const events = [];
    for await (const e of this.streamEvents()) events.push(e);
    return secretsOverview(events, f);
  }

  /** Checks the chain of the file (admin view). */
  async verifyFile() {
    if (!this.c.file) return null;
    return verifyText(await readAll(this.c.file), { hmacKey: this.c.hmacKey });
  }

  async close() {
    await this.queue;
    await Promise.all(this.shippers.map((s) => s.drain(3000)));
    for (const c of this.closers) c();
    if (this.fd !== null) closeSync(this.fd);
    this.fd = null;
  }
}

/** @param {string} file */
async function readAll(file) {
  const chunks = [];
  for await (const c of createReadStream(file)) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}
