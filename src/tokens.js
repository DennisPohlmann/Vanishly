// Vanishly - personal API tokens (API_TOKENS): every signed-in user (or only
// those API_TOKEN_USERS / API_TOKEN_GROUPS allow) makes their own tokens on
// the "API tokens" page. A token acts as its owner, only from its IP
// addresses / networks, with its scopes, until it expires or is revoked.
//
// Format: vnly_<id: 16 hex>_<secret: 43 base64url> (256 random bits; the
// prefix lets secret scanners find leaked tokens). Shown once; Redis keeps
// only HMAC-SHA256(pepper, token), the pepper derived from AUTH_SECRET.
//
// Keys (below REDIS_PREFIX):
//   tok:<id>          hash  h own nm ids name created expires ips scopes revoked used by
//                           (h: the HMAC; own/nm: owner address and name; ids: the
//                           owner's recipient hashes, renewed at each sign-in);
//                           kept 30 days after expiry or revocation
//   tok:u:<owner>     set   the token ids of a user (owner = HMAC of the address)
//   tok:all           set   all token ids (admin list)
//   tokpol:<hash>     hash  type (user|group) subject scopes max by at: a token policy set by
//                           an admin (API_TOKEN_ADMIN_POLICY); hash = the recipient hash of
//                           the address or group (src/auth.js), so it matches the user's ids
//   tokpol:all        set   the hashes of all policies

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { expiryAt, parseScopes, SCOPES } from './config.js';

export { SCOPES };
// Admin functions over the API: only for technical users' tokens, given by an admin (API_ADMIN_TOKENS).
export const ADMIN_SCOPE = 'admin';
const SVC_NAME = /^[a-z0-9][a-z0-9_.-]{1,63}$/;
const TOKEN = /^vnly_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const KEEP = 30 * 86400 * 1000;

/**
 * "203.0.113.0/24, 2001:db8::/32, 198.51.100.7" to normalized networks;
 * throws on anything else.
 * @param {unknown} v string or list
 */
export function parseNetworks(v) {
  const parts = Array.isArray(v) ? v : String(v ?? '').split(/[\s,;]+/);
  /** @type {string[]} */
  const out = [];
  for (const raw of parts) {
    if (typeof raw !== 'string') throw new Error('a network must be a string');
    const p = raw.trim();
    if (!p) continue;
    const m = /^([0-9a-fA-F.:]+)(?:\/(\d{1,3}))?$/.exec(p);
    const fam = m ? isIP(m[1]) : 0;
    if (!m || !fam) throw new Error(`"${p.slice(0, 60)}" is no IP address or network (CIDR)`);
    const bits = m[2] === undefined ? (fam === 4 ? 32 : 128) : Number(m[2]);
    if (bits > (fam === 4 ? 32 : 128) || (fam === 4 ? bits < 8 : bits < 16)) throw new Error(`"${p}": prefix length out of range`);
    const n = `${m[1].toLowerCase()}/${bits}`;
    if (!out.includes(n)) out.push(n);
  }
  if (out.length > 20) throw new Error('at most 20 networks');
  return out;
}

/** "::ffff:203.0.113.5" counts as 203.0.113.5. @param {string} ip */
export function plainIp(ip) {
  return String(ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
}

/**
 * True when ip lies in one of the networks.
 * @param {string} ipIn @param {string[]} nets
 */
export function ipAllowed(ipIn, nets) {
  const ip = plainIp(ipIn);
  const fam = isIP(ip);
  if (!fam) return false;
  const bl = new BlockList();
  for (const n of nets) {
    const [addr, bits] = n.split('/');
    bl.addSubnet(addr, Number(bits), isIP(addr) === 4 ? 'ipv4' : 'ipv6');
  }
  return bl.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

/**
 * @typedef {{ id: string, name: string, owner: string, ownerName: string, ids: string[], created: number,
 *   expires: number, ips: string[], scopes: string[], revoked: number, used: number, revokedBy: string, svc: string }} TokenRecord
 *   svc: the technical user it belongs to ('' for a person's token)
 * @typedef {{ name: string, description: string, responsible: string, ips: string[], enabled: boolean,
 *   max: number | null, created: number, by: string, updated: number }} Service a technical user
 * @typedef {{ scopes: string[], max: number, source: 'user' | 'group' | 'env-group' | 'default' }} Policy
 *   what a user's tokens may do and how many active ones they may have (0 = no limit)
 * @typedef {{ type: 'user' | 'group', subject: string, scopes: string[], max: number | null, by: string, at: number }} StoredPolicy
 */

/** The most permissive of several limits (0 = no limit). @param {number[]} list */
function widest(list) {
  return list.includes(0) ? 0 : Math.max(...list);
}

/** @param {string[]} a @param {string[]} b */
const subset = (a, b) => a.every((s) => b.includes(s));

/** The shorter of two lifetimes ("never" is the longest). @param {string} a @param {string} b */
function shorter(a, b) {
  if (a === 'never') return b;
  if (b === 'never') return a;
  const ref = Date.UTC(2001, 0, 1);
  return expiryAt(a, ref) <= expiryAt(b, ref) ? a : b;
}

export class Tokens {
  /**
   * @param {NonNullable<NonNullable<import('./config.js').Config['auth']>['tokens']>} cfg
   * @param {{ redis: any, p: string }} store
   * @param {{ secret: string }} authCfg
   * @param {(kind: 'u' | 'g', v: string) => string} hash the recipient hash of src/auth.js
   */
  constructor(cfg, store, authCfg, hash) {
    this.c = cfg;
    this.redis = store.redis;
    this.p = store.p;
    this.pepper = createHmac('sha256', authCfg.secret).update('vanishly api tokens v1').digest();
    this.hash = hash;
  }

  /** @param {string} token */
  digest(token) {
    return createHmac('sha256', this.pepper).update(token).digest();
  }

  /** @param {string} owner address */
  ownerKey(owner) {
    return `${this.p}tok:u:${this.hash('u', owner)}`;
  }

  /**
   * May this user make tokens (API_TOKEN_USERS / API_TOKEN_GROUPS)?
   * @param {import('./auth.js').User | null} user
   */
  mayCreate(user) {
    if (!user?.user || user.app || user.token) return false;
    const { users, groups } = this.c;
    if (!users.length && !groups.length) return true;
    return users.includes(user.user) || groups.some((g) => user.ids.includes(this.hash('g', g)));
  }

  /** @param {Record<string, string>} h @param {string} id @returns {TokenRecord} */
  static record(h, id) {
    return {
      id,
      name: h.name || '',
      owner: h.own || '',
      ownerName: h.nm || '',
      ids: (h.ids || '').split(' ').filter(Boolean),
      created: Number(h.created || 0),
      expires: Number(h.expires || 0),
      ips: (h.ips || '').split(' ').filter(Boolean),
      scopes: (h.scopes || '').split(' ').filter(Boolean),
      revoked: Number(h.revoked || 0),
      revokedBy: h.by || '',
      used: Number(h.used || 0),
      svc: h.svc || '',
    };
  }

  /** What the token pages and the API show (never the hash). @param {TokenRecord} r */
  static view(r, now = Date.now()) {
    return {
      id: r.id,
      name: r.name,
      prefix: `vnly_${r.id}_`,
      owner: r.owner,
      ownerName: r.ownerName,
      created: new Date(r.created).toISOString(),
      expires: r.expires ? new Date(r.expires).toISOString() : null,
      lastUsed: r.used ? new Date(r.used).toISOString() : null,
      ips: r.ips,
      scopes: r.scopes,
      state: r.revoked ? 'revoked' : r.expires && r.expires <= now ? 'expired' : 'active',
      revoked: r.revoked ? new Date(r.revoked).toISOString() : null,
      kind: r.svc ? 'service' : 'user',
      ...(r.svc ? { service: r.svc } : {}),
    };
  }

  /**
   * Makes a token for a user. The caller checks mayCreate().
   * @param {import('./auth.js').User} user
   * @param {{ name?: unknown, expires?: unknown, ips?: unknown, scopes?: unknown }} b
   * @returns {Promise<{ token: string, record: TokenRecord } | { error: string, message: string, active?: number, max?: number, allowed?: string[] }>}
   */
  async create(user, b) {
    // What this user may give a token (API_TOKEN_ALLOWED_SCOPES, by group, admin policy).
    const policy = await this.policy(user.user, user.ids);
    return this.issue({ owner: user.user, ownerName: user.name || user.user, ids: user.ids, svc: '' }, b, {
      allowed: policy.scopes,
      defaults: this.defaultScopes(policy),
      max: policy.max,
      maxExpiry: this.c.maxExpiry,
      ipsRequired: this.c.ipBinding === 'required',
    });
  }

  /**
   * Makes a token for a user or a technical user under the given rules.
   * @param {{ owner: string, ownerName: string, ids: string[], svc: string }} who
   * @param {{ name?: unknown, expires?: unknown, ips?: unknown, scopes?: unknown }} b
   * @param {{ allowed: string[], defaults: string[], max: number, maxExpiry: string, ipsRequired: boolean }} rules
   * @returns {Promise<{ token: string, record: TokenRecord } | { error: string, message: string, active?: number, max?: number, allowed?: string[] }>}
   */
  async issue(who, b, rules) {
    const name = typeof b.name === 'string' ? b.name.normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').trim() : '';
    if (!name || name.length > 64) return { error: 'invalid_name', message: 'name: 1 to 64 characters' };
    const choice = b.expires === undefined || b.expires === null || b.expires === '' ? this.c.defaultExpiry : String(b.expires);
    if (!this.c.expiryOptions.includes(choice)) {
      return { error: 'invalid_expiry', message: `expires must be one of ${this.c.expiryOptions.join(', ')}` };
    }
    const now = Date.now();
    const expires = expiryAt(choice, now);
    // API_TOKEN_MAX_EXPIRY (API_ADMIN_TOKEN_MAX_EXPIRY for admin tokens), checked on the exact date.
    if (rules.maxExpiry !== 'never' && (!expires || expires > expiryAt(rules.maxExpiry, now))) {
      return { error: 'invalid_expiry', message: `at most ${rules.maxExpiry}` };
    }
    let ips;
    try {
      ips = parseNetworks(b.ips ?? []);
    } catch (err) {
      return { error: 'invalid_ips', message: /** @type {Error} */ (err).message };
    }
    if (rules.ipsRequired && !ips.length) return { error: 'ips_required', message: 'At least one IP address or network is required for this token' };
    const scopes = b.scopes === undefined ? rules.defaults : b.scopes;
    const valid = [...SCOPES, ...(who.svc ? [ADMIN_SCOPE] : [])];
    if (!Array.isArray(scopes) || !scopes.length || scopes.some((s) => !valid.includes(s))) {
      return { error: 'invalid_scopes', message: `scopes: a list of ${valid.join(', ')}` };
    }
    if (!subset(scopes, rules.allowed)) {
      return { error: 'scope_not_allowed', message: rules.allowed.length ? `This token may only have: ${rules.allowed.join(', ')}` : 'No scope may be given here', allowed: rules.allowed };
    }
    const own = this.ownerKey(who.owner);
    // The limit (0 = none): only active tokens count.
    const max = rules.max;
    let active = await this.active(who.owner);
    if (max && active >= max) return { error: 'too_many_tokens', message: `At most ${max} active tokens; revoke one first`, active, max };
    const id = randomBytes(8).toString('hex');
    const token = `vnly_${id}_${randomBytes(32).toString('base64url')}`;
    const key = `${this.p}tok:${id}`;
    const tx = this.redis.multi().hSet(key, {
      h: this.digest(token).toString('base64url'),
      own: who.owner,
      nm: who.ownerName,
      ids: who.ids.join(' '),
      name,
      created: String(now),
      expires: String(expires),
      ips: ips.join(' '),
      scopes: valid.filter((s) => scopes.includes(s)).join(' '),
      ...(who.svc ? { svc: who.svc } : {}),
    });
    if (expires) tx.pExpireAt(key, expires + KEEP);
    await tx.sAdd(own, id).sAdd(`${this.p}tok:all`, id).exec();
    // Two requests at the same time may both have passed the check: count
    // again and take this one back if the limit is now exceeded.
    active = await this.active(who.owner);
    if (max && active > max) {
      await this.redis.multi().del(key).sRem(own, id).sRem(`${this.p}tok:all`, id).exec();
      return { error: 'too_many_tokens', message: `At most ${max} active tokens; revoke one first`, active: active - 1, max };
    }
    return { token, record: /** @type {TokenRecord} */ (await this.get(id)) };
  }

  /**
   * How many active (not revoked, not expired) tokens a user has.
   * @param {string} owner address
   */
  async active(owner, now = Date.now()) {
    return (await this.list(owner)).filter((t) => Tokens.active(t, now)).length;
  }

  /** @param {TokenRecord} t */
  static active(t, now = Date.now()) {
    return !t.revoked && (!t.expires || t.expires > now);
  }

  /** @param {string} id */
  async get(id) {
    if (!/^[0-9a-f]{16}$/.test(id)) return null;
    const h = await this.redis.hGetAll(`${this.p}tok:${id}`);
    return h?.h ? Tokens.record(h, id) : null;
  }

  /**
   * The tokens of one user, or all (owner ''); ids of gone tokens are cleaned up.
   * @param {string} owner
   */
  async list(owner) {
    const set = owner ? this.ownerKey(owner) : `${this.p}tok:all`;
    const ids = await this.redis.sMembers(set);
    /** @type {TokenRecord[]} */
    const out = [];
    for (const id of ids) {
      const r = await this.get(id);
      if (r && (!owner || r.owner === owner)) out.push(r);
      else if (!r) await this.redis.sRem(set, id);
    }
    return out.sort((a, b) => b.created - a.created);
  }

  /**
   * Revokes a token (its owner, or an admin with owner '').
   * @param {string} id @param {string} owner @param {string} by who revoked it
   */
  async revoke(id, owner, by) {
    const r = await this.get(id);
    if (!r || (owner && r.owner !== owner)) return null;
    if (r.revoked) return r;
    const key = `${this.p}tok:${id}`;
    const now = Date.now();
    await this.redis.multi().hSet(key, { revoked: String(now), by }).pExpireAt(key, now + KEEP).exec();
    return { ...r, revoked: now, revokedBy: by };
  }

  /**
   * Lets a token expire earlier (rotation with a grace period).
   * @param {string} id @param {number} at ms
   */
  async shorten(id, at) {
    const t = await this.get(id);
    if (!t || (t.expires && t.expires <= at)) return;
    const key = `${this.p}tok:${id}`;
    await this.redis.multi().hSet(key, 'expires', String(at)).pExpireAt(key, at + KEEP).exec();
  }

  /**
   * Checks a bearer token from ip. A reason on refusal: malformed, unknown,
   * revoked, expired, ip_denied (the record then says whose token it was).
   * @param {string} token @param {string} ip
   * @returns {Promise<{ ok: true, record: TokenRecord, scopes: string[], policy: Policy } | { ok: false, reason: string, record?: TokenRecord }>}
   *   scopes: what the token may do now (its scopes within the owner's current policy)
   */
  async verify(token, ip) {
    const m = TOKEN.exec(token);
    if (!m) return { ok: false, reason: 'malformed' };
    const h = await this.redis.hGetAll(`${this.p}tok:${m[1]}`);
    if (!h?.h) return { ok: false, reason: 'unknown' };
    const want = Buffer.from(h.h, 'base64url');
    const got = this.digest(token);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return { ok: false, reason: 'unknown' };
    const record = Tokens.record(h, m[1]);
    if (record.revoked) return { ok: false, reason: 'revoked', record };
    if (record.expires && record.expires <= Date.now()) return { ok: false, reason: 'expired', record };
    // A token bound to networks works only from there (stops passing it on);
    // API_TOKEN_IP_BINDING=required makes every token bound.
    if ((record.ips.length || this.c.ipBinding === 'required') && !ipAllowed(ip, record.ips)) return { ok: false, reason: 'ip_denied', record };
    if (record.svc) {
      // A technical user's token: only while the technical user is enabled.
      const svc = await this.service(record.svc);
      if (!svc?.enabled) return { ok: false, reason: 'disabled', record };
    }
    await this.redis.hSet(`${this.p}tok:${m[1]}`, 'used', String(Date.now()));
    if (record.svc) {
      // "admin" only while API_ADMIN_TOKENS is on, and (API_ADMIN_TOKEN_REQUIRE_IP) for a token bound to networks.
      const a = this.c.adminTokens;
      const scopes = record.scopes.filter((s) => s !== ADMIN_SCOPE || (a.enabled && (!a.requireIp || record.ips.length > 0)));
      return { ok: true, record, scopes, policy: { scopes: record.scopes, max: 0, source: 'default' } };
    }
    // The policy of today counts, not the one at creation: a tightened
    // policy takes scopes away from existing tokens at once.
    const policy = await this.policy(record.owner, record.ids);
    return { ok: true, record, scopes: record.scopes.filter((s) => policy.scopes.includes(s)), policy };
  }

  // ------------------------------------------------------------ policies
  /**
   * What a user's tokens may do and how many active ones the user may have:
   * an admin policy for the user (API_TOKEN_ADMIN_POLICY), else the admin
   * policies of the user's groups (together), else API_TOKEN_SCOPES_BY_GROUP
   * (together), else API_TOKEN_ALLOWED_SCOPES and API_TOKEN_MAX_PER_USER.
   * @param {string} owner address @param {string[]} ids the user's recipient hashes
   * @returns {Promise<Policy>}
   */
  async policy(owner, ids) {
    const self = this.hash('u', owner);
    if (this.c.adminPolicy) {
      const keys = [self, ...ids.filter((i) => i !== self)];
      const rows = /** @type {Record<string, string>[]} */ (await Promise.all(keys.map((k) => this.redis.hGetAll(`${this.p}tokpol:${k}`))));
      const mine = rows[0]?.type === 'user' ? Tokens.storedPolicy(rows[0]) : null;
      if (mine) return { scopes: mine.scopes, max: mine.max ?? this.c.maxPerUser, source: 'user' };
      const groups = rows.slice(1).filter((r) => r?.type === 'group').map((r) => Tokens.storedPolicy(r));
      if (groups.length) {
        return { scopes: SCOPES.filter((s) => groups.some((g) => g.scopes.includes(s))), max: widest(groups.map((g) => g.max ?? this.c.maxPerUser)), source: 'group' };
      }
    }
    const byGroup = this.c.scopesByGroup.filter((g) => ids.includes(this.hash('g', g.group)));
    if (byGroup.length) return { scopes: SCOPES.filter((s) => byGroup.some((g) => g.scopes.includes(s))), max: this.c.maxPerUser, source: 'env-group' };
    return { scopes: this.c.allowedScopes, max: this.c.maxPerUser, source: 'default' };
  }

  /**
   * The scopes the form preselects: API_TOKEN_DEFAULT_SCOPES within the
   * policy, else "create" and/or "read" as far as allowed.
   * @param {Policy} policy
   */
  defaultScopes(policy) {
    const d = this.c.defaultScopes.filter((s) => policy.scopes.includes(s));
    if (d.length) return d;
    const core = policy.scopes.filter((s) => s !== 'status');
    return core.length ? core : policy.scopes;
  }

  /** @param {Record<string, string>} h @returns {StoredPolicy} */
  static storedPolicy(h) {
    return {
      type: h.type === 'group' ? 'group' : 'user',
      subject: h.subject || '',
      scopes: (h.scopes || '').split(' ').filter((s) => SCOPES.includes(s)),
      max: h.max === undefined || h.max === '' ? null : Number(h.max),
      by: h.by || '',
      at: Number(h.at || 0),
    };
  }

  /** All admin policies, users first, then groups, by name. */
  async policies() {
    const hashes = await this.redis.sMembers(`${this.p}tokpol:all`);
    /** @type {(StoredPolicy & { key: string })[]} */
    const out = [];
    for (const k of hashes) {
      const h = await this.redis.hGetAll(`${this.p}tokpol:${k}`);
      if (h?.type) out.push({ ...Tokens.storedPolicy(h), key: k });
      else await this.redis.sRem(`${this.p}tokpol:all`, k);
    }
    return out.sort((a, b) => (a.type === b.type ? a.subject.localeCompare(b.subject) : a.type === 'user' ? -1 : 1));
  }

  /**
   * Sets (or, with remove, deletes) the policy of a user or group; returns
   * the old and the new one for the audit log. The caller checks the subject.
   * @param {{ type: 'user' | 'group', subject: string, scopes?: unknown, max?: unknown, remove?: boolean }} b
   * @param {string} by the admin
   * @returns {Promise<{ old: StoredPolicy | null, new: StoredPolicy | null } | { error: string, message: string }>}
   */
  async setPolicy(b, by) {
    const key = this.hash(b.type === 'user' ? 'u' : 'g', b.subject);
    const k = `${this.p}tokpol:${key}`;
    const before = await this.redis.hGetAll(k);
    const old = before?.type ? Tokens.storedPolicy(before) : null;
    if (b.remove) {
      await this.redis.multi().del(k).sRem(`${this.p}tokpol:all`, key).exec();
      return { old, new: null };
    }
    let scopes;
    try {
      scopes = Array.isArray(b.scopes) ? parseScopes(b.scopes.join(',') || 'none') : parseScopes(String(b.scopes ?? ''));
    } catch (err) {
      return { error: 'invalid_scopes', message: /** @type {Error} */ (err).message };
    }
    const max = b.max === undefined || b.max === null || b.max === '' ? null : Number(b.max);
    if (max !== null && (!Number.isInteger(max) || max < 0 || max > 1000)) return { error: 'invalid_max', message: 'max: 0 to 1000 (0 = no limit), or empty for the default' };
    /** @type {StoredPolicy} */
    const now = { type: b.type, subject: b.subject, scopes, max, by, at: Date.now() };
    await this.redis
      .multi()
      .hSet(k, { type: now.type, subject: now.subject, scopes: scopes.join(' '), max: max === null ? '' : String(max), by, at: String(now.at) })
      .sAdd(`${this.p}tokpol:all`, key)
      .exec();
    return { old, new: now };
  }

  /**
   * Revokes the active tokens whose scopes their owner's policy no longer
   * allows (an admin's choice when tightening a policy).
   * @param {string} by
   */
  async revokeExceeding(by) {
    /** @type {TokenRecord[]} */
    const done = [];
    for (const t of await this.list('')) {
      if (!Tokens.active(t) || t.svc) continue;
      const p = await this.policy(t.owner, t.ids);
      if (!subset(t.scopes, p.scopes)) {
        await this.revoke(t.id, '', by);
        done.push(t);
      }
    }
    return done;
  }

  /**
   * At sign-in: the owner's tokens get the current recipient hashes (groups
   * may have changed).
   * @param {import('./auth.js').User} who
   */
  async refresh(who) {
    if (!who.user) return;
    for (const r of await this.list(who.user)) {
      if (!r.revoked) await this.redis.hSet(`${this.p}tok:${r.id}`, { ids: who.ids.join(' '), nm: who.name || who.user });
    }
  }

  // ------------------------------------------------------------ technical users
  // Keys: svc:<name> hash  name desc resp ips on max created by updated; svc:all set.
  /** @param {string} name */
  async service(name) {
    if (!SVC_NAME.test(name)) return null;
    const h = await this.redis.hGetAll(`${this.p}svc:${name}`);
    return h?.name ? Tokens.serviceRecord(h) : null;
  }

  /** @param {Record<string, string>} h @returns {Service} */
  static serviceRecord(h) {
    return {
      name: h.name,
      description: h.desc || '',
      responsible: h.resp || '',
      ips: (h.ips || '').split(' ').filter(Boolean),
      enabled: h.on === '1',
      max: h.max === undefined || h.max === '' ? null : Number(h.max),
      created: Number(h.created || 0),
      by: h.by || '',
      updated: Number(h.updated || 0),
    };
  }

  async services() {
    const names = await this.redis.sMembers(`${this.p}svc:all`);
    /** @type {Service[]} */
    const out = [];
    for (const n of names) {
      const s = await this.service(n);
      if (s) out.push(s);
      else await this.redis.sRem(`${this.p}svc:all`, n);
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Creates (create: true) or changes a technical user; returns the old and
   * the new state for the audit log.
   * @param {{ name?: unknown, description?: unknown, responsible?: unknown, ips?: unknown, enabled?: unknown, max?: unknown }} b
   * @param {string} by @param {boolean} create
   * @returns {Promise<{ old: Service | null, new: Service } | { error: string, message: string }>}
   */
  async saveService(b, by, create) {
    const name = typeof b.name === 'string' ? b.name.trim().toLowerCase() : '';
    if (!SVC_NAME.test(name)) return { error: 'invalid_name', message: 'name: 2 to 64 of a-z 0-9 _ . - (e.g. api_aap)' };
    const old = await this.service(name);
    if (create && old) return { error: 'exists', message: 'A technical user with this name exists' };
    if (!create && !old) return { error: 'not_found', message: 'No such technical user' };
    /** @param {unknown} v @param {number} max */
    const text = (v, max) => (typeof v === 'string' ? v.normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '');
    const description = b.description === undefined && old ? old.description : text(b.description, 200);
    const responsible = b.responsible === undefined && old ? old.responsible : text(b.responsible, 254).toLowerCase();
    if (responsible && !/^[^\s@<>"',;]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(responsible)) return { error: 'invalid_responsible', message: 'responsible: an e-mail address' };
    let ips;
    try {
      ips = b.ips === undefined && old ? old.ips : parseNetworks(b.ips ?? []);
    } catch (err) {
      return { error: 'invalid_ips', message: /** @type {Error} */ (err).message };
    }
    const enabled = b.enabled === undefined ? (old ? old.enabled : true) : b.enabled === true;
    const max = b.max === undefined ? (old ? old.max : null) : b.max === null || b.max === '' ? null : Number(b.max);
    if (max !== null && (!Number.isInteger(max) || max < 0 || max > 1000)) return { error: 'invalid_max', message: 'max: 0 to 1000 (0 = no limit), or empty for API_TOKEN_MAX_PER_USER' };
    const now = Date.now();
    /** @type {Service} */
    const svc = { name, description, responsible, ips, enabled, max, created: old?.created || now, by: old?.by || by, updated: now };
    await this.redis
      .multi()
      .hSet(`${this.p}svc:${name}`, { name, desc: description, resp: responsible, ips: ips.join(' '), on: enabled ? '1' : '0', max: max === null ? '' : String(max), created: String(svc.created), by: svc.by, updated: String(now) })
      .sAdd(`${this.p}svc:all`, name)
      .exec();
    return { old, new: svc };
  }

  /** The tokens of a technical user. @param {string} name */
  serviceTokens(name) {
    return this.list(`svc:${name}`);
  }

  /**
   * Revokes all active tokens of a technical user (disable, delete).
   * @param {string} name @param {string} by
   */
  async revokeService(name, by) {
    /** @type {TokenRecord[]} */
    const done = [];
    for (const t of await this.serviceTokens(name)) {
      if (Tokens.active(t)) {
        await this.revoke(t.id, '', by);
        done.push(t);
      }
    }
    return done;
  }

  /** @param {string} name */
  async deleteService(name) {
    await this.redis.multi().del(`${this.p}svc:${name}`).sRem(`${this.p}svc:all`, name).exec();
  }

  /**
   * Issues a token for a technical user. adminAllowed: the caller may give
   * the "admin" scope (a person who is admin; an admin token only with
   * API_ADMIN_TOKEN_CAN_ISSUE_ADMIN).
   * @param {Service} svc @param {any} b @param {boolean} adminAllowed
   */
  issueService(svc, b, adminAllowed) {
    const a = this.c.adminTokens;
    const wantsAdmin = Array.isArray(b.scopes) && b.scopes.includes(ADMIN_SCOPE);
    const allowed = [...SCOPES, ...(a.enabled && adminAllowed ? [ADMIN_SCOPE] : [])];
    const ips = b.ips === undefined ? svc.ips : b.ips;
    return this.issue({ owner: `svc:${svc.name}`, ownerName: svc.name, ids: [], svc: svc.name }, { ...b, ips }, {
      allowed,
      defaults: ['create'],
      max: svc.max ?? this.c.maxPerUser,
      maxExpiry: wantsAdmin ? shorter(this.c.maxExpiry, a.maxExpiry) : this.c.maxExpiry,
      ipsRequired: this.c.ipBinding === 'required' || (wantsAdmin && a.requireIp),
    });
  }
}
