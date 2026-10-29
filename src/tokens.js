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

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { expiryAt } from './config.js';

export const SCOPES = ['create', 'read', 'status'];
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
 *   expires: number, ips: string[], scopes: string[], revoked: number, used: number, revokedBy: string }} TokenRecord
 */

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
    };
  }

  /**
   * Makes a token for a user. The caller checks mayCreate().
   * @param {import('./auth.js').User} user
   * @param {{ name?: unknown, expires?: unknown, ips?: unknown, scopes?: unknown }} b
   * @returns {Promise<{ token: string, record: TokenRecord } | { error: string, message: string }>}
   */
  async create(user, b) {
    const name = typeof b.name === 'string' ? b.name.normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').trim() : '';
    if (!name || name.length > 64) return { error: 'invalid_name', message: 'name: 1 to 64 characters' };
    const choice = b.expires === undefined || b.expires === null || b.expires === '' ? this.c.defaultExpiry : String(b.expires);
    if (!this.c.expiryOptions.includes(choice)) {
      return { error: 'invalid_expiry', message: `expires must be one of ${this.c.expiryOptions.join(', ')}` };
    }
    const now = Date.now();
    const expires = expiryAt(choice, now);
    // API_TOKEN_MAX_EXPIRY, checked again on the exact date.
    if (this.c.maxExpiry !== 'never' && (!expires || expires > expiryAt(this.c.maxExpiry, now))) {
      return { error: 'invalid_expiry', message: `at most ${this.c.maxExpiry}` };
    }
    let ips;
    try {
      ips = parseNetworks(b.ips ?? []);
    } catch (err) {
      return { error: 'invalid_ips', message: /** @type {Error} */ (err).message };
    }
    if (this.c.ipBinding === 'required' && !ips.length) return { error: 'ips_required', message: 'This server requires at least one IP address or network per token' };
    const scopes = b.scopes === undefined ? ['create', 'status'] : b.scopes;
    if (!Array.isArray(scopes) || !scopes.length || scopes.some((s) => !SCOPES.includes(s))) {
      return { error: 'invalid_scopes', message: `scopes: a list of ${SCOPES.join(', ')}` };
    }
    const own = this.ownerKey(user.user);
    const mine = await this.list(user.user);
    if (mine.filter((t) => !t.revoked && (!t.expires || t.expires > now)).length >= this.c.maxPerUser) {
      return { error: 'too_many_tokens', message: `At most ${this.c.maxPerUser} active tokens per user` };
    }
    const id = randomBytes(8).toString('hex');
    const token = `vnly_${id}_${randomBytes(32).toString('base64url')}`;
    const key = `${this.p}tok:${id}`;
    const tx = this.redis.multi().hSet(key, {
      h: this.digest(token).toString('base64url'),
      own: user.user,
      nm: user.name || user.user,
      ids: user.ids.join(' '),
      name,
      created: String(now),
      expires: String(expires),
      ips: ips.join(' '),
      scopes: [...new Set(scopes)].join(' '),
    });
    if (expires) tx.pExpireAt(key, expires + KEEP);
    await tx.sAdd(own, id).sAdd(`${this.p}tok:all`, id).exec();
    return { token, record: /** @type {TokenRecord} */ (await this.get(id)) };
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
   * Checks a bearer token from ip. A reason on refusal: malformed, unknown,
   * revoked, expired, ip_denied (the record then says whose token it was).
   * @param {string} token @param {string} ip
   * @returns {Promise<{ ok: true, record: TokenRecord } | { ok: false, reason: string, record?: TokenRecord }>}
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
    await this.redis.hSet(`${this.p}tok:${m[1]}`, 'used', String(Date.now()));
    return { ok: true, record };
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
}
