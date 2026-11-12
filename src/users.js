// Vanishly - local user accounts (AUTH_PROVIDER=local): Vanishly keeps its
// own users in Redis instead of asking an OpenID Connect provider.
//
// Keys (below REDIS_PREFIX), without expiry (Redis needs persistence):
//   luser:<address>  hash  name pw role groups off created updated sv
//   luser:all        set   the addresses
// pw: "scrypt$<N>$<r>$<p>$<salt>$<hash>" (base64url, 16-byte salt, 32-byte hash).
// sv: changes with every password change and every disable, so the
// sessions made before stop working (src/auth.js, user()).

import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/** @typedef {import('./auth.js').User} User */
/**
 * @typedef {{ user: string, name: string, role: 'admin' | 'user', groups: string[], disabled: boolean,
 *   created: number, updated: number, sv: string, pw: string }} LocalUser
 */

const EMAIL = /^[^\s@<>"',;]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
// One of OWASP's scrypt minimums (N=2^15, r=8, p=3): 32 MiB per hash, so the
// four hashes libuv runs at once stay at 128 MiB.
const N = 32768;
const R = 8;
const P = 3;
const KEYLEN = 32;
const MAX_PASSWORD = 1024;

/** @param {string} pw @param {Buffer} salt @param {number} n @param {number} r @param {number} p @returns {Promise<Buffer>} */
function derive(pw, salt, n, r, p) {
  return new Promise((resolve, reject) =>
    scrypt(pw.normalize('NFC'), salt, KEYLEN, { N: n, r, p, maxmem: 256 * n * r + 1024 * 1024 }, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

/** A password hash with its parameters. @param {string} pw */
export async function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = await derive(pw, salt, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

/** True when pw matches the stored hash (constant-time compare). @param {string} pw @param {string} stored */
export async function verifyPassword(pw, stored) {
  const m = /^scrypt\$(\d+)\$(\d+)\$(\d+)\$([\w-]{22})\$([\w-]{43})$/.exec(stored || '');
  if (!m || typeof pw !== 'string' || pw.length > MAX_PASSWORD) return false;
  const [n, r, p] = [Number(m[1]), Number(m[2]), Number(m[3])];
  // Only sane parameters: a tampered record must not make us allocate gigabytes.
  if (n < 16384 || n > 1048576 || (n & (n - 1)) !== 0 || r < 1 || r > 16 || p < 1 || p > 8) return false;
  const key = await derive(pw, Buffer.from(m[4], 'base64url'), n, r, p);
  return timingSafeEqual(key, Buffer.from(m[5], 'base64url'));
}

/** A group name of a local user: 1 to 200 characters, no comma or control characters. @param {unknown} g */
const validGroup = (g) => typeof g === 'string' && g.trim().length > 0 && g.length <= 200 && !/[\x00-\x1f,]/.test(g);

export class Users {
  /**
   * @param {NonNullable<import('./config.js').Config['auth']>} cfg
   * @param {{ redis: any, p: string }} store
   * @param {(kind: 'u' | 'g', value: string) => string} hash the recipient hash (Auth.hash)
   */
  constructor(cfg, store, hash) {
    this.c = /** @type {NonNullable<typeof cfg.local>} */ (cfg.local);
    this.redis = store.redis;
    this.p = store.p;
    this.hash = hash;
    // Unknown users are checked against this, so they take as long as known ones.
    this.dummy = hashPassword(randomBytes(16).toString('hex'));
  }

  /** @param {string} v */
  static validName(v) {
    return typeof v === 'string' && v.length <= 254 && EMAIL.test(v.trim().toLowerCase());
  }

  /** @param {string} user */
  key(user) {
    return `${this.p}luser:${user}`;
  }

  /** @param {Record<string, string>} h @returns {LocalUser} */
  static record(h) {
    return {
      user: h.user,
      name: h.name || h.user,
      role: h.role === 'admin' ? 'admin' : 'user',
      groups: (h.groups || '').split('\n').filter(Boolean),
      disabled: h.off === '1',
      created: Number(h.created || 0),
      updated: Number(h.updated || 0),
      sv: h.sv || '',
      pw: h.pw || '',
    };
  }

  /** The record without the hash, for the API. @param {LocalUser} u */
  static view(u) {
    return { user: u.user, name: u.name, role: u.role, groups: u.groups, disabled: u.disabled, created: new Date(u.created).toISOString(), updated: new Date(u.updated).toISOString() };
  }

  /** @param {string} user @returns {Promise<LocalUser | null>} */
  async get(user) {
    const u = typeof user === 'string' ? user.trim().toLowerCase() : '';
    if (!Users.validName(u)) return null;
    const h = await this.redis.hGetAll(this.key(u));
    return h?.user ? Users.record(h) : null;
  }

  /** All users, sorted by address. */
  async list() {
    const names = /** @type {string[]} */ (await this.redis.sMembers(`${this.p}luser:all`)).filter((n) => Users.validName(n)).sort();
    const out = [];
    for (const n of names) {
      const u = await this.get(n);
      if (u) out.push(u);
    }
    return out;
  }

  /** The signed-in user a session of this account gives. @param {LocalUser} u @returns {User} */
  identity(u) {
    return { name: u.name, user: u.user, ids: [this.hash('u', u.user), ...u.groups.map((g) => this.hash('g', g))], admin: u.role === 'admin', sv: u.sv };
  }

  /** null or the reason a password is refused. @param {unknown} pw */
  passwordProblem(pw) {
    if (typeof pw !== 'string' || pw.length < this.c.minLength) return `at least ${this.c.minLength} characters`;
    if (pw.length > MAX_PASSWORD) return `at most ${MAX_PASSWORD} characters`;
    return null;
  }

  /**
   * Checks the fields an admin sends (name, role, groups, disabled).
   * @param {any} b @returns {{ error: string, message: string } | { name?: string, role?: 'admin' | 'user', groups?: string[], disabled?: boolean }}
   */
  static fields(b) {
    /** @type {{ name?: string, role?: 'admin' | 'user', groups?: string[], disabled?: boolean }} */
    const out = {};
    if (b.name !== undefined) {
      if (typeof b.name !== 'string' || b.name.length > 100 || /[\x00-\x1f]/.test(b.name)) return { error: 'invalid_name', message: 'name: at most 100 characters' };
      out.name = b.name.trim();
    }
    if (b.role !== undefined) {
      if (b.role !== 'admin' && b.role !== 'user') return { error: 'invalid_role', message: 'role: admin or user' };
      out.role = b.role;
    }
    if (b.groups !== undefined) {
      if (!Array.isArray(b.groups) || b.groups.length > 50 || !b.groups.every(validGroup)) return { error: 'invalid_groups', message: 'groups: at most 50 names of 1 to 200 characters, no commas' };
      out.groups = [...new Set(b.groups.map((/** @type {string} */ g) => g.trim()))];
    }
    if (b.disabled !== undefined) {
      if (typeof b.disabled !== 'boolean') return { error: 'invalid_disabled', message: 'disabled: true or false' };
      out.disabled = b.disabled;
    }
    return out;
  }

  /**
   * A new user. Refused when the address is taken.
   * @param {any} b { user, name?, password, role?, groups?, disabled? }
   * @returns {Promise<{ error: string, message: string } | { user: LocalUser }>}
   */
  async create(b) {
    const user = typeof b?.user === 'string' ? b.user.trim().toLowerCase() : '';
    if (!Users.validName(user)) return { error: 'invalid_user', message: 'user: an e-mail address (the sign-in name)' };
    const f = Users.fields(b);
    if ('error' in f) return f;
    const problem = this.passwordProblem(b.password);
    if (problem) return { error: 'invalid_password', message: `password: ${problem}` };
    const pw = await hashPassword(b.password);
    // SADD is the atomic "does it exist": two replicas bootstrapping at once create it once.
    if (!(await this.redis.sAdd(`${this.p}luser:all`, user))) return { error: 'exists', message: 'A user with this address exists' };
    const now = String(Date.now());
    const h = { user, name: f.name || user, pw, role: f.role || 'user', groups: (f.groups || []).join('\n'), off: f.disabled ? '1' : '0', created: now, updated: now, sv: randomBytes(8).toString('base64url') };
    await this.redis.hSet(this.key(user), h);
    return { user: Users.record(h) };
  }

  /** Active admins other than this one. @param {string} except */
  async otherAdmins(except) {
    return (await this.list()).filter((u) => u.user !== except && u.role === 'admin' && !u.disabled).length;
  }

  /**
   * Changes name, role, groups or disabled. The last active admin stays an active admin.
   * shortcut: the last-admin check and the write are not one transaction; two admins
   * demoting each other in the same millisecond could both win. Use WATCH/MULTI if that matters.
   * @param {string} user @param {any} b
   * @returns {Promise<{ error: string, message: string } | { old: LocalUser, new: LocalUser }>}
   */
  async update(user, b) {
    const old = await this.get(user);
    if (!old) return { error: 'not_found', message: 'No such user' };
    const f = Users.fields(b || {});
    if ('error' in f) return f;
    const stillAdmin = (f.role ?? old.role) === 'admin' && !(f.disabled ?? old.disabled);
    if (old.role === 'admin' && !old.disabled && !stillAdmin && !(await this.otherAdmins(old.user))) {
      return { error: 'last_admin', message: 'The last active admin cannot be demoted or disabled' };
    }
    /** @type {Record<string, string>} */
    const h = { updated: String(Date.now()) };
    if (f.name !== undefined) h.name = f.name || old.user;
    if (f.role) h.role = f.role;
    if (f.groups) h.groups = f.groups.join('\n');
    if (f.disabled !== undefined) h.off = f.disabled ? '1' : '0';
    // Disabled: its sessions end now.
    if (f.disabled && !old.disabled) h.sv = randomBytes(8).toString('base64url');
    await this.redis.hSet(this.key(old.user), h);
    return { old, new: /** @type {LocalUser} */ (await this.get(old.user)) };
  }

  /**
   * A new password; all sessions of the user end.
   * @param {string} user @param {unknown} pw
   * @returns {Promise<{ error: string, message: string } | { user: LocalUser }>}
   */
  async setPassword(user, pw) {
    const old = await this.get(user);
    if (!old) return { error: 'not_found', message: 'No such user' };
    const problem = this.passwordProblem(pw);
    if (problem) return { error: 'invalid_password', message: `password: ${problem}` };
    await this.redis.hSet(this.key(old.user), { pw: await hashPassword(/** @type {string} */ (pw)), sv: randomBytes(8).toString('base64url'), updated: String(Date.now()) });
    return { user: /** @type {LocalUser} */ (await this.get(old.user)) };
  }

  /**
   * Deletes a user; not the last active admin.
   * @param {string} user @returns {Promise<{ error: string, message: string } | { user: LocalUser }>}
   */
  async remove(user) {
    const old = await this.get(user);
    if (!old) return { error: 'not_found', message: 'No such user' };
    if (old.role === 'admin' && !old.disabled && !(await this.otherAdmins(old.user))) return { error: 'last_admin', message: 'The last active admin cannot be deleted' };
    await this.redis.multi().del(this.key(old.user)).sRem(`${this.p}luser:all`, old.user).exec();
    return { user: old };
  }

  /**
   * The account for this address and password, or null. Unknown and
   * disabled accounts cost the same hash as a wrong password.
   * @param {unknown} user @param {unknown} pw
   * @returns {Promise<{ ok: boolean, reason: '' | 'bad_credentials' | 'disabled', user?: LocalUser }>} user: only when it exists
   */
  async login(user, pw) {
    const u = typeof user === 'string' ? await this.get(user) : null;
    const password = typeof pw === 'string' ? pw : '';
    const ok = await verifyPassword(password, u?.pw || (await this.dummy));
    if (!u || !ok) return { ok: false, reason: 'bad_credentials', ...(u ? { user: u } : {}) };
    if (u.disabled) return { ok: false, reason: 'disabled', user: u };
    return { ok: true, reason: '', user: u };
  }

  /**
   * At start: with no users yet, the admin from LOCAL_ADMIN_USERNAME and
   * LOCAL_ADMIN_PASSWORD is created; without them the start fails. Once
   * there are users the settings are ignored, so a changed password stays.
   * @returns {Promise<LocalUser | null>} the user created, or null
   */
  async bootstrap() {
    if (await this.redis.sCard(`${this.p}luser:all`)) return null;
    const { adminUser, adminPassword } = this.c;
    if (!adminUser || !adminPassword) throw new Error('AUTH_PROVIDER=local has no users yet: set LOCAL_ADMIN_USERNAME and LOCAL_ADMIN_PASSWORD (or LOCAL_ADMIN_PASSWORD_FILE) for the first admin');
    const r = await this.create({ user: adminUser, password: adminPassword, role: 'admin' });
    // Another replica was faster: fine.
    if ('error' in r) {
      if (r.error === 'exists') return null;
      throw new Error(`LOCAL_ADMIN_*: ${r.message}`);
    }
    return r.user;
  }
}
