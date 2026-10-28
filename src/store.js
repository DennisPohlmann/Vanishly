// Vanishly - secrets, receipts and rate limits in Redis.
//
// Keys (all below REDIS_PREFIX):
//   s:<id>      hash  ct iv salt it vh views attempts rid created expires [to]
//               expires with the secret; deleted on the last view or burn;
//               to = the hashed recipients (src/auth.js), space-separated
//   r:<rid>     hash  sid created expires maxViews viewsLeft state pass burned [rc]
//               the creator's receipt; kept RECEIPT_KEEP seconds longer;
//               rc = number of recipients
//   r:<rid>:v   list  times of the views (no IPs, no user agents); with
//               RECEIPT_SHOW_VIEWER "time<TAB>name" of the signed-in viewer
//   rl:<bucket>:<ip-hash>  counter for the rate limits
// The server never sees the key of a secret, only the ciphertext.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createClient } from 'redis';

// Takes one view of the secret. Atomic, so two parallel reveals of a
// one-view secret cannot both succeed. Fail-closed on purpose: the first
// command after the existence check is a write (HINCRBY); if Redis refuses
// writes (read-only, OOM), the script fails before the ciphertext is read,
// and the ciphertext is only returned after the view was counted and, on
// the last view, the key deleted.
const REVEAL = `
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
local left = redis.call('HINCRBY', KEYS[1], 'views', -1)
local d = redis.call('HMGET', KEYS[1], 'ct', 'iv', 'salt', 'it')
if left <= 0 then redis.call('DEL', KEYS[1]) end
if redis.call('EXISTS', KEYS[2]) == 1 then
  redis.call('HSET', KEYS[2], 'viewsLeft', math.max(left, 0), 'state', left <= 0 and 'received' or 'viewed')
  if ARGV[2] == '1' then
    redis.call('RPUSH', KEYS[3], ARGV[1])
    local ttl = redis.call('PTTL', KEYS[2])
    if ttl > 0 then redis.call('PEXPIRE', KEYS[3], ttl) end
  end
end
return {left, d[1], d[2], d[3], d[4]}
`;

const BURNED = `
if redis.call('EXISTS', KEYS[1]) == 1 then redis.call('HSET', KEYS[1], 'state', 'burned', 'burned', ARGV[1]) end
`;

/** 128 random bits, base64url (22 characters). */
export function newId() {
  return randomBytes(16).toString('base64url');
}

/** @param {string} id */
export function validId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{22}$/.test(id);
}

/** @param {string} v */
function sha256(v) {
  return createHash('sha256').update(v).digest();
}

/**
 * @typedef {{ ciphertext: string, iv: string, salt: string, iterations: number, verifier?: string }} Payload
 * @typedef {import('redis').RedisClientType} Redis
 */

export class Store {
  /**
   * @param {any} redis a connected node-redis client
   * @param {{ redisPrefix: string, receiptKeep: number, passphraseAttempts: number,
   *   features?: { receipts: boolean, viewLog: boolean } }} config
   */
  constructor(redis, config) {
    this.redis = redis;
    this.p = config.redisPrefix;
    this.receiptKeep = config.receiptKeep;
    this.attempts = config.passphraseAttempts;
    // ENABLE_RECEIPTS=false: no receipt is stored. ENABLE_VIEW_LOG=false: no view times.
    this.receipts = config.features?.receipts !== false;
    this.viewLog = this.receipts && config.features?.viewLog !== false;
  }

  /** @param {string} url @param {ConstructorParameters<typeof Store>[1]} config */
  static async connect(url, config) {
    const redis = createClient({ url });
    // The client retries about every second while Redis is away: log the
    // outage and the recovery once each instead of one line per retry.
    let down = false;
    redis.on('error', (/** @type {Error} */ err) => {
      if (down) return;
      down = true;
      console.error(`redis: ${err.message} (retrying)`);
    });
    redis.on('ready', () => {
      if (!down) return;
      down = false;
      console.error('redis: connected again');
    });
    await redis.connect();
    return new Store(redis, config);
  }

  /**
   * True when Redis answers and accepts a write within `ms`. A read-only
   * replica, a full memory (OOM) or a lost connection give false: then no
   * secret can be stored, viewed or burned, so the health check must fail.
   * @param {number} [ms]
   */
  async writable(ms = 2000) {
    /** @type {NodeJS.Timeout | undefined} */
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), ms);
    });
    const write = this.redis
      .set(`${this.p}health`, String(Date.now()), { PX: 60000 })
      .then((/** @type {unknown} */ r) => r === 'OK')
      .catch(() => false);
    try {
      return Boolean(await Promise.race([write, timeout]));
    } finally {
      clearTimeout(timer);
    }
  }

  async close() {
    await this.redis.quit();
  }

  /**
   * @param {Payload} payload
   * @param {number} ttl seconds
   * @param {number} views
   * @param {string[]} [to] hashed recipients; empty = anyone with the link
   */
  async create(payload, ttl, views, to = []) {
    const id = newId();
    const rid = newId();
    const now = Date.now();
    const expires = now + ttl * 1000;
    const pass = payload.verifier ? 1 : 0;
    const s = `${this.p}s:${id}`;
    const r = `${this.p}r:${rid}`;
    const tx = this.redis
      .multi()
      .hSet(s, {
        ct: payload.ciphertext,
        iv: payload.iv,
        salt: payload.salt,
        it: String(payload.iterations),
        vh: payload.verifier ? sha256(payload.verifier).toString('base64url') : '',
        views: String(views),
        attempts: '0',
        rid,
        created: String(now),
        expires: String(expires),
        ...(to.length ? { to: to.join(' ') } : {}),
      })
      .pExpireAt(s, expires);
    if (this.receipts) {
      tx.hSet(r, {
        sid: id,
        created: String(now),
        expires: String(expires),
        maxViews: String(views),
        viewsLeft: String(views),
        state: 'new',
        pass: String(pass),
        ...(to.length ? { rc: String(to.length) } : {}),
      }).pExpireAt(r, expires + this.receiptKeep * 1000);
    }
    await tx.exec();
    return { id, receiptId: this.receipts ? rid : null, created: now, expires, views, passphrase: Boolean(pass), restricted: to.length > 0 };
  }

  /**
   * What the reveal page needs before the reveal: whether the secret exists,
   * whether it needs a passphrase and the parameters to derive the verifier.
   * @param {string} id
   */
  async meta(id) {
    const [salt, it, vh, views, expires, to] = await this.redis.hmGet(`${this.p}s:${id}`, [
      'salt',
      'it',
      'vh',
      'views',
      'expires',
      'to',
    ]);
    if (salt == null) return null;
    return {
      passphrase: Boolean(vh),
      restricted: Boolean(to),
      salt,
      iterations: Number(it),
      viewsLeft: Number(views),
      expires: Number(expires),
    };
  }

  /**
   * The hashed recipients of a secret; [] = anyone with the link, null = gone.
   * @param {string} id
   */
  async recipients(id) {
    const [rid, to] = await this.redis.hmGet(`${this.p}s:${id}`, ['rid', 'to']);
    if (rid == null) return null;
    return to ? to.split(' ') : [];
  }

  /**
   * Hands out the ciphertext once per allowed view. Who may (recipients)
   * is checked before, in src/app.js.
   * @param {string} id
   * @param {string} [verifier]
   * @param {string} [viewer] name for the view log (RECEIPT_SHOW_VIEWER)
   * @returns {Promise<{ status: 'ok', payload: Omit<Payload, 'verifier'>, viewsLeft: number }
   *   | { status: 'notfound' } | { status: 'badpass', attemptsLeft: number } | { status: 'burned' }>}
   */
  async reveal(id, verifier, viewer = '') {
    const s = `${this.p}s:${id}`;
    const [vh, rid] = await this.redis.hmGet(s, ['vh', 'rid']);
    if (rid == null) return { status: 'notfound' };
    if (vh) {
      const ok =
        typeof verifier === 'string' &&
        verifier.length > 0 &&
        timingSafeEqual(sha256(verifier), Buffer.from(vh, 'base64url'));
      if (!ok) {
        const tried = await this.redis.hIncrBy(s, 'attempts', 1);
        if (tried >= this.attempts) {
          await this.burnSecret(id, rid);
          return { status: 'burned' };
        }
        return { status: 'badpass', attemptsLeft: this.attempts - tried };
      }
    }
    const r = `${this.p}r:${rid}`;
    const entry = viewer ? `${Date.now()}\t${viewer.replace(/[\t\r\n]/g, ' ')}` : String(Date.now());
    const res = /** @type {any[] | null} */ (
      await this.redis.eval(REVEAL, { keys: [s, r, `${r}:v`], arguments: [entry, this.viewLog ? '1' : '0'] })
    );
    if (!res || Number(res[0]) < 0) return { status: 'notfound' };
    return {
      status: 'ok',
      payload: { ciphertext: res[1], iv: res[2], salt: res[3], iterations: Number(res[4]) },
      viewsLeft: Number(res[0]),
    };
  }

  /** @param {string} id @param {string} rid */
  async burnSecret(id, rid) {
    if (Number(await this.redis.del(`${this.p}s:${id}`)) !== 1) return false;
    // Only an existing receipt: a new hash here would never expire.
    await this.redis.eval(BURNED, { keys: [`${this.p}r:${rid}`], arguments: [String(Date.now())] });
    return true;
  }

  /** @param {string} rid */
  async receipt(rid) {
    const r = `${this.p}r:${rid}`;
    const [h, views] = await Promise.all([this.redis.hGetAll(r), this.redis.lRange(`${r}:v`, 0, -1)]);
    if (!h || !h.sid) return null;
    let state = h.state;
    if ((state === 'new' || state === 'viewed') && Number(h.expires) <= Date.now()) state = 'expired';
    else if (state === 'new' || state === 'viewed') {
      // The secret can also be gone without a view: expired a moment ago.
      if (!(await this.redis.exists(`${this.p}s:${h.sid}`))) state = 'expired';
    }
    return {
      secretId: h.sid,
      state,
      created: Number(h.created),
      expires: Number(h.expires),
      maxViews: Number(h.maxViews),
      viewsLeft: state === 'new' || state === 'viewed' ? Number(h.viewsLeft) : 0,
      passphrase: h.pass === '1',
      burned: h.burned ? Number(h.burned) : null,
      recipients: Number(h.rc || 0),
      views: views.map((v) => Number(v.split('\t')[0])),
      viewers: views.map((v) => v.split('\t')[1] || ''),
    };
  }

  /**
   * Destroys the secret of a receipt before it is viewed (again).
   * @param {string} rid
   */
  async burn(rid) {
    const sid = await this.redis.hGet(`${this.p}r:${rid}`, 'sid');
    if (!sid) return null;
    return this.burnSecret(sid, rid);
  }

  /**
   * Fixed-window rate limit. The IP is hashed, so Redis holds no addresses.
   * @param {string} bucket
   * @param {string} ip
   * @param {number} limit 0 = off
   * @param {number} window seconds
   */
  async rateLimit(bucket, ip, limit, window) {
    if (!limit) return { ok: true, retryAfter: 0 };
    const key = `${this.p}rl:${bucket}:${sha256(ip).toString('base64url').slice(0, 22)}`;
    const [count, ttl] = /** @type {[number, number]} */ (
      /** @type {unknown} */ (await this.redis.multi().incr(key).ttl(key).exec())
    );
    if (Number(ttl) < 0) await this.redis.expire(key, window);
    return { ok: Number(count) <= limit, retryAfter: Number(ttl) > 0 ? Number(ttl) : window };
  }
}
