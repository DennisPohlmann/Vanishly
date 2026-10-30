// Vanishly - rate limits as express-rate-limit middleware. Counted in Redis
// (src/store.js, the rl:<bucket>:<hash> keys), so every replica shares the
// same fixed windows; the client IP is hashed before it reaches the
// middleware's store or its debug output.

import { rateLimit } from 'express-rate-limit';
import { Store } from './store.js';

/** express-rate-limit store on the Redis counters of src/store.js. */
class RedisCounter {
  /** @param {Store} store @param {string} bucket @param {number} window seconds */
  constructor(store, bucket, window) {
    this.store = store;
    this.bucket = bucket;
    this.window = window;
    this.prefix = `${bucket}:`;
    // Shared across replicas.
    this.localKeys = false;
  }

  /** @param {string} key */
  async increment(key) {
    const { count, ttl } = await this.store.hit(this.bucket, key, this.window);
    return { totalHits: count, resetTime: new Date(Date.now() + ttl * 1000) };
  }

  /** @param {string} key */
  async decrement(key) {
    await this.store.unhit(this.bucket, key);
  }

  /** @param {string} key */
  async resetKey(key) {
    await this.store.resetHits(this.bucket, key);
  }
}

/**
 * @callback OnLimit
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 * @param {number} retryAfter seconds until the window ends
 */

/**
 * A fixed-window limit per client IP (req.ip, so TRUST_PROXY decides which
 * address counts). limit 0 = off. Over the limit, onLimit answers.
 * @param {{ store: Store, bucket: string, limit: number, window: number, onLimit: OnLimit,
 *   skip?: (req: import('express').Request) => boolean }} o
 */
export function limiter({ store, bucket, limit, window, onLimit, skip }) {
  return rateLimit({
    windowMs: window * 1000,
    limit,
    store: /** @type {import('express-rate-limit').Store} */ (new RedisCounter(store, bucket, window)),
    keyGenerator: (req) => Store.ipKey(req.ip || ''),
    skip: (req) => !limit || Boolean(skip?.(req)),
    // Answers as before: only Retry-After (set by onLimit), no RateLimit-* headers.
    standardHeaders: false,
    legacyHeaders: false,
    // No start-up checks of the library: the key is already a hash, and its
    // warnings about proxies and keys would go to the log.
    validate: false,
    handler: (req, res, next) => {
      const reset = /** @type {any} */ (req).rateLimit?.resetTime;
      const retryAfter = reset instanceof Date ? Math.max(1, Math.ceil((reset.getTime() - Date.now()) / 1000)) : window;
      onLimit(req, res, next, retryAfter);
    },
  });
}
