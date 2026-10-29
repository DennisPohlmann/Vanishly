// Vanishly - entry point: reads the settings, connects to Redis, serves HTTP.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { Store } from './store.js';
import { loadTheme, ROOT } from './theme.js';

const version = process.env.VANISHLY_VERSION || readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();
/** @type {import('./config.js').Config} */ let config;
/** @type {import('./theme.js').Theme} */ let theme;
try {
  config = loadConfig();
  theme = loadTheme(config, version);
} catch (err) {
  // A wrong setting stops the start, so the container does not come up half-configured.
  console.error(`Vanishly: invalid setting: ${/** @type {Error} */ (err).message}`);
  process.exit(78); // EX_CONFIG
}
// Redis must be reachable and writable before the first request: without it
// no secret can be stored, viewed or burned. Docker's restart policy retries.
/** @type {Store} */ let store;
try {
  store = await withTimeout(Store.connect(config.redisUrl, config), 10000, 'no connection within 10 s');
  if (!(await store.writable(5000))) throw new Error('it refuses writes (read-only replica or memory full?)');
} catch (err) {
  console.error(`Vanishly: Redis is not reachable or not writable: ${/** @type {Error} */ (err).message}`);
  process.exit(69); // EX_UNAVAILABLE
}
const app = createApp({ config, store, theme, version });
/** @type {import('./audit.js').Audit | null} */
const audit = app.locals.audit;
if (audit) {
  // The first event of every start: which settings shape the log. A log that
  // cannot be written stops the start (AUDIT_LOG_FAIL=closed).
  const a = /** @type {NonNullable<typeof config.audit>} */ (config.audit);
  try {
    await audit.log({
      type: 'system.startup',
      actor: { type: 'system' },
      details: {
        format: a.format,
        sinks: [a.file && 'file', a.stdout && 'stdout', a.redis && 'redis', a.syslog && `syslog-${a.syslog.proto}`, a.otlp && 'otlp', a.webhook && 'webhook'].filter(Boolean),
        signed: Boolean(a.hmacKey),
        fail: a.failClosed ? 'closed' : 'open',
        ip: a.ip,
        comment: config.comment.mode,
        sign_in: config.auth?.provider || 'none',
        api_tokens: config.auth?.tokens ? (config.auth.tokens.required ? 'required' : 'on') : 'off',
        admin_view: Boolean(config.auth?.admin.auditView),
      },
    });
  } catch (err) {
    console.error(`Vanishly: the audit log cannot be written: ${/** @type {Error} */ (err).message}`);
    if (a.failClosed) process.exit(73); // EX_CANTCREAT
  }
}

const server = app.listen(config.port, config.host, () => {
  console.log(`Vanishly ${version} listening on ${config.host}:${config.port}, template "${theme.name}"`);
});
server.headersTimeout = 20000;
server.requestTimeout = 30000;

/** @param {string} signal */
function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  server.close(async () => {
    if (audit) {
      await audit.log({ type: 'system.shutdown', actor: { type: 'system' }, reason: signal }).catch(() => {});
      await audit.close().catch(() => {});
    }
    store.close().finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

/**
 * @template T
 * @param {Promise<T>} p @param {number} ms @param {string} message
 * @returns {Promise<T>}
 */
function withTimeout(p, ms, message) {
  return Promise.race([p, new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms).unref())]);
}
