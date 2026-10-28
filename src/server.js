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

const server = app.listen(config.port, config.host, () => {
  console.log(`Vanishly ${version} listening on ${config.host}:${config.port}, template "${theme.name}"`);
});
server.headersTimeout = 20000;
server.requestTimeout = 30000;

/** @param {string} signal */
function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  server.close(() => {
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
