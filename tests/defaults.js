// The tests below were written when POST /api/v1/share, POST /api/v1/open
// and the MCP server were on by default; they keep testing them, so they
// switch them on unless a test sets them itself. config.test.js and
// tests/downloads.test.js check the real defaults.
import { loadConfig as load } from '../src/config.js';

/** @param {Record<string, string | undefined>} env */
export const loadConfig = (env) =>
  load({ ENABLE_SHARE_API: 'true', ENABLE_OPEN_API: 'true', ...(env.ENABLE_API === 'false' ? {} : { ENABLE_MCP: 'true' }), ...env });
