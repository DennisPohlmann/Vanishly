// The tests below were written when POST /api/v1/share and POST /api/v1/open
// were on by default; they keep testing them (and the MCP tools on them), so
// they switch them on unless a test sets them itself. config.test.js and
// tests/downloads.test.js check the real defaults.
import { loadConfig as load } from '../src/config.js';

/** @param {Record<string, string | undefined>} env */
export const loadConfig = (env) =>
  load({ ENABLE_SERVER_CREATE_API: 'true', ENABLE_SERVER_OPEN_API: 'true', ENABLE_SERVER_CREATE_MCP: 'true', ENABLE_SERVER_OPEN_MCP: 'true', ...(env.ENABLE_API === 'false' ? {} : { ENABLE_MCP: 'true' }), ...env });
