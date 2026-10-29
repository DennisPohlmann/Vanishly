// Vanishly - the directory backend for the sign-in provider (see base.js).

import { Auth0 } from './auth0.js';
import { Cognito } from './cognito.js';
import { Entra } from './entra.js';
import { Google } from './google.js';
import { JumpCloud } from './jumpcloud.js';
import { Keycloak } from './keycloak.js';
import { Okta } from './okta.js';
import { Ping } from './ping.js';

export { Directory } from './base.js';

const BACKENDS = { entra: Entra, keycloak: Keycloak, okta: Okta, auth0: Auth0, google: Google, ping: Ping, jumpcloud: JumpCloud, cognito: Cognito };

/**
 * The backend, or null when there is none (no ENTRA_GRAPH / DIRECTORY_API).
 * @param {import('./base.js').AuthConfig} cfg
 * @param {import('./base.js').Context} ctx
 * @returns {import('./base.js').Directory | null}
 */
export function createDirectory(cfg, ctx) {
  if (cfg.provider === 'entra' ? !cfg.graph : !cfg.directory) return null;
  const Backend = BACKENDS[/** @type {keyof typeof BACKENDS} */ (cfg.provider)];
  return Backend ? new Backend(cfg, ctx) : null;
}
