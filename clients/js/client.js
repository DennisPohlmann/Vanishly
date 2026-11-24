// HTTP client for the Vanishly API (/api/v1), with fetch.
import { decryptSecret, encryptSecret, unlockKey, verifierFor } from './crypto.js';

export const VERSION = '4.0.0';
const LINK = /^(https?:\/\/[^#]+?)\/s\/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$/;
const OPTIONS = ['ttl', 'views', 'confirmed', 'recipients', 'recipientGroups', 'responsible', 'responsibleGroups', 'comment'];

/** An answer other than 2xx. */
export class ApiError extends Error {
  /** @param {number} status @param {string} error @param {string} message @param {any} body */
  constructor(status, error, message, body) {
    super(`${status} ${error}: ${message}`);
    this.status = status;
    this.error = error;
    this.body = body ?? {};
  }
}

/** Splits https://host/s/<id>#<key> into { base, id, key }. @param {string} link */
export function parseLink(link) {
  const m = LINK.exec(String(link).trim());
  if (!m) throw new Error('not a secret link: https://.../s/<id>#<key>');
  return { base: m[1], id: m[2], key: m[3] };
}

/** @param {Record<string, any>} o */
function options(o = {}) {
  const bad = Object.keys(o).filter((k) => !OPTIONS.includes(k));
  if (bad.length) throw new TypeError(`unknown option(s): ${bad.join(', ')}`);
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));
}

const seg = (/** @type {string} */ s) => encodeURIComponent(s);

export class Client {
  /**
   * @param {string} baseUrl e.g. https://ots.example.com
   * @param {{ token?: string, runId?: string, comment?: string, onBehalfOf?: string, clientName?: string, fetch?: typeof fetch }} [opts]
   */
  constructor(baseUrl, opts = {}) {
    if (!/^https?:\/\//.test(baseUrl || '')) throw new Error('baseUrl must start with https:// or http://');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.opts = opts;
    /** Set when the server recommends a newer client. @type {string | null} */
    this.recommendedVersion = null;
  }

  /**
   * Any API call; path is below /api ("/v1/config").
   * @param {string} method @param {string} path @param {any} [body] @param {Record<string, any>} [query] @param {{ raw?: boolean }} [o]
   */
  async request(method, path, body, query, o = {}) {
    const q = new URLSearchParams(Object.entries(query || {}).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [k, String(v)]));
    const url = `${this.baseUrl}/api${path}${q.size ? `?${q}` : ''}`;
    const name = this.opts.clientName || 'js';
    /** @type {Record<string, string>} */
    const headers = { Accept: 'application/json', 'X-Vanishly-Client': `${name}/${VERSION}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.opts.token) headers.Authorization = `Bearer ${this.opts.token}`;
    if (this.opts.runId) headers['X-Run-Id'] = this.opts.runId;
    if (this.opts.comment) headers['X-Audit-Comment'] = encodeURIComponent(this.opts.comment);
    if (this.opts.onBehalfOf) headers['X-On-Behalf-Of'] = this.opts.onBehalfOf;
    const res = await (this.opts.fetch || fetch)(url, { method: method.toUpperCase(), headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const rec = res.headers.get('x-vanishly-client-recommended');
    if (rec) this.recommendedVersion = rec;
    const text = await res.text();
    if (!res.ok) {
      let b = {};
      try {
        b = JSON.parse(text);
      } catch {}
      throw new ApiError(res.status, b.error || 'http_error', b.message || res.statusText, b);
    }
    if (o.raw) return text;
    return text ? JSON.parse(text) : null;
  }

  /** Encrypts here and stores it; adds shareUrl and receiptUrl. @param {string} secret @param {string} [passphrase] @param {Record<string, any>} [opts] */
  async create(secret, passphrase = '', opts = {}) {
    const { key, payload } = await encryptSecret(secret, passphrase);
    const res = await this.createSecret({ ...JSON.parse(JSON.stringify(payload)), ...options(opts) });
    res.shareUrl = `${this.baseUrl}${res.secretPath}#${key}`;
    res.receiptUrl = res.receiptPath ? `${this.baseUrl}${res.receiptPath}#${key}` : null;
    return res;
  }

  /** Takes one view and decrypts here. @param {string} link @param {string} [passphrase] */
  async open(link, passphrase = '') {
    const { base, id, key } = parseLink(link);
    if (base !== this.baseUrl) throw new Error(`the link belongs to ${base}, not to ${this.baseUrl}`);
    let pk;
    let verifier;
    if (passphrase) {
      const meta = await this.secretMeta(id);
      if (meta.passphrase) {
        pk = await unlockKey(passphrase, meta);
        verifier = await verifierFor(pk, meta);
      }
    }
    const payload = await this.reveal(id, verifier);
    return { secret: await decryptSecret(payload, key, pk), viewsLeft: payload.viewsLeft };
  }

  index() { return this.request('GET', '/v1'); }
  config() { return this.request('GET', '/v1/config'); }
  downloads() { return this.request('GET', '/v1/downloads'); }
  /** @param {Record<string, any>} payload */
  createSecret(payload) { return this.request('POST', '/v1/secrets', payload); }
  /** Server-side encryption: the server sees the secret. @param {string} secret @param {string} [passphrase] @param {Record<string, any>} [opts] */
  share(secret, passphrase = '', opts = {}) { return this.request('POST', '/v1/share', { secret, ...(passphrase ? { passphrase } : {}), ...options(opts) }); }
  /** Server-side reveal: the server sees key and secret. @param {string} link @param {string} [passphrase] */
  openOnServer(link, passphrase = '') { return this.request('POST', '/v1/open', { link, ...(passphrase ? { passphrase } : {}) }); }
  /** @param {string} id */
  secretMeta(id) { return this.request('GET', `/v1/secrets/${seg(id)}`); }
  /** @param {string} id @param {string} [verifier] */
  reveal(id, verifier) { return this.request('POST', `/v1/secrets/${seg(id)}/reveal`, verifier ? { verifier } : {}); }
  /** @param {string} id */
  receipt(id) { return this.request('GET', `/v1/receipts/${seg(id)}`); }
  /** @param {string} id */
  burn(id) { return this.request('POST', `/v1/receipts/${seg(id)}/burn`, {}); }
  me() { return this.request('GET', '/v1/me'); }
  /** @param {Record<string, any>} [q] */
  mySecrets(q) { return this.request('GET', '/v1/me/secrets', undefined, q); }
  /** @param {string} ref */
  mySecret(ref) { return this.request('GET', `/v1/me/secrets/${seg(ref)}`); }
  /** @param {string} ref */
  burnMySecret(ref) { return this.request('POST', `/v1/me/secrets/${seg(ref)}/burn`, {}); }
  groups(q = '') { return this.request('GET', '/v1/groups', undefined, { q }); }
  people(q = '') { return this.request('GET', '/v1/people', undefined, { q }); }
  tokens() { return this.request('GET', '/v1/tokens'); }
  /** @param {Record<string, any>} body */
  createToken(body) { return this.request('POST', '/v1/tokens', body); }
  /** @param {string} id */
  revokeToken(id) { return this.request('POST', `/v1/tokens/${seg(id)}/revoke`, {}); }
  adminStatus() { return this.request('GET', '/v1/admin/status'); }
  adminTokens() { return this.request('GET', '/v1/admin/tokens'); }
  /** @param {string} id */
  adminRevokeToken(id) { return this.request('POST', `/v1/admin/tokens/${seg(id)}/revoke`, {}); }
  /** format csv or jsonl comes back as text. @param {Record<string, any>} [q] */
  audit(q = {}) { return this.request('GET', '/v1/admin/audit', undefined, q, { raw: q.format === 'csv' || q.format === 'jsonl' }); }
  auditVerify() { return this.request('GET', '/v1/admin/audit/verify'); }
  tokenPolicies() { return this.request('GET', '/v1/admin/token-policies'); }
  /** @param {Record<string, any>} body */
  setTokenPolicy(body) { return this.request('POST', '/v1/admin/token-policies', body); }
  /** @param {Record<string, any>} [q] */
  adminSecrets(q) { return this.request('GET', '/v1/admin/secrets', undefined, q); }
  /** @param {string} ref */
  adminSecret(ref) { return this.request('GET', `/v1/admin/secrets/${seg(ref)}`); }
  /** @param {string} ref */
  adminBurn(ref) { return this.request('POST', `/v1/admin/secrets/${seg(ref)}/burn`, {}); }
  serviceAccounts() { return this.request('GET', '/v1/admin/service-accounts'); }
  /** @param {Record<string, any>} body */
  createServiceAccount(body) { return this.request('POST', '/v1/admin/service-accounts', body); }
  /** @param {string} name @param {Record<string, any>} body */
  changeServiceAccount(name, body) { return this.request('POST', `/v1/admin/service-accounts/${seg(name)}`, body); }
  /** @param {string} name */
  deleteServiceAccount(name) { return this.request('POST', `/v1/admin/service-accounts/${seg(name)}/delete`, {}); }
  /** @param {string} name */
  serviceAccountTokens(name) { return this.request('GET', `/v1/admin/service-accounts/${seg(name)}/tokens`); }
  /** @param {string} name @param {Record<string, any>} [body] */
  issueServiceAccountToken(name, body = {}) { return this.request('POST', `/v1/admin/service-accounts/${seg(name)}/tokens`, body); }
  /** @param {string} name @param {string} id @param {Record<string, any>} [body] */
  rotateServiceAccountToken(name, id, body = {}) { return this.request('POST', `/v1/admin/service-accounts/${seg(name)}/tokens/${seg(id)}/rotate`, body); }
  users() { return this.request('GET', '/v1/admin/users'); }
  /** @param {Record<string, any>} body */
  createUser(body) { return this.request('POST', '/v1/admin/users', body); }
  /** @param {string} user @param {Record<string, any>} body */
  changeUser(user, body) { return this.request('POST', `/v1/admin/users/${seg(user)}`, body); }
  /** @param {string} user @param {Record<string, any>} [body] */
  resetUserPassword(user, body = {}) { return this.request('POST', `/v1/admin/users/${seg(user)}/password`, body); }
  /** @param {string} user */
  deleteUser(user) { return this.request('POST', `/v1/admin/users/${seg(user)}/delete`, {}); }
}
