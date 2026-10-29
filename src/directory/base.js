// Vanishly - the directory behind the people search (RECIPIENT_USER_GROUP),
// the group search (RECIPIENT_GROUPS=*) and groups that are not in the token.
// One backend per provider (src/directory/<provider>.js); this is what they share.
//
// A backend answers with raw entries; src/auth.js checks the addresses,
// removes duplicates, sorts and caches. Errors name only the HTTP status,
// never an id, address or token (they reach the log).

import * as client from 'openid-client';

/** @typedef {NonNullable<import('../config.js').Config['auth']>} AuthConfig */
/** @typedef {{ name: string, user: string, mail: string }} Person user: the address the person signs in with */
/** @typedef {{ id: string, name: string }} Group id: the value in the groups claim */
/** @typedef {{ fetch: typeof fetch, oidc: () => Promise<client.Configuration> }} Context */

// Members of RECIPIENT_USER_GROUP are listed once and searched here, kept
// this long and up to this many (backends without a search in one group).
export const MEMBERS_TTL = 300000;
export const MEMBERS_MAX = 5000;

/** @param {unknown} v */
export const str = (v) => (typeof v === 'string' ? v.trim() : '');

/**
 * True when a word of the name, the address or the user name starts with term.
 * @param {Person} p
 * @param {string} term lower case
 */
export function matches(p, term) {
  return (
    p.name.toLowerCase().split(/[\s,.()-]+/).some((w) => w.startsWith(term)) ||
    p.name.toLowerCase().startsWith(term) ||
    p.user.startsWith(term) ||
    p.mail.startsWith(term)
  );
}

export class Directory {
  /** Shown in errors: "<label> answered 403". */
  label = 'directory';

  /**
   * @param {AuthConfig} cfg
   * @param {Context} ctx
   */
  constructor(cfg, ctx) {
    this.c = cfg;
    this.d = /** @type {NonNullable<AuthConfig['directory']>} */ (cfg.directory);
    this.fetch = ctx.fetch;
    this.oidc = ctx.oidc;
    /** @type {{ token: string, until: number } | null} */
    this.access = null;
    /** @type {{ people: Person[], until: number } | null} */
    this.memberList = null;
    /** @type {Promise<Person[]> | null} */
    this.loading = null;
  }

  /**
   * A request with a timeout; JSON back, an error with the status otherwise.
   * @param {string} url
   * @param {RequestInit} [init]
   * @returns {Promise<{ data: any, res: Response }>}
   */
  async request(url, init = {}) {
    const res = await this.fetch(url, { ...init, signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`${this.label} answered ${res.status}`);
    return { data: await res.json(), res };
  }

  /**
   * A token, kept until two minutes before it expires.
   * @param {() => Promise<{ token: string, expiresIn?: number }>} get
   */
  async token(get) {
    if (this.access && this.access.until > Date.now()) return this.access.token;
    const t = await get();
    if (!t.token) throw new Error(`${this.label}: no access token`);
    this.access = { token: t.token, until: Date.now() + Math.max(60, (t.expiresIn || 3600) - 120) * 1000 };
    return t.token;
  }

  /**
   * Client credentials at the sign-in provider's token endpoint, with
   * DIRECTORY_CLIENT_ID/SECRET when set, otherwise as the sign-in client.
   * @param {Record<string, string>} [params]
   */
  clientToken(params = {}) {
    return this.token(async () => {
      let cfg = await this.oidc();
      if (this.d.clientId) {
        cfg = new client.Configuration(cfg.serverMetadata(), this.d.clientId, this.d.clientSecret);
        if (this.c.issuer.startsWith('http:')) client.allowInsecureRequests(cfg);
      }
      const t = await client.clientCredentialsGrant(cfg, params);
      return { token: t.access_token, expiresIn: t.expires_in };
    });
  }

  /**
   * A next-page link only when it stays on the same server (the token goes with it).
   * @param {string} next
   * @param {string} base
   */
  static sameOrigin(next, base) {
    try {
      return new URL(next, base).origin === new URL(base).origin ? new URL(next, base).href : '';
    } catch {
      return '';
    }
  }

  /**
   * All members of RECIPIENT_USER_GROUP (backends without a search in a group).
   * @returns {Promise<Person[]>}
   */
  async members() {
    return [];
  }

  /** The member list, loaded once per MEMBERS_TTL; parallel searches share one load. */
  async cachedMembers() {
    if (this.memberList && this.memberList.until > Date.now()) return this.memberList.people;
    if (!this.loading) {
      this.loading = this.members()
        .then((people) => {
          this.memberList = { people: people.slice(0, MEMBERS_MAX), until: Date.now() + MEMBERS_TTL };
          return this.memberList.people;
        })
        .finally(() => {
          this.loading = null;
        });
    }
    return this.loading;
  }

  /**
   * Members of RECIPIENT_USER_GROUP that match term (2 to 64 characters, lower case).
   * @param {string} term
   * @returns {Promise<Person[]>}
   */
  async searchPeople(term) {
    return (await this.cachedMembers()).filter((p) => matches(p, term)).slice(0, 25);
  }

  /**
   * Groups whose name starts with or contains term (RECIPIENT_GROUPS=*).
   * @param {string} _term
   * @returns {Promise<Group[]>}
   */
  async searchGroups(_term) {
    return [];
  }

  /**
   * The groups of a user from the directory, or null to use the groups claim.
   * @param {Record<string, any>} _claims
   * @returns {Promise<string[] | null>}
   */
  async groupsOf(_claims) {
    return null;
  }
}
