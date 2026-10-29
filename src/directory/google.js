// Vanishly - Google Workspace through the Admin SDK Directory API. A service
// account with domain-wide delegation for the scopes below acts for an admin
// (DIRECTORY_GOOGLE_CREDENTIALS_FILE, DIRECTORY_GOOGLE_ADMIN). Google puts no
// groups into the ID token, so the groups of a user come from here (direct
// memberships). Group values are the group addresses in lower case.

import { SignJWT, importPKCS8 } from 'jose';
import { Directory, str } from './base.js';

const SCOPES = [
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
].join(' ');

/** Only letters, digits and . _ @ - reach a query. @param {string} term */
const clean = (term) => term.replace(/[^\p{L}\p{N}.@_-]/gu, '');

export class Google extends Directory {
  label = 'Google';

  base() {
    return `${this.d.url || 'https://admin.googleapis.com'}/admin/directory/v1`;
  }

  /** JWT bearer grant: the service account signs, Google returns a token for the admin. */
  async bearer() {
    const g = /** @type {NonNullable<typeof this.d.google>} */ (this.d.google);
    return this.token(async () => {
      const key = await importPKCS8(g.privateKey, 'RS256');
      const assertion = await new SignJWT({ scope: SCOPES })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', ...(g.keyId ? { kid: g.keyId } : {}) })
        .setIssuer(g.clientEmail)
        .setSubject(g.admin)
        .setAudience(g.tokenUri)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(key);
      const { data } = await this.request(g.tokenUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
      });
      return { token: str(data?.access_token), expiresIn: Number(data?.expires_in) || 3600 };
    });
  }

  /** @param {string} path */
  async get(path) {
    return (await this.request(`${this.base()}${path}`, { headers: { Authorization: `Bearer ${await this.bearer()}`, Accept: 'application/json' } })).data;
  }

  /** The members (also of nested groups); Google lists only their addresses. */
  async members() {
    const people = [];
    let token = '';
    for (let n = 0; n < 25; n++) {
      const q = new URLSearchParams({ maxResults: '200', includeDerivedMembership: 'true', ...(token ? { pageToken: token } : {}) });
      const data = await this.get(`/groups/${encodeURIComponent(this.c.userGroup)}/members?${q}`);
      for (const m of Array.isArray(data?.members) ? data.members : []) {
        if (m?.type !== 'USER' || (m?.status && m.status !== 'ACTIVE')) continue;
        const mail = str(m?.email).toLowerCase();
        people.push({ name: '', user: mail, mail });
      }
      token = str(data?.nextPageToken);
      if (!token) break;
    }
    return people;
  }

  /**
   * Users whose given name, family name or address starts with term, among the members.
   * @param {string} term
   */
  async searchPeople(term) {
    const t = clean(term);
    if (t.length < 2) return [];
    const members = new Set((await this.cachedMembers()).map((p) => p.user));
    const queries = [`givenName:'${t}'*`, `familyName:'${t}'*`, `email:${t}*`];
    const pages = await Promise.all(
      queries.map((query) =>
        this.get(`/users?${new URLSearchParams({ customer: 'my_customer', query, maxResults: '25', projection: 'basic', viewType: 'admin_view' })}`),
      ),
    );
    const people = [];
    for (const data of pages) {
      for (const u of Array.isArray(data?.users) ? data.users : []) {
        const mail = str(u?.primaryEmail).toLowerCase();
        if (u?.suspended === true || !members.has(mail)) continue;
        people.push({ name: str(u?.name?.fullName), user: mail, mail });
      }
    }
    return people;
  }

  /** @param {string} term */
  async searchGroups(term) {
    const t = clean(term);
    if (t.length < 2) return [];
    const pages = await Promise.all(
      [`name:'${t}'*`, `email:${t}*`].map((query) =>
        this.get(`/groups?${new URLSearchParams({ customer: 'my_customer', query, maxResults: '10' })}`),
      ),
    );
    /** @type {Map<string, string>} */
    const found = new Map();
    for (const data of pages) {
      for (const g of Array.isArray(data?.groups) ? data.groups : []) {
        const id = str(g?.email).toLowerCase();
        if (id) found.set(id, str(g?.name) || id);
      }
    }
    return [...found].map(([id, name]) => ({ id, name: `${name} (${id})` })).slice(0, 10);
  }

  /**
   * The direct groups of the signed-in address.
   * @param {Record<string, any>} claims
   */
  async groupsOf(claims) {
    const mail = str(claims.email).toLowerCase();
    if (!mail || claims.email_verified === false) return [];
    const out = [];
    let token = '';
    for (let n = 0; n < 10; n++) {
      const q = new URLSearchParams({ userKey: mail, maxResults: '200', ...(token ? { pageToken: token } : {}) });
      const data = await this.get(`/groups?${q}`);
      for (const g of Array.isArray(data?.groups) ? data.groups : []) if (str(g?.email)) out.push(str(g.email).toLowerCase());
      token = str(data?.nextPageToken);
      if (!token) break;
    }
    return out;
  }
}
