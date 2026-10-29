// Vanishly - Okta through its Management API with an API token
// (DIRECTORY_API_TOKEN, of a read-only admin). Group values are the group
// names, as the groups claim of Okta carries them.

import { Directory, str } from './base.js';

export class Okta extends Directory {
  label = 'Okta';

  base() {
    return this.d.url || new URL(this.c.issuer).origin;
  }

  /** @param {string} url */
  async get(url) {
    return this.request(url, { headers: { Authorization: `SSWS ${this.d.token}`, Accept: 'application/json' } });
  }

  async members() {
    const people = [];
    let url = `${this.base()}/api/v1/groups/${encodeURIComponent(this.c.userGroup)}/users?limit=200`;
    for (let n = 0; url && n < 25; n++) {
      const { data, res } = await this.get(url);
      for (const u of Array.isArray(data) ? data : []) {
        if (u?.status && u.status !== 'ACTIVE') continue;
        const p = u?.profile || {};
        const mail = str(p.email).toLowerCase();
        const name = str(p.displayName) || [str(p.firstName), str(p.lastName)].filter(Boolean).join(' ');
        people.push({ name, user: mail, mail });
      }
      // Paging: Link: <...>; rel="next"
      const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') || '')?.[1] || '';
      url = next ? Directory.sameOrigin(next, this.base()) : '';
    }
    return people;
  }

  /** @param {string} term */
  async searchGroups(term) {
    const { data } = await this.get(`${this.base()}/api/v1/groups?q=${encodeURIComponent(term)}&limit=10`);
    return (Array.isArray(data) ? data : [])
      .map((/** @type {any} */ g) => str(g?.profile?.name))
      .filter(Boolean)
      .map((name) => ({ id: name, name }));
  }
}
