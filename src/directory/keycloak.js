// Vanishly - Keycloak through its Admin REST API. A confidential client with
// a service account and the realm-management roles view-users, query-users
// and query-groups (DIRECTORY_CLIENT_ID/SECRET, or the sign-in client).
// Group values are the full paths (/staff), as the Group Membership mapper
// writes them with "Full group path" on.

import { Directory, str } from './base.js';

export class Keycloak extends Directory {
  label = 'Keycloak';

  /** https://host/realms/x -> https://host/admin/realms/x */
  base() {
    if (this.d.url) return this.d.url;
    const u = new URL(this.c.issuer);
    u.pathname = u.pathname.replace(/\/realms\/([^/]+)\/?$/, '/admin/realms/$1');
    return u.href.replace(/\/$/, '');
  }

  /** @param {string} path */
  async get(path) {
    const token = await this.clientToken();
    return (await this.request(`${this.base()}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } })).data;
  }

  /** RECIPIENT_USER_GROUP as id; a path is looked up once. */
  async groupId() {
    if (!this.c.userGroup.startsWith('/')) return this.c.userGroup;
    if (!this.id) {
      const g = await this.get(`/group-by-path/${this.c.userGroup.slice(1).split('/').map(encodeURIComponent).join('/')}`);
      if (typeof g?.id !== 'string') throw new Error('Keycloak: group not found');
      /** @type {string | undefined} */
      this.id = g.id;
    }
    return /** @type {string} */ (this.id);
  }

  async members() {
    const id = encodeURIComponent(await this.groupId());
    const people = [];
    for (let first = 0; first < 5000; first += 200) {
      const page = await this.get(`/groups/${id}/members?first=${first}&max=200&briefRepresentation=true`);
      if (!Array.isArray(page)) break;
      for (const u of page) {
        if (u?.enabled === false || u?.emailVerified === false) continue;
        const mail = str(u?.email).toLowerCase();
        const name = [str(u?.firstName), str(u?.lastName)].filter(Boolean).join(' ') || str(u?.username);
        people.push({ name, user: mail, mail });
      }
      if (page.length < 200) break;
    }
    return people;
  }

  /** @param {string} term */
  async searchGroups(term) {
    const tree = await this.get(`/groups?search=${encodeURIComponent(term)}&max=10&briefRepresentation=true`);
    /** @type {{ id: string, name: string }[]} */
    const out = [];
    /** @param {any[]} list */
    const walk = (list) => {
      for (const g of Array.isArray(list) ? list : []) {
        const path = str(g?.path);
        if (path && str(g?.name).toLowerCase().includes(term)) out.push({ id: path, name: path });
        walk(g?.subGroups);
      }
    };
    walk(tree);
    return out.slice(0, 10);
  }
}
