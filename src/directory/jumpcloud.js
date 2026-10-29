// Vanishly - JumpCloud through its API with an API key (DIRECTORY_API_TOKEN,
// of a read-only administrator). RECIPIENT_USER_GROUP is a user group id;
// members of nested groups count. EU organisations: DIRECTORY_URL=https://console.eu.jumpcloud.com

import { Directory, str } from './base.js';

export class JumpCloud extends Directory {
  label = 'JumpCloud';

  base() {
    return this.d.url || 'https://console.jumpcloud.com';
  }

  /** @param {string} path */
  async get(path) {
    return (await this.request(`${this.base()}${path}`, { headers: { 'x-api-key': this.d.token, Accept: 'application/json' } })).data;
  }

  async members() {
    /** @type {string[]} */
    const ids = [];
    for (let skip = 0; skip < 5000; skip += 100) {
      const page = await this.get(`/api/v2/usergroups/${encodeURIComponent(this.c.userGroup)}/membership?limit=100&skip=${skip}`);
      const list = Array.isArray(page) ? page : [];
      for (const m of list) if (m?.type === 'user' && /^[0-9a-f]{24}$/.test(str(m?.id))) ids.push(m.id);
      if (list.length < 100) break;
    }
    const people = [];
    for (let i = 0; i < ids.length; i += 100) {
      const filter = `_id:$in:${ids.slice(i, i + 100).join('|')}`;
      const data = await this.get(`/api/systemusers?limit=100&fields=email%20firstname%20lastname%20displayname%20state%20suspended&filter=${encodeURIComponent(filter)}`);
      for (const u of Array.isArray(data?.results) ? data.results : []) {
        if (u?.suspended === true || (u?.state && u.state !== 'ACTIVATED')) continue;
        const mail = str(u?.email).toLowerCase();
        const name = str(u?.displayname) || [str(u?.firstname), str(u?.lastname)].filter(Boolean).join(' ');
        people.push({ name, user: mail, mail });
      }
    }
    return people;
  }
}
