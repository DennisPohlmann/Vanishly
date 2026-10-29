// Vanishly - PingOne through its Platform API. A worker application with
// the Identity Data Read Only role (DIRECTORY_CLIENT_ID/SECRET, or the
// sign-in client when it is a worker). RECIPIENT_USER_GROUP is a group id.

import { Directory, str } from './base.js';

export class Ping extends Directory {
  label = 'PingOne';

  /** https://auth.pingone.eu/<env>/as -> https://api.pingone.eu/v1/environments/<env> */
  base() {
    if (this.d.url) return this.d.url;
    const u = new URL(this.c.issuer);
    const env = u.pathname.split('/')[1];
    return `https://${u.hostname.replace(/^auth\./, 'api.')}/v1/environments/${env}`;
  }

  async members() {
    const people = [];
    const filter = `memberOfGroups[id eq "${this.c.userGroup}"]`;
    let url = `${this.base()}/users?limit=100&filter=${encodeURIComponent(filter)}`;
    for (let n = 0; url && n < 50; n++) {
      const token = await this.clientToken();
      const { data } = await this.request(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } });
      for (const u of Array.isArray(data?._embedded?.users) ? data._embedded.users : []) {
        if (u?.enabled === false) continue;
        const mail = str(u?.email).toLowerCase();
        const name = str(u?.name?.formatted) || [str(u?.name?.given), str(u?.name?.family)].filter(Boolean).join(' ') || str(u?.username);
        people.push({ name, user: mail, mail });
      }
      const next = str(data?._links?.next?.href);
      url = next ? Directory.sameOrigin(next, this.base()) : '';
    }
    return people;
  }
}
