// Vanishly - Auth0 through its Management API. A machine-to-machine
// application with read:users and read:roles (DIRECTORY_CLIENT_ID/SECRET, or
// the sign-in client). RECIPIENT_USER_GROUP is a role; Auth0 has no groups
// of its own, so there is no group search. With a custom domain set
// DIRECTORY_URL to the tenant domain (https://<tenant>.<region>.auth0.com).

import { Directory, str } from './base.js';

export class Auth0 extends Directory {
  label = 'Auth0';

  base() {
    return this.d.url || new URL(this.c.issuer).origin;
  }

  async bearer() {
    return this.token(async () => {
      const { data } = await this.request(`${this.base()}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'client_credentials',
          client_id: this.d.clientId || this.c.clientId,
          client_secret: this.d.clientSecret || this.c.clientSecret,
          audience: `${this.base()}/api/v2/`,
        }),
      });
      return { token: str(data?.access_token), expiresIn: Number(data?.expires_in) || 3600 };
    });
  }

  async members() {
    const people = [];
    // The Management API gives at most 1000 users of a role this way.
    for (let page = 0; page < 10; page++) {
      const { data } = await this.request(
        `${this.base()}/api/v2/roles/${encodeURIComponent(this.c.userGroup)}/users?per_page=100&page=${page}`,
        { headers: { Authorization: `Bearer ${await this.bearer()}`, Accept: 'application/json' } },
      );
      const list = Array.isArray(data) ? data : [];
      for (const u of list) {
        const mail = str(u?.email).toLowerCase();
        people.push({ name: str(u?.name), user: mail, mail });
      }
      if (list.length < 100) break;
    }
    return people;
  }
}
