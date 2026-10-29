// Vanishly - Microsoft Entra ID through Microsoft Graph (ENTRA_GRAPH=true).
// App-only token (client credentials): GroupMember.Read.All, for the people
// search also User.Read.All.

import * as client from 'openid-client';
import { Directory, str } from './base.js';

/**
 * @param {unknown} v
 * @returns {string[]}
 */
const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);

export class Entra extends Directory {
  label = 'Graph';

  /**
   * @param {string} path below /v1.0
   * @param {RequestInit} [init]
   */
  async graph(path, init = {}) {
    const token = await this.token(async () => {
      const t = await client.clientCredentialsGrant(await this.oidc(), { scope: `${this.c.graphUrl}/.default` });
      return { token: t.access_token, expiresIn: t.expires_in };
    });
    const { data } = await this.request(`${this.c.graphUrl}/v1.0${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...init.headers },
    });
    return data;
  }

  /**
   * Graph only when the token has no groups claim or too many groups (overage).
   * @param {Record<string, any>} claims
   */
  async groupsOf(claims) {
    const overage = Boolean(claims._claim_names?.groups || claims.hasgroups);
    if (typeof claims.oid !== 'string' || (!overage && Array.isArray(claims.groups))) return null;
    if (!/^[0-9a-f-]{36}$/i.test(claims.oid)) return [];
    const r = await this.graph(`/users/${claims.oid}/getMemberGroups`, {
      method: 'POST',
      body: JSON.stringify({ securityEnabledOnly: false }),
    });
    return strings(r.value);
  }

  /** @param {string} term */
  async searchGroups(term) {
    const params = new URLSearchParams({
      $search: `"displayName:${term}"`,
      $select: 'id,displayName',
      $top: '10',
      $orderby: 'displayName',
    });
    const r = await this.graph(`/groups?${params}`, { headers: { ConsistencyLevel: 'eventual' } });
    return (Array.isArray(r.value) ? r.value : [])
      .filter((/** @type {any} */ g) => typeof g?.id === 'string' && typeof g?.displayName === 'string')
      .map((/** @type {any} */ g) => ({ id: g.id.toLowerCase(), name: g.displayName }));
  }

  /**
   * Graph searches the group itself (also nested groups). "user" is the
   * address the person signs in with: the UPN, for guests (#EXT#) their mail.
   * @param {string} term
   */
  async searchPeople(term) {
    const params = new URLSearchParams({
      $search: ['displayName', 'mail', 'userPrincipalName'].map((f) => `"${f}:${term}"`).join(' OR '),
      $select: 'displayName,mail,userPrincipalName',
      $top: '10',
      $count: 'true',
    });
    const r = await this.graph(`/groups/${this.c.userGroup}/transitiveMembers/microsoft.graph.user?${params}`, {
      headers: { ConsistencyLevel: 'eventual' },
    });
    return (Array.isArray(r.value) ? r.value : []).map((/** @type {any} */ u) => {
      const upn = str(u?.userPrincipalName).toLowerCase();
      const mail = str(u?.mail).toLowerCase();
      return { name: str(u?.displayName), user: upn.includes('#ext#') ? mail : upn, mail };
    });
  }
}
