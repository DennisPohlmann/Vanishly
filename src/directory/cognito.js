// Vanishly - Amazon Cognito through the user pool API (ListUsersInGroup,
// ListGroups), signed with AWS Signature Version 4. Credentials from the
// standard AWS variables: keys, or a role via a web identity token (EKS IRSA).
// IAM: cognito-idp:ListUsersInGroup, cognito-idp:ListGroups on the user pool.

import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Directory, str } from './base.js';

/** @param {string} v */
const hex = (v) => createHash('sha256').update(v).digest('hex');
/** @param {string | Buffer} key @param {string} v */
const hmac = (key, v) => createHmac('sha256', key).update(v).digest();

export class Cognito extends Directory {
  label = 'Cognito';

  get aws() {
    return /** @type {NonNullable<typeof this.d.aws>} */ (this.d.aws);
  }

  /** @returns {Promise<{ id: string, secret: string, session: string }>} */
  async credentials() {
    const a = this.aws;
    if (a.accessKeyId) return { id: a.accessKeyId, secret: a.secretAccessKey, session: a.sessionToken };
    if (this.creds && this.creds.until > Date.now()) return this.creds;
    // AssumeRoleWithWebIdentity needs no signature; the token file is renewed by Kubernetes.
    const token = (await readFile(a.tokenFile, 'utf8')).trim();
    const res = await this.fetch(`https://sts.${a.region}.amazonaws.com/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        Action: 'AssumeRoleWithWebIdentity',
        Version: '2011-06-15',
        RoleArn: a.roleArn,
        RoleSessionName: 'vanishly',
        WebIdentityToken: token,
        DurationSeconds: '3600',
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`STS answered ${res.status}`);
    const xml = await res.text();
    /** @param {string} tag */
    const tag = (tag) => new RegExp(`<${tag}>([^<]+)</${tag}>`).exec(xml)?.[1] || '';
    /** @type {{ id: string, secret: string, session: string, until: number } | undefined} */
    this.creds = { id: tag('AccessKeyId'), secret: tag('SecretAccessKey'), session: tag('SessionToken'), until: Date.now() + 50 * 60000 };
    if (!this.creds.id) throw new Error('STS: no credentials');
    return this.creds;
  }

  /**
   * One call of the Cognito user pool API.
   * @param {string} action
   * @param {Record<string, unknown>} input
   */
  async call(action, input) {
    const { region } = this.aws;
    const url = new URL(this.d.url || `https://cognito-idp.${region}.amazonaws.com/`);
    const body = JSON.stringify(input);
    const c = await this.credentials();
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const day = amzDate.slice(0, 8);
    /** @type {Record<string, string>} */
    const headers = {
      'content-type': 'application/x-amz-json-1.1',
      host: url.host,
      'x-amz-date': amzDate,
      ...(c.session ? { 'x-amz-security-token': c.session } : {}),
      'x-amz-target': `AWSCognitoIdentityProviderService.${action}`,
    };
    const names = Object.keys(headers).sort();
    const signed = names.join(';');
    const canonical = ['POST', url.pathname || '/', '', ...names.map((h) => `${h}:${headers[h]}`), '', signed, hex(body)].join('\n');
    const scope = `${day}/${region}/cognito-idp/aws4_request`;
    const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, hex(canonical)].join('\n');
    const key = hmac(hmac(hmac(hmac(`AWS4${c.secret}`, day), region), 'cognito-idp'), 'aws4_request');
    const signature = createHmac('sha256', key).update(toSign).digest('hex');
    const { host: _host, ...send } = headers;
    const { data } = await this.request(url.href, {
      method: 'POST',
      headers: { ...send, Authorization: `AWS4-HMAC-SHA256 Credential=${c.id}/${scope}, SignedHeaders=${signed}, Signature=${signature}` },
      body,
    });
    return data;
  }

  async members() {
    const people = [];
    let next = '';
    for (let n = 0; n < 100; n++) {
      const data = await this.call('ListUsersInGroup', { UserPoolId: this.aws.pool, GroupName: this.c.userGroup, Limit: 60, ...(next ? { NextToken: next } : {}) });
      for (const u of Array.isArray(data?.Users) ? data.Users : []) {
        if (u?.Enabled === false) continue;
        /** @type {Record<string, string>} */
        const at = Object.fromEntries((Array.isArray(u?.Attributes) ? u.Attributes : []).map((/** @type {any} */ a) => [str(a?.Name), str(a?.Value)]));
        if (at.email_verified === 'false') continue;
        const mail = (at.email || '').toLowerCase();
        const name = at.name || [at.given_name, at.family_name].filter(Boolean).join(' ') || str(u?.Username);
        people.push({ name, user: mail, mail });
      }
      next = str(data?.NextToken);
      if (!next) break;
    }
    return people;
  }

  /** @param {string} term */
  async searchGroups(term) {
    if (!this.groupList || this.groupList.until < Date.now()) {
      /** @type {string[]} */
      const names = [];
      let next = '';
      for (let n = 0; n < 20; n++) {
        const data = await this.call('ListGroups', { UserPoolId: this.aws.pool, Limit: 60, ...(next ? { NextToken: next } : {}) });
        for (const g of Array.isArray(data?.Groups) ? data.Groups : []) if (str(g?.GroupName)) names.push(str(g.GroupName));
        next = str(data?.NextToken);
        if (!next) break;
      }
      /** @type {{ names: string[], until: number } | undefined} */
      this.groupList = { names, until: Date.now() + 300000 };
    }
    return this.groupList.names
      .filter((g) => g.toLowerCase().includes(term))
      .slice(0, 10)
      .map((g) => ({ id: g, name: g }));
  }
}
