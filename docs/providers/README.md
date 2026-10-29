# Sign-in providers

Vanishly signs people in with OpenID Connect. `AUTH_PROVIDER` picks the
provider; besides Microsoft Entra ID and a generic `oidc`, there are presets
that know each provider's issuer format and groups claim and, with
`DIRECTORY_API=true`, can search its directory for the form. Everything is
off by default; without a directory the sender types e-mail addresses.

| Provider | `AUTH_PROVIDER` | Groups in the token | Groups to pick (`Name=<value>`) | Group search (`RECIPIENT_GROUPS=*`) | People search (`RECIPIENT_USER_GROUP`) | Directory access | Setup |
|---|---|---|---|---|---|---|---|
| Microsoft Entra ID | `entra` | `groups` (object ids); Graph for users in more than 200 groups | yes | yes (`ENTRA_GRAPH=true`) | yes, group id | app permissions in Graph | [INSTALLATION.md](../INSTALLATION.md#10-sign-in-with-entra-id-or-oidc) |
| Keycloak | `keycloak` | `groups` (Group Membership mapper) | yes | yes | yes, group path or id | service account client | [keycloak.md](keycloak.md) |
| Okta | `okta` | `groups` (groups claim) | yes | yes | yes, group id | API token | [okta.md](okta.md) |
| Auth0 | `auth0` | none built in: a claim you add in an Action (`OIDC_GROUPS_CLAIM`) | yes | no | yes, role id | machine-to-machine app | [auth0.md](auth0.md) |
| Google Workspace | `google` | none: from the directory | yes, with `DIRECTORY_API=true` | yes | yes, group address | service account, domain-wide delegation | [google.md](google.md) |
| PingOne | `ping` | `groups` (attribute mapping) | yes | no | yes, group id | worker app | [ping.md](ping.md) |
| JumpCloud | `jumpcloud` | `groups` (group attribute) | yes | no | yes, user group id | API key | [jumpcloud.md](jumpcloud.md) |
| Amazon Cognito | `cognito` | `cognito:groups` | yes | yes | yes, group name | IAM (keys or role) | [cognito.md](cognito.md) |
| Any other OpenID provider | `oidc` | `groups` (`OIDC_GROUPS_CLAIM`) | yes | no | no | none | [CONFIG.md](../CONFIG.md#sign-in-and-recipients-auth_-entra_-oidc_-recipient) |

"Groups to pick" means `RECIPIENT_GROUPS=Name=<value>,...`, where the value
is what the provider puts into the groups claim. "Group search" lets the
sender search all groups instead. "People search" suggests the members of
one group while the sender types a name.

## What every provider needs

1. A **confidential client** (web application) with the authorization code
   flow and PKCE, redirect URI `<BASE_URL>/auth/callback`, scopes `openid
   profile email`, and the post logout (sign-out) redirect URI
   `<BASE_URL>/auth/logged-out` (`AUTH_LOGOUT=provider`, the default except
   for Entra; Google and Cognito have no logout endpoint in their discovery,
   there only Vanishly signs out).
2. A **verified e-mail address** in the ID token (`email`, not
   `email_verified: false`): Vanishly matches recipients by it. User names
   people can choose themselves are not used.
3. For groups: the groups claim in the **ID token** (or the directory, for
   Google). The values in `RECIPIENT_GROUPS` and in the search must be the
   same as in that claim.
4. For the search: `DIRECTORY_API=true` and the directory access in the
   table. The access is read-only; give it no more than the page names.

The settings shared by all presets:

```bash
AUTH_PROVIDER=keycloak            # or okta, auth0, google, ping, jumpcloud, cognito
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://sso.example.com/realms/main
OIDC_CLIENT_ID=vanishly
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
# AUTH_ALLOWED_DOMAINS=example.com # only these domains sign in (required for google)
# OIDC_GROUPS_CLAIM=groups         # the claim with the groups (preset default)
# RECIPIENT_GROUPS=Finance=finance,IT=it   # or * with a directory
# DIRECTORY_API=true                # people / group search in the directory
# RECIPIENT_USER_GROUP=...          # whose members the form suggests
```

All settings: [CONFIG.md](../CONFIG.md#sign-in-and-recipients-auth_-entra_-oidc_-recipient).

## How the search works

- Vanishly lists the members of `RECIPIENT_USER_GROUP` once (at most 5000)
  and keeps the list in memory for 5 minutes; a search filters it by the
  start of a name, the e-mail address or the user name (from 2 characters
  on, at most 10 hits). Entra and Google search in the directory instead.
- Only signed-in users can search, through `GET /api/v1/people` and
  `GET /api/v1/groups`, rate limited like reading. Nothing from the
  directory is written to Redis.
- A member without a verified e-mail address, disabled or suspended, is
  left out. A person is added with the address they sign in with.
- If the directory does not answer, the form says the search is not
  available and typing an address still works; the log gets
  `auth: people search failed: <provider> answered <status>`, without
  names, addresses or tokens.
- Privacy: every signed-in sender can look up names and addresses of that
  group's members. Pick a group that may be visible to all senders.

## Tested

Keycloak 26 is tested end to end (sign-in, groups without path, people and
group search, recipients) with the local test stack. The other directory
backends are covered by tests against stand-ins of their APIs
(`tests/directory.test.js`); the request formats follow the providers'
documentation. Please report anything that differs in your tenant.
