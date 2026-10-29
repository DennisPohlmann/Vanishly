# Auth0

`AUTH_PROVIDER=auth0`. Issuer: `https://<tenant>.<region>.auth0.com/` or
your custom domain, with the trailing slash (Vanishly adds it).

## Sign-in application

1. **Applications → Create Application → Regular Web Application**.
2. **Allowed Callback URLs**: `https://ots.example.com/auth/callback`;
   **Allowed Logout URLs**: `https://ots.example.com/auth/logged-out`
   (and switch on **RP-Initiated Logout** under the tenant's advanced
   settings, so Auth0 lists its logout endpoint).
3. Copy domain, client id and client secret.
4. With social or database connections anyone could sign up: switch
   sign-ups off, or set `AUTH_ALLOWED_DOMAINS`.

## Groups

Auth0 puts no groups into tokens. Add the user's roles (or another list)
with a post-login **Action** under a namespaced claim:

```js
exports.onExecutePostLogin = async (event, api) => {
  const roles = event.authorization?.roles || [];
  api.idToken.setCustomClaim('https://ots.example.com/groups', roles);
};
```

Then `OIDC_GROUPS_CLAIM=https://ots.example.com/groups` and
`RECIPIENT_GROUPS=Finance=finance,IT=it` (the role names). There is no
group search with Auth0.

## Directory (search)

A **Machine to Machine** application, authorized for the **Auth0
Management API** with the scopes `read:users` and `read:roles`. Set it as
`DIRECTORY_CLIENT_ID` / `DIRECTORY_CLIENT_SECRET` (or authorize the
sign-in application itself and leave them out).

`RECIPIENT_USER_GROUP` is the id of a **role** (`rol_...`): the form
suggests its users, at most 1000.

With a custom domain the Management API still lives on the tenant domain:
`DIRECTORY_URL=https://<tenant>.<region>.auth0.com`.

## Example (`.env` or Compose)

Required: `AUTH_PROVIDER`, `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` (or `_FILE`) and `AUTH_SECRET` (or `_FILE`). The
same lines go into `.env` next to `docker-compose.yml`
([docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml))
or into its `environment:` block.

```bash
AUTH_PROVIDER=auth0
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://example.eu.auth0.com/
OIDC_CLIENT_ID=change-me
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
OIDC_GROUPS_CLAIM=https://ots.example.com/groups
RECIPIENT_GROUPS=Finance=finance,IT=it
DIRECTORY_API=true
DIRECTORY_CLIENT_ID=change-me
DIRECTORY_CLIENT_SECRET_FILE=/run/secrets/auth0_m2m_secret
RECIPIENT_USER_GROUP=rol_abcdefghijklmnop
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| A member of a role gets "not shared with your account" | The post-login Action is not deployed or not in the Login flow, or `OIDC_GROUPS_CLAIM` differs from its claim name |
| Log `auth: people search failed: Auth0 answered 403` | The machine-to-machine app lacks `read:users` or `read:roles` on the Management API |
| Log `auth: people search failed: Auth0 answered 404` | With a custom domain set `DIRECTORY_URL` to the tenant domain |
| "Sign out" does not ask again | Switch on **RP-Initiated Logout** and add `<BASE_URL>/auth/logged-out` to **Allowed Logout URLs** |

General problems: [providers/README.md](README.md#troubleshooting).
