# Vanishly with Amazon Cognito (example)

Vanishly and Redis with sign-in through an Amazon Cognito user pool:
recipients, groups, the people and group search and admins from the pool.
You need a confidential app client and, for the search, IAM keys (below).
All settings are in `.env`; the details of each are in
[docs/providers/cognito.md](../../docs/providers/cognito.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at Cognito

1. In the user pool: **App integration → App clients → Create**:
   **Confidential client** with a client secret.
2. **Managed login / Hosted UI**: a domain for the pool; allowed callback
   URL `<BASE_URL>/auth/callback` (e.g. `http://localhost:3000/auth/callback`
   for a test on your machine); OAuth grant **Authorization code**; scopes
   `openid`, `profile`, `email`. Users need a verified `email`.
3. For the search: an IAM user with the policy from
   [docs/providers/cognito.md](../../docs/providers/cognito.md#directory-search)
   (`cognito-idp:ListUsersInGroup`, `cognito-idp:ListGroups` on this pool)
   and an access key. Without it set `DIRECTORY_API=false` in `.env` and
   leave the `AWS_*` lines empty.

Cognito lists no logout endpoint: "Sign out" ends only the Vanishly
session.

## 2. Settings and start

```bash
cd docker-compose/cognito
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 2, without `/auth/callback` |
| `OIDC_ISSUER` | `https://cognito-idp.<region>.amazonaws.com/<user pool id>` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the app client (or `OIDC_CLIENT_SECRET_FILE`) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | the access key of step 3 (`AWS_SESSION_TOKEN` too for temporary keys) |

Optional:

| Setting | Example |
|---|---|
| `RECIPIENT_GROUPS` | `Finance=finance,IT=it` (group names), or `*` to search all groups |
| `RECIPIENT_USER_GROUP` | the name of the group whose members the form suggests |
| `ADMIN_GROUPS` | the group name of the admins; or `ADMIN_USERS` with e-mail addresses |

```bash
docker compose up -d        # or: podman-compose up -d
docker compose logs vanishly
```

A wrong or missing value stops the start with a message in the log. On a
server put a reverse proxy with TLS in front of `127.0.0.1:3000` and set
`BASE_URL=https://...`, `TRUST_PROXY=1` and `HSTS=true`
([docs/INSTALLATION.md](../../docs/INSTALLATION.md)).

## How it is set up

- `docker-compose.yml`: Vanishly and Redis (memory only, as in
  [standalone](../standalone/docker-compose.yml)); it sets nothing itself
  and loads `.env` with `env_file:`. Port only on 127.0.0.1.
  `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are no Vanishly settings
  but the standard AWS variables; they are in `.env` too.
- `.env` (from `.env.example`, git-ignored): every setting, first what this
  example sets (`AUTH_PROVIDER=cognito`, `OIDC_*`, `DIRECTORY_API=true`, the `AWS_*` keys, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of Amazon Cognito: [Troubleshooting](../../docs/providers/cognito.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
