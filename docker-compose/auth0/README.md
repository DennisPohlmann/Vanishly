# Vanishly with Auth0 (example)

Vanishly and Redis with sign-in through Auth0: recipients, roles as groups,
the people search and admins from your tenant. You need a Regular Web
Application and, for the search, a Machine to Machine application (below).
All settings are in `.env`; the details of each are in
[docs/providers/auth0.md](../../docs/providers/auth0.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at Auth0

1. **Applications → Create Application → Regular Web Application**.
   **Allowed Callback URLs** `<BASE_URL>/auth/callback` (e.g.
   `http://localhost:3000/auth/callback` for a test on your machine),
   **Allowed Logout URLs** `<BASE_URL>/auth/logged-out`; switch on
   **RP-Initiated Logout** in the tenant's advanced settings. Copy domain,
   client id and client secret.
2. With social or database connections anyone could sign up: switch
   sign-ups off, or set `AUTH_ALLOWED_DOMAINS`.
3. Groups: Auth0 puts none into tokens. Add a post-login **Action** that
   sets the roles under a namespaced claim, e.g.
   `https://ots.example.com/groups`
   ([docs/providers/auth0.md](../../docs/providers/auth0.md#groups)).
4. For the search: a **Machine to Machine** application authorized for the
   **Auth0 Management API** with `read:users` and `read:roles` (or authorize
   the sign-in application and leave `DIRECTORY_CLIENT_*` empty). Without
   the search set `DIRECTORY_API=false` in `.env`.

## 2. Settings and start

```bash
cd docker-compose/auth0
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 1, without `/auth/callback` |
| `OIDC_ISSUER` | `https://<tenant>.<region>.auth0.com/` or your custom domain |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the application (or `OIDC_CLIENT_SECRET_FILE`) |

Optional:

| Setting | Example |
|---|---|
| `OIDC_GROUPS_CLAIM` | the claim of your Action, e.g. `https://ots.example.com/groups` |
| `RECIPIENT_GROUPS` | `Finance=finance,IT=it` (role names; no group search with Auth0) |
| `DIRECTORY_CLIENT_ID` / `DIRECTORY_CLIENT_SECRET` | the Machine to Machine application |
| `DIRECTORY_URL` | with a custom domain: `https://<tenant>.<region>.auth0.com` |
| `RECIPIENT_USER_GROUP` | `rol_...`, the id of the role whose users the form suggests |
| `ADMIN_GROUPS` | a role name of the admins; or `ADMIN_USERS` with e-mail addresses |

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
- `.env` (from `.env.example`, git-ignored): every setting, first what this
  example sets (`AUTH_PROVIDER=auth0`, `OIDC_*`, `AUTH_ALLOWED_DOMAINS`, `DIRECTORY_*`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of Auth0: [Troubleshooting](../../docs/providers/auth0.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
