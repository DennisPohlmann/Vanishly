# Vanishly with JumpCloud (example)

Vanishly and Redis with sign-in through JumpCloud: recipients, groups, the
people search and admins from your organization. You need an OIDC
application and, for the search, an API key (below). All settings are in
`.env`; the details of each are in
[docs/providers/jumpcloud.md](../../docs/providers/jumpcloud.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at JumpCloud

1. **SSO Applications → Add New Application → Custom Application**, with
   **Manage Single Sign-On (SSO)** → **OIDC**. Redirect URI
   `<BASE_URL>/auth/callback` (e.g. `http://localhost:3000/auth/callback`
   for a test on your machine), client authentication **Client Secret
   Basic**, scopes `openid profile email`.
2. **Include group attribute** with the name `groups`; **User Groups**: who
   may use Vanishly. Copy client id and secret (shown once).
3. For the search: an API key (**Settings → API key**, or a service account
   with read-only access). Without it set `DIRECTORY_API=false` in `.env`.

JumpCloud lists no logout endpoint: "Sign out" ends only the Vanishly
session.

## 2. Settings and start

```bash
cd docker-compose/jumpcloud
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 1, without `/auth/callback` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the application (or `OIDC_CLIENT_SECRET_FILE`) |
| `DIRECTORY_API_TOKEN` | the API key of step 3 (or `DIRECTORY_API_TOKEN_FILE`) |

Optional:

| Setting | Example |
|---|---|
| `DIRECTORY_URL` | EU region: `https://console.eu.jumpcloud.com` |
| `RECIPIENT_GROUPS` | `Finance=Finance,IT=IT` (group names; no group search with JumpCloud) |
| `RECIPIENT_USER_GROUP` | the id of the user group (24 hex characters) whose members the form suggests |
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
- `.env` (from `.env.example`, git-ignored): every setting, first what this
  example sets (`AUTH_PROVIDER=jumpcloud`, `OIDC_*`, `DIRECTORY_*`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of JumpCloud: [Troubleshooting](../../docs/providers/jumpcloud.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
