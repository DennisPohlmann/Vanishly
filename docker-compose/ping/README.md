# Vanishly with PingOne (example)

Vanishly and Redis with sign-in through PingOne: recipients, groups, the
people search and admins from your environment. You need an OIDC Web App
and, for the search, a Worker application (below). All settings are in
`.env`; the details of each are in
[docs/providers/ping.md](../../docs/providers/ping.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at PingOne

1. **Applications → Applications → +**: **OIDC Web App**. Response type
   **Code**, grant type **Authorization Code**, PKCE **S256 required**,
   token endpoint authentication **Client Secret Basic**, redirect URI
   `<BASE_URL>/auth/callback` (e.g. `http://localhost:3000/auth/callback`
   for a test on your machine), signoff URL `<BASE_URL>/auth/logged-out`.
   Enable it and copy client id and secret.
2. **Attribute Mappings → Add**: attribute `groups`, mapping **Group
   Names**, in the ID token.
3. For the search: a **Worker** application with the role **Identity Data
   Read Only** for the environment. Without it set `DIRECTORY_API=false`
   in `.env`.

## 2. Settings and start

```bash
cd docker-compose/ping
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 1, without `/auth/callback` |
| `OIDC_ISSUER` | `https://auth.pingone.<region>/<environment id>/as` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the OIDC Web App (or `OIDC_CLIENT_SECRET_FILE`) |

Optional:

| Setting | Example |
|---|---|
| `DIRECTORY_CLIENT_ID` / `DIRECTORY_CLIENT_SECRET` | the Worker application (empty: the sign-in app) |
| `RECIPIENT_GROUPS` | `Finance=Finance,IT=IT` (group names; no group search with PingOne) |
| `RECIPIENT_USER_GROUP` | the id of the group whose members the form suggests |
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
  example sets (`AUTH_PROVIDER=ping`, `OIDC_*`, `DIRECTORY_*`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of PingOne: [Troubleshooting](../../docs/providers/ping.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
