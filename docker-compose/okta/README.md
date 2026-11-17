# Vanishly with Okta (example)

Vanishly and Redis with sign-in through Okta: recipients, groups, the
people and group search and admins from your Okta org. You need a sign-in
app and, for the search, an API token (below). All settings are in `.env`;
the details of each are in
[docs/providers/okta.md](../../docs/providers/okta.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at Okta

1. **Applications → Create App Integration**: OIDC, **Web Application**,
   grant type **Authorization Code**, sign-in redirect URI
   `<BASE_URL>/auth/callback` (e.g. `http://localhost:3000/auth/callback`
   for a test on your machine), sign-out redirect URI
   `<BASE_URL>/auth/logged-out`.
2. **Assignments**: the people or groups who may use Vanishly. Copy client
   id and client secret.
3. Groups claim `groups` in the **ID token** (org server: in the app under
   **Sign On**; custom authorization server: **Security → API →
   Authorization Servers → Claims**), filter e.g. matches regex `.*`.
4. For the search: **Security → API → Tokens → Create token**, made by an
   admin with the **Read-only Administrator** role. Without it set
   `DIRECTORY_API=false` in `.env`.

## 2. Settings and start

```bash
cd docker-compose/okta
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 1, without `/auth/callback` |
| `OIDC_ISSUER` | `https://<org>.okta.com/oauth2/default` (custom authorization server) or `https://<org>.okta.com` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the app (or `OIDC_CLIENT_SECRET_FILE`) |
| `DIRECTORY_API_TOKEN` | the API token of step 4 (or `DIRECTORY_API_TOKEN_FILE`) |

Optional:

| Setting | Example |
|---|---|
| `RECIPIENT_GROUPS` | `IT=IT Admins,Finance=Finance` (group names), or `*` to search all groups |
| `RECIPIENT_USER_GROUP` | `00g...`, the id of the group whose members the form suggests |
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
  example sets (`AUTH_PROVIDER=okta`, `OIDC_*`, `DIRECTORY_API=true`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of Okta: [Troubleshooting](../../docs/providers/okta.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
