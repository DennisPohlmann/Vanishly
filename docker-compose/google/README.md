# Vanishly with Google Workspace (example)

Vanishly and Redis with sign-in through Google Workspace: recipients,
groups, the people and group search and admins from your Workspace
directory. You need an OAuth client and, for groups and the search, a
service account with domain-wide delegation (below). All settings are in
`.env`; the details of each are in
[docs/providers/google.md](../../docs/providers/google.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at Google

1. Google Cloud console, a project of your organization: **APIs &
   Services → OAuth consent screen**, user type **Internal**.
2. **Credentials → Create credentials → OAuth client ID → Web
   application**, authorized redirect URI `<BASE_URL>/auth/callback` (e.g.
   `http://localhost:3000/auth/callback` for a test on your machine). Copy
   client id and client secret.
3. Enable the **Admin SDK API**. **IAM & Admin → Service accounts →
   Create**, **Keys → Add key → JSON**: save the file as
   `google-service-account.json` next to `docker-compose.yml` (git-ignored)
   and make it readable for the container's user (uid 1000), e.g.
   `chmod 644 google-service-account.json` on a machine only you use, or
   `sudo chown 1000 google-service-account.json && chmod 400 google-service-account.json`.
4. Admin console: **Security → Access and data control → API controls →
   Domain-wide delegation → Add new**, client id of the service account,
   the three read-only scopes from
   [docs/providers/google.md](../../docs/providers/google.md#directory-search-groups).

Without the service account Google gives no groups and no search: set
`DIRECTORY_API=false`, empty `DIRECTORY_GOOGLE_*` and remove the two
`secrets` blocks from `docker-compose.yml`.

## 2. Settings and start

```bash
cd docker-compose/google
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 2, without `/auth/callback` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the OAuth client (or `OIDC_CLIENT_SECRET_FILE`) |
| `AUTH_ALLOWED_DOMAINS` | your Workspace domains, e.g. `example.com` (required: every Google account could sign in otherwise) |
| `DIRECTORY_GOOGLE_ADMIN` | an admin the service account acts for, who can read users and groups |

Optional:

| Setting | Example |
|---|---|
| `RECIPIENT_GROUPS` | `Finance=finance@example.com` (group addresses), or `*` to search all groups |
| `RECIPIENT_USER_GROUP` | the address of the group whose members the form suggests |
| `ADMIN_GROUPS` | the group address of the admins; or `ADMIN_USERS` with e-mail addresses |

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
  The JSON key `google-service-account.json` next to it is mounted as the
  Docker secret `/run/secrets/google_service_account`
  (`DIRECTORY_GOOGLE_CREDENTIALS_FILE`).
- `.env` (from `.env.example`, git-ignored): every setting, first what this
  example sets (`AUTH_PROVIDER=google`, `OIDC_*`, `AUTH_ALLOWED_DOMAINS`, `DIRECTORY_API=true`, `DIRECTORY_GOOGLE_*`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of Google Workspace: [Troubleshooting](../../docs/providers/google.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
