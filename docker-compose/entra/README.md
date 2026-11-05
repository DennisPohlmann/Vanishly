# Vanishly with Microsoft Entra ID (example)

Vanishly and Redis with sign-in through Microsoft Entra ID: recipients,
groups, the people search and admins from your own tenant. You need an app
registration in Entra (below). All settings are in `.env`; the details of
each are in [docs/providers/entra.md](../../docs/providers/entra.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. App registration in Entra

1. Entra admin center → **App registrations** → **New registration**: name
   `Vanishly`, "Accounts in this organizational directory only", redirect
   URI **Web** (not SPA) `<BASE_URL>/auth/callback`, e.g.
   `http://localhost:3000/auth/callback` for a test on your machine or
   `https://ots.example.com/auth/callback` on a server.
2. **Overview**: note the **Directory (tenant) ID** and the **Application
   (client) ID**.
3. **Certificates & secrets** → **New client secret**: note its **value**
   (not its id).
4. **Token configuration** → **Add groups claim** → "Security groups" (ID
   token: "Group ID"), so that secrets for groups and `ADMIN_GROUPS` work.
5. **API permissions** → **Add a permission** → Microsoft Graph →
   **Application permissions**: `GroupMember.Read.All` (group search, users
   in more than 200 groups) and `User.Read.All` (people search, the mail
   address for `ENTRA_SHOW_ADDRESS=mail`) → **Grant admin consent** for your
   tenant. Without them set `ENTRA_GRAPH=false` in `.env`.
6. Optional: to sign out of Microsoft too (`AUTH_LOGOUT=provider`), add
   `<BASE_URL>/auth/logged-out` as a second **Web** redirect URI. In
   **Enterprise applications** → Vanishly → Properties, "Assignment
   required" limits who can sign in at all.

## 2. Settings and start

```bash
cd docker-compose/entra
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 1, without `/auth/callback` |
| `ENTRA_TENANT_ID` | Directory (tenant) ID |
| `ENTRA_CLIENT_ID` | Application (client) ID |
| `ENTRA_CLIENT_SECRET` | value of the client secret (or `ENTRA_CLIENT_SECRET_FILE`) |

Optional, all with group **object ids** from Entra:

| Setting | Example |
|---|---|
| `RECIPIENT_GROUPS` | `IT Admins=<object id>,HR=<object id>`, or `*` to search all groups (needs `ENTRA_GRAPH=true`) |
| `RECIPIENT_USER_GROUP` | `<object id>` of the group whose members the form suggests (needs `ENTRA_GRAPH=true`) |
| `ADMIN_GROUPS` | `<object id>` of the admins' group; or `ADMIN_USERS` with UPNs |
| `ENTRA_SHOW_ADDRESS` | `mail` shows the mail address instead of the UPN |

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
  example sets (`AUTH_PROVIDER=entra`, `ENTRA_*`, `ENTRA_GRAPH=true`,
  `RECIPIENTS=optional`, the groups and admins), then the others with their
  defaults. `OIDC_*` and `DIRECTORY_*` are for the other providers and stay
  empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems such as `AADSTS50011` (redirect URI) or Graph answering 403 (admin
consent missing): [Troubleshooting](../../docs/providers/entra.md#troubleshooting).
