# Vanishly with local accounts (example)

Vanishly and Redis with sign-in through Vanishly's own user accounts
(`AUTH_PROVIDER=local`): no identity provider, the admins manage the users
on the **Users** tab of the administration. Everything else (recipients,
groups, admins, API tokens, "My secrets", the audit log) works as with a
provider. All settings are in `.env`; the details are in
[docs/providers/local.md](../../docs/providers/local.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## Settings and start

```bash
cd docker-compose/local
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `LOCAL_ADMIN_USERNAME` | the e-mail address the first admin signs in with |
| `LOCAL_ADMIN_PASSWORD` | its password, at least `LOCAL_PASSWORD_MIN_LENGTH` (12) characters (or `LOCAL_ADMIN_PASSWORD_FILE`) |
| `BASE_URL` | `http://localhost:3000` for a test, `https://...` on a server |

```bash
docker compose up -d        # or: podman-compose up -d
docker compose logs vanishly
```

At the first start (no users in Redis yet) Vanishly creates this admin and
logs `created the admin from LOCAL_ADMIN_USERNAME`. Sign in, change the
password under your name → **Change password**, then remove
`LOCAL_ADMIN_PASSWORD` from `.env`: once there are users the two settings
are ignored, so a changed password is never overwritten. Without users and
without them the start fails.

On a server put a reverse proxy with TLS in front of `127.0.0.1:3000` and
set `BASE_URL=https://...`, `TRUST_PROXY=1` and `HSTS=true`
([docs/INSTALLATION.md](../../docs/INSTALLATION.md)).

## How it is set up

- `docker-compose.yml`: Vanishly and Redis; it sets nothing itself and loads
  `.env` with `env_file:`. Port only on 127.0.0.1.
- Redis keeps its data in an append-only file on the volume `redis-data`:
  the accounts, API tokens and the audit stream must survive a restart.
  Open secrets land there too, only as ciphertext. Back the volume up.
- `.env` (from `.env.example`, git-ignored): every setting; this example sets
  `AUTH_PROVIDER=local`, the first admin and `AUDIT_LOG=true` with
  `AUDIT_LOG_REDIS=true`. `ENTRA_*`, `OIDC_*`, `DIRECTORY_*` and the other
  provider settings stay empty: with `AUTH_PROVIDER=local` they stop the start.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).
