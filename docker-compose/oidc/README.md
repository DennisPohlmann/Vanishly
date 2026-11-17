# Vanishly with any OpenID Connect provider (example)

Vanishly and Redis with sign-in through any provider that speaks OpenID
Connect discovery (`<issuer>/.well-known/openid-configuration`), e.g.
Authentik, Zitadel, Authelia or Dex (not tested one by one). For Entra,
Keycloak, Okta, Auth0, Google, PingOne, JumpCloud and Cognito use their own
examples instead. There is no people or group search with `oidc`: senders
type e-mail addresses and pick the groups listed in `RECIPIENT_GROUPS`. All
settings are in `.env`; the details of each are in
[docs/providers/oidc.md](../../docs/providers/oidc.md) and
[docs/CONFIG.md](../../docs/CONFIG.md).

## 1. Setup at your provider

1. A **confidential client** (web application) with the **authorization
   code** flow; Vanishly always sends PKCE (S256).
2. Redirect URI `<BASE_URL>/auth/callback` (e.g.
   `http://localhost:3000/auth/callback` for a test on your machine); post
   logout redirect URI `<BASE_URL>/auth/logged-out`.
3. Scopes `openid profile email`; the ID token must carry a verified
   `email`.
4. Groups (optional): a `groups` claim (list of strings) in the **ID
   token**, or another claim name with `OIDC_GROUPS_CLAIM`.

To try sign-in without a provider, see the test login server in
[docs/providers/oidc.md](../../docs/providers/oidc.md#try-it-locally).

## 2. Settings and start

```bash
cd docker-compose/oidc
cp .env.example .env
# random secrets:
for k in AUTH_SECRET RATE_LIMIT_KEY; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `BASE_URL` | the address of step 2, without `/auth/callback` |
| `OIDC_ISSUER` | the issuer exactly as in the discovery document (trailing `/` included) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | of the client (or `OIDC_CLIENT_SECRET_FILE`) |

Optional:

| Setting | Example |
|---|---|
| `OIDC_SCOPES` | add the scope that puts the groups into the ID token, if your provider needs one |
| `OIDC_GROUPS_CLAIM` | the claim with the groups (empty: `groups`) |
| `RECIPIENT_GROUPS` | `Ops=ops,Finance=finance` (values of the groups claim) |
| `ADMIN_GROUPS` | a value of the groups claim; or `ADMIN_USERS` with e-mail addresses |

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
  example sets (`AUTH_PROVIDER=oidc`, `OIDC_*`, `RECIPIENTS=optional`, the groups and admins), then the others with their defaults. `ENTRA_*` and
  `LOCAL_*` are for other providers and stay empty.
- Own templates: mount them in your `docker-compose.override.yml`, as in
  [standalone](../standalone/docker-compose.yml).

Problems of any OpenID Connect provider: [Troubleshooting](../../docs/providers/oidc.md#troubleshooting);
for all providers: [providers/README.md](../../docs/providers/README.md#troubleshooting).
