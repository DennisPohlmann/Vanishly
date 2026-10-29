# PingOne

`AUTH_PROVIDER=ping`. Issuer: `https://auth.pingone.<region>/<environment
id>/as` (`.com`, `.eu`, `.ca`, `.asia`, `.com.au`).

## Sign-in application

1. **Applications → Applications → +**: **OIDC Web App**.
2. **Configuration**: response type **Code**, grant type **Authorization
   Code**, PKCE **S256 required**, token endpoint authentication **Client
   Secret Basic**, redirect URI `https://ots.example.com/auth/callback`,
   signoff URL `https://ots.example.com/auth/logged-out`.
3. Enable the application and copy client id and secret.

## Groups

**Attribute Mappings → Add**: attribute `groups`, PingOne mapping **Group
Names** (`memberOfGroupNames`), in the ID token.
`RECIPIENT_GROUPS=Finance=Finance,IT=IT` (the group names). There is no
group search with PingOne.

## Directory (search)

A **Worker** application with the role **Identity Data Read Only** for the
environment, as `DIRECTORY_CLIENT_ID` / `DIRECTORY_CLIENT_SECRET`.

`RECIPIENT_USER_GROUP` is the id of the group whose members the form
suggests. The API address follows the issuer
(`https://api.pingone.<region>/v1/environments/<id>`); `DIRECTORY_URL`
overrides it.

## Example (`.env` or Compose)

Required: `AUTH_PROVIDER`, `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` (or `_FILE`) and `AUTH_SECRET` (or `_FILE`). The
same lines go into `.env` next to `docker-compose.yml`
([docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml))
or into its `environment:` block.

```bash
AUTH_PROVIDER=ping
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://auth.pingone.eu/11111111-2222-3333-4444-555555555555/as
OIDC_CLIENT_ID=change-me
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
RECIPIENT_GROUPS=Finance=Finance,IT=IT
DIRECTORY_API=true
DIRECTORY_CLIENT_ID=change-me
DIRECTORY_CLIENT_SECRET_FILE=/run/secrets/ping_worker_secret
RECIPIENT_USER_GROUP=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Start stops with `OIDC_ISSUER: the issuer of ping, e.g. ...` | Use `https://auth.pingone.<region>/<environment id>/as` |
| A group member gets "not shared with your account" | The `groups` attribute mapping (Group Names) is missing in the ID token |
| Log `auth: people search failed: PingOne answered 403` | The worker application lacks **Identity Data Read Only** for this environment |

General problems: [providers/README.md](README.md#troubleshooting).
