# Any other OpenID Connect provider

`AUTH_PROVIDER=oidc` works with every provider that speaks OpenID Connect
discovery (`<issuer>/.well-known/openid-configuration`), e.g. Authentik,
Zitadel, Authelia or Dex (not tested one by one; the test server below
is). For Keycloak, Okta, Auth0, Google, PingOne, JumpCloud and Cognito use
their presets instead ([overview](README.md)); they check the issuer and
add the directory search.

## Sign-in client

1. A **confidential client** (web application) with the **authorization
   code** flow; Vanishly always sends PKCE (S256).
2. Redirect URI `https://ots.example.com/auth/callback`; post logout
   redirect URI `https://ots.example.com/auth/logged-out` (for
   `AUTH_LOGOUT=provider`, the default; providers without a logout
   endpoint in their discovery sign out only in Vanishly).
3. Scopes `openid profile email` (`OIDC_SCOPES`, add the scope that puts
   the groups into the ID token if your provider needs one).
4. The ID token must carry a verified `email` (not `email_verified:
   false`).

## Required settings

`AUTH_PROVIDER=oidc`, `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` (or `OIDC_CLIENT_SECRET_FILE`) and `AUTH_SECRET` (or
`AUTH_SECRET_FILE`). All others:
[CONFIG.md](../CONFIG.md#sign-in-and-recipients-auth_-entra_-oidc_-directory_-recipient).

## Groups

Let the provider put a `groups` claim (a list of strings) into the **ID
token**; another claim name with `OIDC_GROUPS_CLAIM`. List the values in
`RECIPIENT_GROUPS`: `RECIPIENT_GROUPS=Ops=ops,Finance=finance`.

## People and group search

None with `oidc`: there is no directory API (`DIRECTORY_*` does not apply
and `RECIPIENT_GROUPS=*` stops the start). Senders type e-mail addresses
and pick the groups listed in `RECIPIENT_GROUPS`.

## Example (`.env` or Compose)

The same lines go into `.env` next to `docker-compose.yml`
([docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml))
or into its `environment:` block.

```bash
AUTH_PROVIDER=oidc
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://sso.example.com/application/o/vanishly/
OIDC_CLIENT_ID=vanishly
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
# OIDC_GROUPS_CLAIM=groups
# RECIPIENT_GROUPS=Ops=ops,Finance=finance
```

## Try it locally

`docker-compose/standalone/docker-compose.auth-test.yml` adds a test login
server ([mock-oauth2-server](https://github.com/navikt/mock-oauth2-server))
with `AUTH_PROVIDER=oidc`, where you can sign in as anybody. Only for your
own machine:

```sh
cd docker-compose/standalone
docker compose -f docker-compose.yml -f docker-compose.auth-test.yml up -d
```

Open `http://localhost:3000` and click "Sign in". On the test server's page
type any user name and, as claims,
`{"email": "alice@example.com", "name": "Alice", "groups": ["ops"]}`.
Create a secret for `bob@example.com`, open the link in a private window
and sign in there as Bob (or as somebody else, to see it refused).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Log `auth: sign-in provider not reachable: ...` | `OIDC_ISSUER` is wrong or its discovery document cannot be reached from the container; the issuer must match the `issuer` in that document exactly (trailing `/` included) |
| Log `auth: sign-in failed: the account has no e-mail address or user name` | The ID token has no `email`, or `email_verified: false`; add the `email` scope or mark the address verified |
| A group member gets "not shared with your account" | The groups are not in the ID token (only in the access token or userinfo), or the claim has another name: set `OIDC_GROUPS_CLAIM` |
| Start stops with `RECIPIENT_GROUPS=* is not available with AUTH_PROVIDER=oidc` | List the groups as `Name=<value>` |

General problems: [providers/README.md](README.md#troubleshooting).
