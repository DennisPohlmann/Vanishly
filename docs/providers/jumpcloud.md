# JumpCloud

`AUTH_PROVIDER=jumpcloud`. Issuer: `https://oauth.id.jumpcloud.com/`.

## Sign-in application

1. **SSO Applications → Add New Application → Custom Application**, with
   **Manage Single Sign-On (SSO)** → **OIDC**.
2. **Redirect URIs**: `https://ots.example.com/auth/callback`; client
   authentication **Client Secret Basic**; scopes `openid profile email`.
3. **User Groups**: the groups who may use Vanishly.
4. Copy client id and secret (shown once).

## Groups

In the application's SSO settings, **Include group attribute** with the
name `groups`: the claim then holds the names of the user's groups.
`RECIPIENT_GROUPS=Finance=Finance,IT=IT`. There is no group search with
JumpCloud.

## Directory (search)

An API key (**Settings → API key**, or a service account with read-only
access) as `DIRECTORY_API_TOKEN` (better `DIRECTORY_API_TOKEN_FILE`).

`RECIPIENT_USER_GROUP` is the id of the user group whose members the form
suggests (24 hex characters, in the URL of the group); members of nested
groups count. Organizations in the EU region:
`DIRECTORY_URL=https://console.eu.jumpcloud.com`.

## Example

```bash
AUTH_PROVIDER=jumpcloud
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://oauth.id.jumpcloud.com/
OIDC_CLIENT_ID=change-me
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
RECIPIENT_GROUPS=Finance=Finance,IT=IT
DIRECTORY_API=true
DIRECTORY_API_TOKEN_FILE=/run/secrets/jumpcloud_api_key
RECIPIENT_USER_GROUP=0123456789abcdef01234567
```
