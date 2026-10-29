# Okta

`AUTH_PROVIDER=okta`. Issuer: a custom authorization server
(`https://<org>.okta.com/oauth2/default`) or the org server
(`https://<org>.okta.com`).

## Sign-in app

1. **Applications → Create App Integration**: OIDC, **Web Application**.
2. Grant type **Authorization Code**; **Sign-in redirect URI**
   `https://ots.example.com/auth/callback`; **Sign-out redirect URI**
   `https://ots.example.com/auth/logged-out`.
3. **Assignments**: the people or groups who may use Vanishly.
4. Copy client id and client secret. Okta requires PKCE for this flow only
   if you switch it on; Vanishly always sends it.

## Groups

Put the group names into the ID token as `groups`:

- Org server: in the app, **Sign On → OpenID Connect ID Token → Groups
  claim filter**: `groups`, matches regex `.*` (or a narrower filter).
- Custom authorization server (**Security → API → Authorization Servers →
  default → Claims → Add Claim**): name `groups`, include in **ID Token**,
  value type **Groups**, filter as above.

`RECIPIENT_GROUPS=IT=IT Admins,Finance=Finance` (the group names; spaces
are fine).

## Directory (search)

An API token (**Security → API → Tokens → Create token**) of an admin with
the **Read-only Administrator** role. The token acts with that admin's
rights; keep it in a secret file.

`RECIPIENT_USER_GROUP` is the id of the group whose members the form
suggests (`00g...`, in the URL of the group in the admin console).
`RECIPIENT_GROUPS=*` searches groups by name.

## Example

```bash
AUTH_PROVIDER=okta
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://example.okta.com/oauth2/default
OIDC_CLIENT_ID=0oa1example
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
RECIPIENT_GROUPS=*
DIRECTORY_API=true
DIRECTORY_API_TOKEN_FILE=/run/secrets/okta_api_token
RECIPIENT_USER_GROUP=00g1abcdefghijklmnop
```

The Management API is called at the issuer's host; `DIRECTORY_URL`
overrides it.
