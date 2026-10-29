# Google Workspace

`AUTH_PROVIDER=google`. Issuer: `https://accounts.google.com`.

Every Google account can sign in with Google, so
**`AUTH_ALLOWED_DOMAINS` is required**: only addresses of these domains
whose Workspace domain (`hd` claim) matches get in. A private Google
account with an address of your domain is refused.

## Sign-in client

1. In the Google Cloud console of a project in your organization:
   **APIs & Services → OAuth consent screen**: user type **Internal**.
2. **Credentials → Create credentials → OAuth client ID → Web
   application**, authorized redirect URI
   `https://ots.example.com/auth/callback`.
3. Copy client id and client secret.

## Groups

Google puts no groups into the ID token. With `DIRECTORY_API=true`
Vanishly asks the directory for the groups of each user at sign-in (direct
memberships). The values are the group addresses:
`RECIPIENT_GROUPS=Finance=finance@example.com` or `*` for a search.

## Directory (search, groups)

1. Enable the **Admin SDK API** in the project.
2. **IAM & Admin → Service accounts → Create**; **Keys → Add key → JSON**.
   Mount the file and point `DIRECTORY_GOOGLE_CREDENTIALS_FILE` at it.
3. In the Admin console: **Security → Access and data control → API
   controls → Domain-wide delegation → Add new**, client id of the service
   account, scopes:

   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly
   ```

4. `DIRECTORY_GOOGLE_ADMIN`: an admin the service account acts for (a
   user with at least read access to users and groups, e.g. a custom role
   with "Users: Read" and "Groups: Read").

`RECIPIENT_USER_GROUP` is the address of the group whose members the form
suggests (also through nested groups).

## Example

```bash
AUTH_PROVIDER=google
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=change-me.apps.googleusercontent.com
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
AUTH_ALLOWED_DOMAINS=example.com
RECIPIENT_GROUPS=*
DIRECTORY_API=true
DIRECTORY_GOOGLE_CREDENTIALS_FILE=/run/secrets/google_service_account.json
DIRECTORY_GOOGLE_ADMIN=directory-reader@example.com
RECIPIENT_USER_GROUP=staff@example.com
```
