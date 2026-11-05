# Microsoft Entra ID

`AUTH_PROVIDER=entra`. Vanishly signs in at
`https://login.microsoftonline.com/<tenant id>/v2.0` and refuses tokens of
other tenants. Entra uses its own settings (`ENTRA_*`), not `OIDC_*`.

## App registration

1. Entra admin center → **App registrations** → **New registration**:
   name `Vanishly`, "Accounts in this organizational directory only",
   redirect URI **Web** `https://ots.example.com/auth/callback`.
2. **Certificates & secrets** → new client secret; note its value.
3. Optional, to sign out of Microsoft too (`AUTH_LOGOUT=provider`): add
   `https://ots.example.com/auth/logged-out` as a second **Web** redirect
   URI (Authentication). By default (`local`) only Vanishly signs out, as
   the Microsoft session is shared with Microsoft 365.
4. Optional: in **Enterprise applications** → Vanishly → Properties, set
   "Assignment required" to limit who can sign in at all.

The whole site behind **Entra Application Proxy** (pre-authentication)
works as well, alone or together with this: the proxy keeps everybody
outside the tenant away, the built-in sign-in decides per secret.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `ENTRA_TENANT_ID` | (required) | Directory (tenant) id, a GUID; tokens of other tenants are refused |
| `ENTRA_CLIENT_ID` | (required) | Application (client) id of the app registration |
| `ENTRA_CLIENT_SECRET` | (required) | Client secret; or `ENTRA_CLIENT_SECRET_FILE` with a file that holds it (Docker secrets) |
| `ENTRA_AUTHORITY` | `https://login.microsoftonline.com` | Only for national clouds, e.g. `https://login.microsoftonline.us` |
| `ENTRA_GRAPH` | `false` | `true`: use Microsoft Graph for the group and people search and for users in more than 200 groups (see below) |
| `ENTRA_GRAPH_URL` | `https://graph.microsoft.com` | Only for national clouds |
| `ENTRA_SHOW_ADDRESS` | `upn` | The address shown for a person in the header, the people search, the status page and the view log: `upn` (the sign-in name, e.g. `jdoe@example.com`) or `mail` (the mail address, e.g. `john.doe@example.com`; see [Who is who](#who-is-who)) |

Plus `BASE_URL` and `AUTH_SECRET`, and the general sign-in settings in
[CONFIG.md](../CONFIG.md#sign-in-and-recipients-auth_-entra_-oidc_-directory_-recipient).
`DIRECTORY_*` does not apply to Entra; it uses `ENTRA_GRAPH`.

## Who is who

Vanishly matches recipients by names the account cannot pick itself: the
`preferred_username` / `upn` (the sign-in name), and `email` only when
Entra verified its domain (optional claim `xms_edov`). Guests are matched
by their e-mail address.

The UPN often differs from the mail address (`jdoe@example.com` and
`john.doe@example.com`). The UPN stays the key (API tokens, `ADMIN_USERS`,
the audit log); `ENTRA_SHOW_ADDRESS=mail` only changes the address shown,
and the people search then adds a person with their mail address. Vanishly
takes it from Microsoft Graph (`ENTRA_GRAPH=true` with `User.Read.All`,
the user's `mail`, kept 5 minutes), otherwise from the `email` claim when
`xms_edov` is set; without one it shows the UPN.

UPN and mail address both work as recipient, in the form and on the API,
whatever `ENTRA_SHOW_ADDRESS` says: with `ENTRA_GRAPH=true` Vanishly adds
the user's mail from Graph to the names they match at sign-in, so a secret
for `john.doe@example.com` opens for the account `jdoe@example.com`
(without Graph only when the `email` claim is verified).

`RECIPIENTS_DIRECTORY_ONLY=true` (needs `ENTRA_GRAPH=true` and
`User.Read.All`) refuses addresses that are no user of the tenant: each
recipient and responsible person is looked up in Graph (`userPrincipalName`
or `mail`) when the secret is created, and both the UPN and the mail of the
user found are stored. Mail aliases (`proxyAddresses`) are not matched.

## Groups

**Token configuration** → **Add groups claim** → "Security groups" (ID
token: "Group ID"). The values are the groups' object ids:
`RECIPIENT_GROUPS=IT Admins=<group object id>,HR=<group object id>`.

Users in more than 200 groups get no `groups` claim. Vanishly then asks
Microsoft Graph when `ENTRA_GRAPH=true`; otherwise such a user cannot open
secrets for a group.

## Group and people search (Graph)

**API permissions** → Microsoft Graph → **Application permissions** →
`GroupMember.Read.All` (group search with `RECIPIENT_GROUPS=*`, users in
more than 200 groups) and `User.Read.All` (people search) → **Grant admin
consent**, then `ENTRA_GRAPH=true`.

`RECIPIENT_USER_GROUP` is the object id of the group whose members the form
suggests. Entra searches the directory for each query; a person is added
with their UPN (guests: their e-mail; with `ENTRA_SHOW_ADDRESS=mail` their
mail address).

## API tokens

**Expose an API** → Application ID URI `api://<client id>`, add a scope
(e.g. `Secrets.Use`), set "accessTokenAcceptedVersion" to 2 in the
manifest, and `AUTH_API_AUDIENCE=api://<client id>`. Vanishly checks
issuer, audience, expiry and tenant. Details:
[CONFIG.md](../CONFIG.md#api-with-sign-in).

## Example (`.env` or Compose)

A ready Compose example with every setting is
[docker-compose/entra](../../docker-compose/entra/README.md). The same lines go
into `.env` next to its `docker-compose.yml` (or that of
[docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml))
or into an `environment:` block.

```bash
AUTH_PROVIDER=entra
BASE_URL=https://ots.example.com
ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000
ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000000
ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
# RECIPIENT_GROUPS=IT Admins=<group object id>,HR=<group object id>
# ENTRA_GRAPH=true
# RECIPIENT_USER_GROUP=<object id of the group whose members are suggested>
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Microsoft shows `AADSTS50011` (redirect URI mismatch) | The redirect URI is not exactly `<BASE_URL>/auth/callback`; check `BASE_URL` and the **Web** platform (not SPA) |
| Microsoft shows `AADSTS7000215` (invalid client secret) | The value of the secret, not its id, belongs into `ENTRA_CLIENT_SECRET`; or it expired |
| Log `auth: sign-in failed: token from another tenant` | `ENTRA_TENANT_ID` is not the tenant the account belongs to |
| A group member gets "not shared with your account" | No groups claim (step "Groups"), or the user is in more than 200 groups and `ENTRA_GRAPH` is off |
| Log `auth: people search failed: Graph answered 403` | Admin consent for `User.Read.All` / `GroupMember.Read.All` missing |

General problems: [providers/README.md](README.md#troubleshooting).
