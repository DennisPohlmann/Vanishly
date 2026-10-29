# Keycloak

`AUTH_PROVIDER=keycloak`. Issuer: `https://<host>/realms/<realm>` (older
versions with `/auth`: `https://<host>/auth/realms/<realm>`).

## Sign-in client

1. **Clients → Create client**: OpenID Connect, client id `vanishly`.
2. **Client authentication** on (confidential), **Standard flow** on,
   **Direct access grants** off.
3. **Valid redirect URIs**: `https://ots.example.com/auth/callback`;
   **Valid post logout redirect URIs**:
   `https://ots.example.com/auth/logged-out`; **Web origins**:
   `https://ots.example.com`.
4. **Advanced → Proof Key for Code Exchange Code Challenge Method**: `S256`.
5. **Credentials**: copy the client secret.
6. Users need an e-mail address with **Email verified** on.

## Groups

**Client scopes → vanishly-dedicated → Add mapper → By configuration →
Group Membership**: token claim name `groups`, **Add to ID token** on.

- **Full group path** on: the values are `/finance`, `/staff/it`.
- Off: just the names (`finance`). Vanishly treats `finance` as
  `/finance`, so both work for top-level groups; for nested groups keep
  the full path on, or two groups with the same name become one.

`RECIPIENT_GROUPS=Finance=/finance,IT=/it` (or `finance`, `it`).

## Directory (search)

A second client for the search keeps the sign-in client small:

1. **Clients → Create client**: client id `vanishly-directory`, **Client
   authentication** on, only **Service accounts roles** on.
2. **Service account roles → Assign role → Filter by clients**:
   `realm-management` `view-users`, `query-users`, `query-groups`.
3. Copy its secret.

Without `DIRECTORY_CLIENT_ID` Vanishly uses the sign-in client; it then
needs the service account and the roles itself.

`RECIPIENT_USER_GROUP` is the path (`/staff`) or the id of the group whose
members the form suggests. Only direct members count, not those of
subgroups. `RECIPIENT_GROUPS=*` searches all groups by name and offers
their full paths.

## Example

```bash
AUTH_PROVIDER=keycloak
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://sso.example.com/realms/main
OIDC_CLIENT_ID=vanishly
OIDC_CLIENT_SECRET=change-me
AUTH_SECRET=change-me-to-32-or-more-random-characters
RECIPIENT_GROUPS=*
DIRECTORY_API=true
DIRECTORY_CLIENT_ID=vanishly-directory
DIRECTORY_CLIENT_SECRET=change-me
RECIPIENT_USER_GROUP=/staff
```

`DIRECTORY_URL` overrides the admin API address (default: the issuer with
`/admin/realms/<realm>`), e.g. when the admin API is only reachable
internally.
