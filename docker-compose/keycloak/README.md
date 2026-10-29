# Vanishly with Keycloak (example)

Try sign-in, recipients, responsible groups, the protected status page and
the people search on your own machine: Vanishly, Redis and Keycloak 26 with
a ready realm and three demo users. Plain http and demo users: **not for a
server**. For a real setup see [docs/INSTALLATION.md](../../docs/INSTALLATION.md)
and [docs/providers](../../docs/providers/).

## Start

```bash
cd docker-compose/keycloak
cp .env.example .env
# random secrets instead of the change-me values:
for k in KC_ADMIN_PASSWORD KC_CLIENT_SECRET KC_DIRECTORY_CLIENT_SECRET VANISHLY_AUTH_SECRET; do
  sed -i "s|^$k=.*|$k=$(openssl rand -hex 24)|" .env; done
docker compose up -d        # or: podman-compose up -d
```

Keycloak needs about 30 seconds the first time. Stop with
`docker compose down`; the realm is imported again on the next start, so
changes made in the admin console are lost.

| What | Address |
|---|---|
| Vanishly | http://localhost:3000 (`VANISHLY_PORT`) |
| Keycloak admin console | http://localhost:8080/admin, user `admin`, password `KC_ADMIN_PASSWORD` |
| Realm (issuer) | http://localhost:8080/realms/vanishly (`KEYCLOAK_PORT`) |

## Demo users

All with the password `DEMO_PASSWORD` from `.env` (demo only).

| User | E-mail | Groups |
|---|---|---|
| `alice` | alice@example.com | finance, staff |
| `bob` | bob@example.com | it, staff |
| `carol` | carol@example.com | finance, staff |

## What to try

1. Sign in as **alice**. In "Only for these people" type `bo`: the people
   search (members of `/staff`) offers Bob. Or pick the group **IT**.
2. Open "Responsible" and pick the group **Finance**, tick the confirmation
   and create the link.
3. Open the link in a private window and sign in as **bob**: the secret
   opens. As **carol** it says "not shared with your account".
4. Open the status link: not signed in, it asks for a sign-in. **bob** (opened
   it) sees the status and who opened it, but may not burn it; **carol**
   (Finance, responsible) and **alice** (creator) see it and may burn it.
5. "Sign out" signs out at Keycloak too and comes back to Vanishly.

## How it is set up

- `docker-compose.yml`: Keycloak (`start-dev`, realm import), Redis (memory
  only) and Vanishly with `AUTH_PROVIDER=keycloak`, `RECIPIENT_GROUPS`,
  `DIRECTORY_API` with `RECIPIENT_USER_GROUP=/staff`, `RESPONSIBLE=optional`,
  `STATUS_ACCESS=signed-in` and `RECEIPT_SHOW_VIEWER=true`. Vanishly runs in
  Keycloak's network, so the browser and Vanishly reach Keycloak under the
  same address. Ports only on 127.0.0.1.
- `realm-vanishly.json`: realm `vanishly` with the login client `vanishly`
  (redirect `<VANISHLY_URL>/auth/callback`, PKCE, sign-out redirect
  `/auth/logged-out`, a mapper for the `groups` claim), the service-account
  client `vanishly-directory` (reads users and groups for the people
  search), the groups `finance`, `it`, `staff` and the demo users. Keycloak
  fills the `${...}` values from the environment on import.
- `VANISHLY_IMAGE` in `.env` runs another image, e.g. one built locally.
