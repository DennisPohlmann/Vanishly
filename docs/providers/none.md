# No sign-in (default)

`AUTH_PROVIDER=none`, the default. Nobody signs in; there is no "Sign in"
link, no session cookie and no call to any identity provider.

## What works

- Everybody who can reach the site creates secret links (`/`), with
  passphrase, expiry, views and the generator as configured
  ([CONFIG.md](../CONFIG.md)).
- Whoever has a link can open it; the key after `#` is the only lock,
  plus the passphrase if one is set.
- The status page works by link (`STATUS_ACCESS=link`, the only choice
  without sign-in): whoever has the status link sees the state and the
  view times and may burn the secret (`ENABLE_BURN`).
- The API works as without sign-in: `POST /api/v1/secrets`, the reveal,
  `/api/v1/share` and `/api/v1/open` as switched on
  ([CONFIG.md](../CONFIG.md#api-access)).

## What is off

- Recipients ("Only for these people"), groups and the people search.
- Responsible people (`RESPONSIBLE` must stay `off`) and the status page
  for signed-in people only (`STATUS_ACCESS=signed-in`).
- Names and addresses on the status page (`RECEIPT_SHOW_VIEWER`).

Setting any sign-in setting (`ENTRA_*`, `OIDC_*`, `DIRECTORY_*`, `AUTH_*`,
`RECIPIENT*`, `RECEIPT_SHOW_VIEWER`), `RESPONSIBLE=optional|required` or
`STATUS_ACCESS=signed-in` without a provider stops the start with a
message, so a half configured sign-in cannot go unnoticed.

## Keep the site to your people without sign-in

Put a login of your reverse proxy (or the VPN) in front of `/` and
`/api/v1/secrets`, and leave `/s/`, `/api/v1/secrets/{id}` and the static
files open for the recipients
([CONFIG.md](../CONFIG.md#api-access)). Or put the whole site behind a
pre-authenticating proxy such as Entra Application Proxy.

## Settings (`.env` or Compose)

Nothing to set: leave `AUTH_PROVIDER` empty or `none`, as in
[docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Start stops with `... needs AUTH_PROVIDER (...)` | A sign-in setting is set while `AUTH_PROVIDER=none`; remove it or pick a provider |
| Start stops with `RESPONSIBLE needs sign-in (AUTH_PROVIDER)` | `RESPONSIBLE` is `optional` or `required`; set it to `off` |
| Start stops with `STATUS_ACCESS=signed-in needs sign-in (AUTH_PROVIDER)` | Leave `STATUS_ACCESS` empty or `link` |
