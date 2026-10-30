# Usage

## Pages

| Path | Page |
|---|---|
| `/` | Create a secret: text, optional passphrase, expiry, number of views, password generator |
| `/s/<id>#<key>` | The recipient's link: shows a button; the secret is fetched and decrypted only after the click |
| `/r/<id>#<key>` | The status page (receipt): state, created, expires, views left, the history (created, opened, burned), share link, burn button. With `STATUS_ACCESS=signed-in` only after a sign-in, see below |
| `/api/docs` | API documentation (Scalar API reference) |
| `/api/openapi.json` | OpenAPI 3.1 document |
| `/healthz` | `ok` (200) when Redis answers and accepts writes, otherwise 503 |
| `/auth/login`, `/auth/logout`, `/auth/logged-out` | Sign in and out; `/auth/logged-out` is where the provider returns after a sign-out (only with `AUTH_PROVIDER`) |
| `/settings/tokens` | "API tokens" (user menu, `API_TOKENS=true`): make a personal API token (name, lifetime, allowed addresses, and what it may do: "only create", "only retrieve", "both", plus status and burn, as far as allowed; shown once), list your tokens with expiry, last use and state, revoke them; shows "2 of 3 active tokens" (`API_TOKEN_MAX_PER_USER`) and, at the limit, a notice instead of the form |
| `/admin` | "Administration" (user menu, admins only, `ADMIN_USERS` / `ADMIN_GROUPS`), tabs: audit log (filter, export, hash chain check), secrets (metadata of every secret: who for whom, comment, state, who opened it), API tokens (all, revoke), technical users (API-only accounts and their tokens: issue, rotate, revoke), token permissions per user and group; warns when Redis has no persistence ([CONFIG.md](CONFIG.md#admin-interface)) |

The header has the language switch and the light/dark switch (remembered in
the browser) and, with sign-in, "Sign in", or the full name with the
e-mail address below it and "Sign out". "Sign out" also signs out at the
provider (`AUTH_LOGOUT=provider`, the default except with Entra ID).
With `AUDIT_COMMENT=optional` or `required` the form has a "Comment" field
(what the secret is for, e.g. a ticket number): it goes into the audit log
and onto the status page, not into the secret.

## How sharing works

1. The browser creates a random 256-bit key, encrypts the secret with
   AES-256-GCM and sends only the ciphertext to the server.
2. The server stores it in Redis with the expiry and the number of views
   and returns two ids.
3. The browser shows two links: the **share link** `/s/<id>#<key>` for the
   recipient and the **receipt link** `/r/<receipt id>#<key>` for you. The
   key after `#` never reaches the server.
4. The recipient opens the link and clicks "Show the secret". The server
   hands out the ciphertext once and counts the view; at the last view it
   deletes it. The browser decrypts and removes the key from the address
   bar.

With a **passphrase** the key is mixed with a PBKDF2 hash of the
passphrase, so the link alone is not enough. Send the passphrase on another
channel (phone, other messenger). The server checks a verifier derived from
it before it hands out anything: a wrong passphrase uses no view, and after
`PASSPHRASE_ATTEMPTS` wrong ones the secret is destroyed.

With **sign-in** on (`AUTH_PROVIDER`), you may have to sign in first, and
you can add people (e-mail addresses) and groups under "Only for these
people". With the people search (`RECIPIENT_USER_GROUP`) type part of a
name, pick the person from the suggestions (arrow keys and Enter, or a
click) and repeat for more people. Then the recipient has to sign in, and only the listed people
can open the secret; for anybody else it stays closed and no view is used.
The link with its key is still needed, as before.

With `RESPONSIBLE`, the folded section **"Responsible"** names the people
or groups who look after the secret, with the same picker
(`RESPONSIBLE=required`: at least one).

**Who sees the status page.** With `STATUS_ACCESS=link` (without sign-in
the only choice) whoever has the receipt link: **keep it private**, it
contains the key too, so it can show the share link again. With
`STATUS_ACCESS=signed-in` (the default with sign-in) the page asks for a
sign-in and shows the status only to you (the creator), the responsible
people and those who opened the secret; only you and the responsible
people may burn it. It then also shows who created it and who is
responsible, and with `RECEIPT_SHOW_VIEWER=true` the name and address of
each person who opened it. Details: [CONFIG.md](CONFIG.md#status-page).

## Receipt states

| State | Meaning |
|---|---|
| Not viewed yet | open, no view yet |
| Viewed, still available | at least one view, views left |
| Viewed, deleted | all views used, the secret is gone |
| Burned | you burned it, or too many wrong passphrases |
| Expired | the expiry passed before all views were used |

Receipts stay `RECEIPT_KEEP` seconds after the expiry, then they are gone
too. They hold times, no IPs or browsers; with sign-in the names and
addresses shown on the status page (`RECEIPT_SHOW_VIEWER`,
`STATUS_ACCESS=signed-in`).

## Operation

- Health check: `GET /healthz` (Docker `HEALTHCHECK` uses it).
- Logs: one line per request, e.g. `POST /api/v1/secrets 201 4.1ms`; ids
  appear as `:id`, IPs and user agents are never logged.
- Nothing to back up: secrets are meant to disappear. Back up your `.env`
  and your own templates.
