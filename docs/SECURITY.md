# How Vanishly protects a secret

This page explains what happens to a secret from the moment it is typed in
until it is gone, what the server and Redis can see, and where the limits
are. The exact crypto format is in [INTERFACE.md](INTERFACE.md#crypto-format-v1).

## In short

- The secret is encrypted **in the sender's browser**. The server and Redis
  only ever get ciphertext.
- The key is a random 256-bit value that exists **only in the link**, after
  the `#`. Browsers never send that part to a server, so it never reaches
  Vanishly, the reverse proxy or any log.
- Redis keeps the ciphertext **in memory only**, with an expiry. It is
  deleted on the last view, on "Burn now", after too many wrong passphrases
  or when it expires, whichever comes first.
- If Redis cannot be written to, **no secret is handed out**: taking a view
  and handing out the ciphertext are one step that either fully happens or
  does not happen at all.

## The life of a secret

1. **Create.** The browser makes a random 32-byte key
   (`crypto.getRandomValues`) and a random salt, derives the encryption key
   with HKDF-SHA256 and encrypts the text with AES-256-GCM (Web Crypto). It
   sends ciphertext, IV, salt, the wanted expiry and number of views to
   `POST /api/v1/secrets`. The text and the key stay in the browser.
2. **Store.** The server picks a random 128-bit id and stores one Redis hash
   with the ciphertext, IV, salt, views left and the passphrase check value
   (see below). The hash gets a Redis expiry (`PEXPIREAT`), so Redis deletes
   it by itself at the expiry time, even if Vanishly is not running.
3. **Share.** The browser builds the link `https://…/s/<id>#<key>`. Only the
   person with the full link can decrypt.
4. **Open.** Opening the link shows only a button, so link previews in chat
   and mail apps cannot use up a view. After the click the browser asks for
   one view (`POST /api/v1/secrets/<id>/reveal`), gets the ciphertext and
   decrypts it locally with the key from the `#` part.
5. **Gone.** On the last view Redis deletes the ciphertext in the same step
   that hands it out. What stays is the receipt (status and view times, no
   content, no IP addresses) for `RECEIPT_KEEP` seconds.

## Recipients (sign-in)

With `AUTH_PROVIDER` the sender can name who may open a secret. This is a
second lock next to the link, enforced by the server:

- The server hands out the ciphertext, the salt and the view count only
  after a signed-in user (session cookie or bearer token) matched the list.
  The check comes before the passphrase check and the view count, so a
  non-recipient can neither use a view nor burn the secret with wrong
  passphrases. The answer is the same for every non-recipient and never
  names the recipients.
- The encryption does not change: the key is still only in the link. An
  administrator who reads Redis gets ciphertext and keyed hashes, not the
  secret. The other way round, someone who reads Redis can skip the
  server's recipient check, so the check protects against people with the
  link, not against the server operator.
- The login uses OpenID Connect with the authorization code flow, PKCE,
  `state` and `nonce` (`openid-client`), checks the ID token and, with
  Entra, the tenant. The session cookie is `HttpOnly`, `SameSite=Lax`,
  `Secure` with the `__Host-` prefix behind HTTPS; a cookie on a request
  from another site (`Sec-Fetch-Site`, `Origin`) does not count, against
  CSRF. After a login the browser returns only to `/`, `/s/<id>` or
  `/r/<id>`.
- The sign-in loses the part after `#` on its way through the provider, so
  the secret page keeps the key in the browser tab's `sessionStorage` for
  the round trip and removes it when the page comes back. It never goes to
  the server. This is the only place Vanishly stores the key, and only in
  the recipient's own tab.
- Addresses are matched on the user name / e-mail claims. If an address is
  given to a new person while a secret for the old one is still open, the
  new person could open it; keep expiries short.
- The people search (`RECIPIENT_USER_GROUP`) shows every signed-in sender
  names and addresses of that group's members (at most 10 per search, from
  2 characters on, rate limited). It uses read-only directory access of
  the app itself (Graph application permissions, a Keycloak service
  account, an Okta API token, ... see [providers](providers/README.md));
  tokens, member lists (5 minutes) and answers (one minute) stay in
  memory, nothing goes to Redis or the logs. Errors are logged with the
  provider and the HTTP status only. Paging links from a directory are
  followed only on the same server, so its token never goes elsewhere.
- Directory credentials (API tokens, client secrets, the Google service
  account key, AWS keys) can be read from files (`*_FILE`, Docker or
  Kubernetes secrets); give them read access only.
- Sign-out with `AUTH_LOGOUT=provider` sends the browser to the provider's
  end-session endpoint with the ID token as `id_token_hint`; the ID token is
  kept in the session hash for that only and deleted with it. The page CSP
  allows the provider's origin in `form-action` (the sign-out and "another
  account" forms redirect there), nothing else. The way back
  (`/auth/logged-out`) only leads to `/`, `/s/<id>` or `/r/<id>`.
- `AUTH_ALLOWED_DOMAINS` limits sign-in by domain. With Google it is
  required and the Workspace domain (`hd`) must match too: without it any
  Google account could sign in and create secrets.

## Passphrase

A passphrase is a second factor next to the link: with it, the link alone
is not enough.

- The browser stretches the passphrase with PBKDF2-SHA256 (600,000
  iterations, random salt) and mixes the result into the encryption key. The
  passphrase itself never leaves the browser.
- So that the server can refuse a wrong passphrase **without** knowing it,
  the browser also derives a separate check value (HKDF, own label). Redis
  stores only the SHA-256 of that value; the server compares in constant
  time (`timingSafeEqual`).
- A wrong passphrase uses no view. After `PASSPHRASE_ATTEMPTS` wrong tries
  (default 5) the secret is destroyed.

## What Redis holds, and what it does not

| Stored | Not stored |
|---|---|
| ciphertext, IV, salt, iteration count | the secret in plain text |
| SHA-256 of the passphrase check value | the key (it is only in the link) |
| views left, wrong passphrase count, created, expires | the passphrase |
| receipt: state, view times, burn time | IP addresses, user agents, names (except `RECEIPT_SHOW_VIEWER`) |
| rate limit counters, keyed by a truncated SHA-256 of the IP | |
| with sign-in: recipients as keyed hashes (HMAC with `AUTH_SECRET`) | the addresses or groups a secret is for |
| with sign-in: sessions (name, user name, recipient hashes) under a hash of the cookie | access or refresh tokens of the provider |

The Compose file runs Redis **without persistence** (`--save ""
--appendonly no`) and on a `tmpfs`, so nothing of a secret is ever written
to disk. A Redis restart drops all open secrets; that is on purpose.
Someone who copies Redis memory gets ciphertext that is useless without the
link.

## Can a secret survive when Redis has a problem?

Vanishly is built so that a Redis problem can **lose** a secret, but never
**leak** one or hand it out more often than allowed.

- **Taking a view is atomic.** One Lua script checks that the secret
  exists, counts the view down, reads the ciphertext and deletes the hash
  on the last view. Redis runs a script as one step, so two people opening
  a one-view link at the same moment cannot both get it.
- **Fail-closed.** The first thing the script does is a write (counting the
  view down). If Redis refuses writes (read-only replica, `OOM` with
  `maxmemory`, lost connection), the script stops there, nothing is read
  and the request fails with an error. The browser shows "something went
  wrong", not the secret.
- **Burn and wrong passphrases** are writes too. If they fail, the request
  fails and says so; it never reports "burned" when the secret still exists,
  and a wrong passphrase that cannot be counted is refused, not let through.
- **No Redis, no secret.** The ciphertext lives only in Redis. While Redis is
  down nobody can open a secret; when it comes back without persistence the
  open secrets are gone.
- **Health check.** `/healthz` answers 200 only when Redis answers **and
  accepts a write**; otherwise 503, and Docker marks the container
  unhealthy. At start Vanishly makes the same write check and stops with an
  error if Redis cannot be reached or written to.
- **Memory full.** With the Compose default `--maxmemory-policy volatile-ttl`
  Redis drops the secrets closest to expiry first; they are then gone, not
  readable. With `noeviction` new secrets are refused instead.

## Server-side exceptions: `/v1/share` and `/v1/open`

Two API endpoints exist for scripts that cannot run the crypto themselves
(e.g. `curl`). With them, the **server** sees the plain text for the
duration of the request:

- `POST /api/v1/share` gets the secret in plain text, encrypts it exactly
  like a browser would, returns the links with the key and forgets the key.
- `POST /api/v1/open` gets the full link with the key (and the passphrase),
  takes one view, decrypts and returns the text.

Neither stores or logs the text, key or passphrase. They still mean you
trust the server and the TLS connection to it. Switch them off with
`ENABLE_SHARE_API=false` and `ENABLE_OPEN_API=false` if all your users work
in the browser. The web pages never use them.

## The web pages

- **Content Security Policy:** only scripts and styles from the server
  itself, no inline scripts, no third-party requests, no framing.
- **No leaks through the address bar:** `Referrer-Policy: no-referrer`, and
  the key is in the `#` part, which browsers do not send anyway.
- **No caching:** pages and API answers carry `Cache-Control: no-store`.
- **No tracking:** the only cookie is the language choice; search engines
  are told not to index (`X-Robots-Tag`).
- **Access log** (`ACCESS_LOG`): method, path, status and time; ids in the
  path are replaced by `:id`.

## Abuse protection

- Rate limits per client IP for creating and for reading
  (`RATE_LIMIT_*`). Behind a reverse proxy set `TRUST_PROXY`, or every
  visitor counts as the proxy.
- Ids have 128 random bits, so guessing a link is not practical, and every
  guess counts against the read limit.
- Optional rules: `REQUIRE_PASSPHRASE`, `MIN_PASSPHRASE_LENGTH`,
  `PASSPHRASE_COMPLEXITY`, `MIN_SECRET_CHARS`, `CONFIRM_CHECKBOX`.

## Containers

Both containers run without root (Vanishly as `node`, uid 1000; Redis as
`redis`, uid 999), with read-only file systems, all Linux capabilities
dropped and `no-new-privileges`. Redis is reachable only inside the Compose
network, Vanishly only on `127.0.0.1` for the reverse proxy. CI scans the
code, the dependencies and both images on every build and every night
([DEVELOPMENT.md](DEVELOPMENT.md#security-checks)).

## What Vanishly cannot protect against

- **Whoever has the full link** (and the passphrase, if set) can read the
  secret. Send link and passphrase on different channels.
- **The sender's or recipient's device.** Malware, a browser extension or a
  screenshot sees the plain text.
- **A compromised server** could deliver changed JavaScript that leaks the
  next secrets typed in. This is true of every web-based tool; run Vanishly
  on a server you trust, behind HTTPS (`HSTS=true`).
- **The receipt link** contains the key as well (unless
  `ENABLE_RECEIPT_SHARE_LINK=false`). Keep it as private as the share link.
- **Weak passphrases** can be guessed offline by someone with a copy of
  Redis, by testing them against the stored check value. That alone still
  decrypts nothing without the link, and the 600,000 PBKDF2 iterations
  make every guess slow; `MIN_PASSPHRASE_LENGTH` and
  `PASSPHRASE_COMPLEXITY` enforce strong ones.
- **A view is used when the ciphertext is handed out.** If the recipient's
  browser crashes right after, the view is gone.

## Reporting a vulnerability

Please report security problems privately via
[GitHub security advisories](https://github.com/DennisPohlmann/Vanishly/security/advisories/new),
not as a public issue.
