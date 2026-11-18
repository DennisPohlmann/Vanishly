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
   content, no IP addresses) for `RECEIPT_KEEP` (default 7 days).

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
  the recipient's own tab. The automatic sign-in (`AUTH_AUTO_LOGIN`) uses
  the same round trip, at most once per tab (a `sessionStorage` flag), and
  goes back only to `/`, `/s/<id>` or `/r/<id>`.
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
- `AUTH_PROVIDER=local` (own accounts, [providers/local.md](providers/local.md#security)):
  passwords as scrypt hashes (N=2^15, r=8, p=3, random salt, constant-time
  compare); unknown addresses cost the same hash and get the same answer.
  The sign-in and password forms are accepted only from this origin
  (`Sec-Fetch-Site`, `Origin`); every sign-in gets a new session id; failed
  attempts are counted per account (`LOCAL_LOGIN_ATTEMPTS`) and per IP. A
  session carries the account's session version: a new password, disabling
  or deleting ends it at once; role and groups are read on every request.
  The last active admin cannot be removed, and nobody removes themselves.

## Passphrase

A passphrase is a second factor next to the link: with it, the link alone
is not enough.

- The browser stretches the passphrase with PBKDF2-SHA256 (600,000
  iterations, random salt) and mixes the result into the encryption key. The
  passphrase itself never leaves the browser.
- So that the server can refuse a wrong passphrase **without** knowing it,
  the browser also derives a separate check value (HKDF, own label). Redis
  stores only the SHA-256 of that value; the server hashes what the browser
  sends and compares the two hashes inside the same Lua script that takes
  the view, so parallel guesses cannot get past the attempt limit.
- A wrong passphrase uses no view. After `PASSPHRASE_ATTEMPTS` wrong tries
  (default 5) the secret is destroyed.

## What Redis holds, and what it does not

| Stored | Not stored |
|---|---|
| ciphertext, IV, salt, iteration count | the secret in plain text |
| SHA-256 of the passphrase check value | the key (it is only in the link) |
| views left, wrong passphrase count, created, expires | the passphrase |
| receipt: state, view times, burn time | IP addresses, user agents, names (except `RECEIPT_SHOW_VIEWER` and `STATUS_ACCESS=signed-in`, below) |
| with `STATUS_ACCESS=signed-in`: creator, responsible people and openers as keyed hashes (who may see the status), and the names and addresses of creator and responsible to show on the status page | |
| rate limit counters, keyed by a truncated HMAC-SHA256 of the IP with `RATE_LIMIT_KEY` (never stored in Redis); a plain hash of an IPv4 address could be reversed by trying all addresses | |
| with sign-in: recipients and responsible people as keyed hashes (HMAC with `AUTH_SECRET`) | the addresses or groups a secret is for |
| with sign-in: sessions (name, user name, recipient hashes) under a hash of the cookie | access or refresh tokens of the provider |
| with `AUTH_PROVIDER=local`: the accounts (address, name, role, groups, scrypt hash), without expiry, so Redis needs persistence | passwords |

The Compose file runs Redis **without persistence** (`--save ""
--appendonly no`) and on a `tmpfs`, so nothing of a secret is ever written
to disk. A Redis restart drops all open secrets; that is on purpose.
Someone who copies Redis memory gets ciphertext that is useless without the
link.

## Can a secret survive when Redis has a problem?

Vanishly is built so that a Redis problem can **lose** a secret, but never
**leak** one or hand it out more often than allowed.

- **Taking a view is atomic.** One Lua script checks that the secret
  exists, checks the passphrase (counting wrong ones and burning at the
  limit), counts the view down, reads the ciphertext and deletes the hash
  on the last view. Redis runs a script as one step, so two people opening
  a one-view link at the same moment cannot both get it.
- **Fail-closed.** Before it reads the ciphertext the script writes (counting
  the view down). If Redis refuses writes (read-only replica, `OOM` with
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
  visitor counts as the proxy. The counters are in Redis, so all replicas
  share them (express-rate-limit with a store on `src/store.js`). With
  sign-in the sign-in pages have their own counter, and every request the
  sign-in check looks at (not static files, `/healthz`) counts against a
  ceiling of 10 × the larger limit.
- Optional IP access lists (`CREATE_`, `READ_`, `ADMIN_ALLOWED_IPS` /
  `_DENIED_IPS`, [CONFIG.md](CONFIG.md#ip-access)), only in the
  environment: checked on `req.ip` before anything else, so a refused read
  uses no view. They rely on the client IP being right (`TRUST_PROXY`).
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

## Audit log and API tokens

Optional (`AUDIT_LOG`, `API_TOKENS`, see [CONFIG.md](CONFIG.md#audit-log)).

- **What the audit log holds:** who (signed-in address and name, or the
  API token with its owner), what (event type, outcome, reason), when, for
  whom (recipient addresses and groups, responsible), the comment, run id,
  source address and browser name (`AUDIT_LOG_IP`, `AUDIT_LOG_USER_AGENT`).
  **Never** the secret, its ciphertext, key, passphrase, verifier, the URL
  fragment, a full API token, or a secret/receipt id: secrets appear only
  as `ref`, an HMAC of the id, so the log cannot be used to open anything.
  The tests check this for every format. It is personal data: restrict who
  reads the file, the stream and the admin page, and set a retention.
- **Tamper evidence:** a hash chain per instance plus, with
  `AUDIT_LOG_HMAC_KEY`, an HMAC per event; `audit:verify` finds changed,
  removed, inserted or moved events. Keep the key away from where the log
  is stored and ship a copy elsewhere (stdout, syslog, OTLP), then a cut-off
  end shows too. The admin page itself is logged; with
  `AUDIT_LOG_FAIL=closed` (the default) no secret is created or handed out,
  no sign-in completed and no token made unless its event was written.
- **API tokens:** 256 random bits behind the prefix `vnly_<id>_` (secret
  scanners can find leaked ones). Redis keeps only an HMAC-SHA256 with a
  key derived from `AUTH_SECRET`, compared in constant time; the token is
  shown once (only in the create answer, `Cache-Control: no-store`; the
  page empties its fields when it is left, so Back or a reload does not
  show it again). A token acts as its owner with the scopes picked, cannot make
  or manage tokens, and with networks set (`API_TOKEN_IP_BINDING=required`
  makes it mandatory) works only from there: a token passed on to someone
  elsewhere is refused and logged. The client address comes from
  `TRUST_PROXY`; set it exactly to your proxies, else `X-Forwarded-For` can
  be forged. With `API_TOKEN_REQUIRED=true` scripts cannot use the API
  without a token; the pages of the server still call it with their
  session (the browser marks them `Sec-Fetch-Site: same-origin`; a script
  could fake that header, but only with a signed-in session of its own, and
  every call is then logged under that user).
- **Sign-in of MCP clients (`MCP_OAUTH`):** an MCP client gets an API
  token only after the person signed in on this server and pressed
  "Allow" on a page that names the client and the local address the
  browser returns to. The flow is OAuth 2.1 with PKCE (S256 only): a code is
  useless without the verifier that stays in the client, works once and
  for one minute, and is bound to its client and redirect URI. Redirect URIs
  are loopback addresses only (`127.0.0.1`, `localhost`, `[::1]`; any port,
  RFC 8252), so a code never leaves the person's computer. Registered
  clients are not stored: the client id carries name and redirect URIs and
  an HMAC (key derived from `AUTH_SECRET`), so a client id cannot be
  changed to point elsewhere, and open registration fills no storage. The
  consent page is a same-origin form post (`Sec-Fetch-Site`/`Origin`), its
  CSP `form-action` allows only this site and that one loopback origin. The
  token is an ordinary API token of the person (HMAC in Redis, revocable,
  `api.token_created` with `details.via: oauth`). A local program the
  person runs could start this flow, but only the person can allow it.
- **Technical users and admin tokens:** technical users have no sign-in, only
  the tokens an admin issues; disabling or deleting one revokes them all.
  The scope `admin` (the admin API) exists only with `API_ADMIN_TOKENS`
  (on by default when admins are set), only for technical users, given by a
  signed-in admin or, unless `API_ADMIN_TOKEN_CAN_ISSUE_ADMIN=false`, by
  another admin token, bound to IP networks and for at most 90 days by
  default, and every call needs a comment. Set
  `API_ADMIN_TOKEN_CAN_ISSUE_ADMIN=false` (or `API_ADMIN_TOKENS=false`) to
  keep admin tokens in the hands of signed-in admins. The admin interface
  shows secrets' metadata only, never content or keys; with `ADMIN_BURN`
  (default on) an admin can burn a secret that is not opened yet (it never
  sees its content), logged as `secret.burned` with reason `admin`.

## MCP server and the CIS MCP Server Benchmark

`/mcp` ([CONFIG.md](CONFIG.md#mcp-server)) follows the CIS MCP Server
Benchmark v1.0.0 where it applies to a remote Streamable HTTP server with
tools only. **Pass**: met by Vanishly itself. **Operator**: depends on the
deployment. **Deviation**: deliberately not met, with the reason.
**n.a.**: Vanishly has no such feature (stdio, Resources, Prompts, Tasks,
Sampling, MCP Apps, files; Elicitation only for the confirmation below) or it is about MCP clients or
third-party servers (sections 4 and 8, except the server side of 4.1.3).

| Recommendation | Status | How |
|---|---|---|
| 1.1 Protocol version pinned and logged | Pass | `MCP_PROTOCOL_VERSIONS` (allowlist, floor `2025-06-18`); other versions `-32022`, header missing or differing `-32020`, missing `_meta` `-32602`, all `400` and logged (`mcp.request_denied`); version in every `mcp.*` event |
| 1.2, 1.3 Capability baseline, re-validation | Operator | `server/discover` advertises a fixed `{"tools":{}}`, no `listChanged`, no extensions; the tool list changes only with the `ENABLE_*` switches |
| 1.4 Client and server identity | Pass | `clientInfo` (name, version) in every `mcp.*` event; `serverInfo` in each 2026-07-28 result. Matching against an asset inventory: operator |
| 2.2 TLS only | Operator | TLS ends at the reverse proxy; `HSTS=true` behind HTTPS |
| 2.3 Auth through proxies to SSE | n.a. | no SSE: one JSON answer per request |
| 2.4 Metadata headers match the body | Pass | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (also in Base64 form) checked against the body, `-32020` |
| 2.5 Origin validated | Pass | a foreign `Origin` gets `403` and `mcp.request_denied` (`origin_not_allowed`) |
| 3.1.2 OAuth 2.1 or short-lived tokens | Pass | `MCP_OAUTH` (OAuth 2.1, PKCE S256); token lifetime `MCP_OAUTH_TOKEN_EXPIRY` (`1d`), no refresh tokens. Hand-made API tokens follow `API_TOKEN_MAX_EXPIRY` (set it, e.g. `90d`) |
| 3.2.1 Per-tool authorization | Pass | each tool needs one scope (`create_secret`: `create`; `get_secret_status`: `status`; `burn_secret`: `burn`), checked by the API with the owner's current policy; every call logged as `mcp.tool_called` |
| 3.2.2 No token passthrough | Pass | the token is checked by Vanishly and never sent on; tools call the in-process API |
| 3.2.3 Annotations not used for authorization | Pass | authorization comes only from token scopes and policy |
| 3.3.1 Audience-bound tokens (RFC 8707) | Pass | `resource` must be `<BASE_URL>/mcp` (else `invalid_target`); the token gets audience `mcp` and is refused on `/api/v1/*` (`api.token_audience_denied`) |
| 3.3.2 Discovery metadata over TLS, approved issuer | Pass / Operator | Vanishly is its own authorization server, named in the protected resource metadata; TLS by the proxy |
| 3.3.3 No shared downstream service accounts | n.a. | no downstream services |
| 3.3.4 Minimal scopes, step-up | Pass | OAuth offers only `create`, `status` and `burn` (never `read`); a missing scope answers `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."` |
| 3.3.5 Confused deputy, static client ids | Pass / Deviation | no static client ids, no third-party authorization server; consent page per client; only `native` clients with loopback redirects. Any port on the loopback address is accepted, as RFC 8252 section 7.3 requires |
| 4.1.3 Elicitation consented, redacted, identity-bound (server side) | Pass / limit | only with `CONFIRM_CHECKBOX=true`: every `create_secret` asks the person (form mode, a yes/no only; no secret asked for or shown, warnings name only the kind of access data found). The model cannot confirm (no `confirmed` argument); without elicitation or on an older protocol the tool refuses (`confirmation_unavailable`). Logged as `mcp.tool_called` (`confirmation` `requested` / `accepted`, reason `confirmation_declined`), own rate limit counter. No `requestState`, no URL mode: nothing to bind or tamper with. Limit: the yes is what the MCP client reports; a compromised client can forge it, as any client input. Consent UI, decline buttons and the client-side records are the client's |
| 5.1.1 Tool argument validation | Pass | arguments checked against the tool's input schema (types, lengths, ranges, enums, no unknown fields) before the API, refusals as tool errors (`invalid_arguments`) |
| 5.2.2, 5.2.3 Sessions, legacy streams | Pass | no `Mcp-Session-Id`, no SSE stream, `GET`/`DELETE` `405`, `Last-Event-ID` ignored |
| 5.6.1 Idempotency keys | Deviation | a replay would have to store the answer, and the answer of `create_secret` holds the link with its key: the server would keep the key. Each call creates a new secret; `burn_secret` is idempotent |
| 6.1 Context minimized | Pass / limit | tools return only the API's answer (links, status, no secret contents); the plaintext of `create_secret` passes the AI client and its provider |
| 6.2 Tokens and keys protected | Pass | tokens stored only as HMAC; the server never holds a secret's key |
| 7.1.1 Lifecycle and invocation records | Pass | `mcp.request`, `mcp.tool_called`, `mcp.request_denied` with `AUDIT_LOG=true` |
| 7.1.2 Non-null request ids | Pass | an `id` that is `null` or not a string or integer is refused (`-32600`); the id is in the events |
| 7.1.3 Monotonic timestamps | Pass | audit timestamps never go back within one process; hash chain with `seq` |
| 7.2.1 Alerts on audience failures | Pass / Operator | `api.token_audience_denied`, `api.token_denied` in the audit log; alerting in the SIEM |
| 9.1, 9.2 Containers, least privilege | Pass / Operator | see [Containers](#containers); gateway ingress rules by the operator |
| 10.1 Caching | Pass | `Cache-Control: no-store` on `/mcp`; `tools/list` and `server/discover` say `ttlMs` 300000, `cacheScope` `public` (the same for everyone) |
| 10.2 Size limits and quotas | Pass | body limit (64 KiB or 8 × `MAX_SECRET_CHARS`, whichever is larger), own per-IP counter `mcp` (`RATE_LIMIT_READ`), per-token `API_TOKEN_RATE_LIMIT` |

For the strictest setup: `MCP_PROTOCOL_VERSIONS=2026-07-28` (clients that
start with `initialize` then cannot connect), `AUDIT_LOG=true` shipped to
a SIEM, `API_TOKEN_MAX_EXPIRY` set, TLS with `HSTS=true`, and
`MCP_OAUTH` instead of hand-made tokens.

## REST API and the CIS API Security Guide

### Who may do what

| Caller | May | Needs |
|---|---|---|
| Anyone with the link | open a secret without recipients (`/s`, `reveal`, `/v1/open`); with `STATUS_ACCESS=link` see its status and burn it | the full link (and the passphrase, if set) |
| Anyone | create secrets (`/v1/secrets`, `/v1/share`); `GET /v1/config`, the index, the OpenAPI document | `AUTH_CREATE=anyone` or no sign-in |
| Signed-in user | create; open secrets addressed to them or their groups; `/v1/me`, people and group search; with `STATUS_ACCESS=signed-in` the status of secrets they created, are responsible for or opened, and burn the ones they created or are responsible for | a session or a provider token (`AUTH_API_AUDIENCE`) |
| Signed-in user, session only | own API tokens (`/v1/tokens`), "My secrets" (`/v1/me/secrets`) | the session cookie; a token cannot manage tokens |
| API token | what its owner may, limited to its scopes: `create` (create), `read` (meta, reveal, open), `status` (status), `burn` (burn; learns only whether the secret was still there) | `vnly_` token, from its networks, re-checked against the owner's current policy on every call |
| Admin | the admin interface and `/v1/admin/*`: audit log, all tokens, token policies, secrets' metadata (never content), burn, local accounts, technical users | `ADMIN_USERS` / `ADMIN_GROUPS` and a session |
| Technical user | what its tokens' scopes allow; scope `admin` only with `API_ADMIN_TOKENS`, IP-bound, with a comment on every call | tokens issued by an admin; no sign-in |
| MCP client | the MCP tools of its person (`create`, `status`, `burn`) at `/mcp` only | an OAuth token with audience `mcp` |

### Mapping

The REST API (`/api/v1`) follows the CIS API Security Guide v1.0.0
(March 2025) where it applies to a self-hosted product. Most of the guide
is about the processes of whoever builds and runs an API (documentation
standards, threat modelling, release, incident response, decommissioning);
those points are listed once as **Operator**. Status words as in the
[MCP section](#mcp-server-and-the-cis-mcp-server-benchmark).

| Recommendation | Status | How |
|---|---|---|
| 1.1.1-1.1.8 Documentation | Pass | one OpenAPI 3.1 document ([openapi.json](../openapi/openapi.json)) for every endpoint, method, parameter, model, error and rate limit, linted in CI; served reduced to the switched-on endpoints at `/api/openapi.json` and `/api/docs`; [INTERFACE.md](INTERFACE.md#rest-api) |
| 1.1.5 Automation-friendly format | Pass | OpenAPI; a contract test checks the answers of the main endpoints against their schemas (`tests/api.test.js`) |
| 1.1.9, 3.2.4 Communicate changes | Pass | `CHANGELOG.md` and the GitHub release notes for every release |
| 1.2.1-1.2.5, 2.1.1-2.1.5 Roles and access | Pass | see the table above; RBAC (admins, groups) plus per-token scopes; the recipient check (`mayOpen`) runs before the passphrase check and the view count |
| 2.1.3 MFA | Operator | through the OIDC provider; `AUTH_PROVIDER=local` has passwords only ([local.md](providers/local.md#security)) |
| 1.3.1 Data protection | Pass | end-to-end encryption; Redis holds ciphertext and keyed hashes only ([What Redis holds](#what-redis-holds-and-what-it-does-not)) |
| 1.3.3 Threat model | Pass / Operator | this page, including [what Vanishly cannot protect against](#what-vanishly-cannot-protect-against) |
| 2.1.6 Credentials and tokens | Pass | tokens 256 bits, stored as HMAC-SHA256, constant-time compare; local passwords as scrypt; sessions under a hash of the cookie |
| 2.2.1 Requirements per endpoint | Pass | one table in `src/app.js` with switch, rate-limit bucket, scope and IP class per endpoint; `security` per operation in the OpenAPI document |
| 2.2.2, 3.1.4 TLS | Operator | TLS and the HTTP-to-HTTPS redirect at the reverse proxy, `HSTS=true`; Redis over TLS with `rediss://` and `REDIS_TLS_CA_FILE` |
| 2.2.3 Request validation and authorization | Pass | every field checked on the server (types, base64url patterns, lengths, ranges); ids through `validId()`; body size limit; IP lists, scopes and recipients before anything is read or changed |
| 2.2.4 Response validation | Pass | answers built field by field, never whole records; salt and views only for recipients; admins see metadata only; contract test |
| 2.2.5 Rate limits | Pass | per client IP (`RATE_LIMIT_*`, shared in Redis, IPs HMACed), per token (`API_TOKEN_RATE_LIMIT`), own counters for sign-in, OAuth and MCP, `429` with `Retry-After`. WAF and DDoS protection: operator |
| 2.2.6, 2.3.3, 2.4.6, 4.1.1, 4.1.2 Logging | Pass | access log without ids or IPs; the [audit log](#audit-log-and-api-tokens) with hash chain, never secrets, keys or full tokens; shipping to a SIEM (syslog, OTLP, webhook) |
| 2.3.1, 2.3.2 Errors | Pass | one shape `{"error", "message"}`, no stack traces or internals (`500 internal`); status codes as meant (`401`, `403`, `404`, `405` with `Allow`, `409`, `410`, `413`, `422`, `429`, `502`, `503`) |
| 2.3.5 Error recovery | Pass | fail-closed view taking, `AUDIT_LOG_FAIL=closed`, `/healthz` with a write check |
| 2.4.1-2.4.5 Sessions | Pass | new session id per sign-in, `__Host-` cookie (`HttpOnly`, `SameSite=Lax`, `Secure`), `AUTH_SESSION_TTL` (8 hours), sign-out ends the session in Redis, a new password or disabling ends all of an account |
| 2.4.3 Token lifetime | Pass / Operator | MCP tokens `1d` without refresh; hand-made tokens live as long as `API_TOKEN_MAX_EXPIRY` allows (default `never`): set it, e.g. `1y` |
| 2.5.1-2.5.5 Third-party code | Pass | five runtime dependencies ([THIRD-PARTY-LICENSES.md](../THIRD-PARTY-LICENSES.md)), SBOM with each release, `npm audit`, Trivy, CodeQL and Dependabot ([DEVELOPMENT.md](DEVELOPMENT.md#security-checks)) |
| 2.6.1-2.6.4 Testing | Pass | type check, tests, OpenAPI lint, accessibility and scans on every push and pull request |
| 3.1.3 Release process | Pass | semantic-release, started by hand on `main` only |
| 3.2.1-3.2.3 Versioning | Pass | `/api/v1`, only additive changes within it, breaking ones as `/api/v2` with `Deprecation` / `Sunset` ([Versioning](INTERFACE.md#versioning)) |
| 4.3.1 Audit reporting | Pass | audit export (JSON, CSV, JSONL), `audit:verify`, the admin view is logged itself |
| 4.3.2 Retention | Pass / Operator | secrets expire in Redis, receipts after `RECEIPT_KEEP`, the audit stream with `AUDIT_LOG_REDIS_MAXLEN`; rotating and keeping the audit file is the operator's |
| 1.2.2, 1.3.2, 2.2.7, 2.4.7, 2.5.6-2.5.8, 3.1.1, 3.1.2, 3.1.5, 3.3, 4.1.3, 4.1.4, 4.2, 4.3.3, 5 | Operator | exposure and IP lists, compliance, environments, secrets (`*_FILE`), monitoring and alerting (`/healthz`, the audit stream), scaling (Helm chart with autoscaling), penetration tests, decommissioning (Vanishly's data ends with Redis; [uninstall](INSTALLATION.md)) |

For the strictest API setup: `API_TOKEN_REQUIRED=true`,
`API_TOKEN_IP_BINDING=required`, `API_TOKEN_MAX_EXPIRY` set,
`API_TOKEN_RATE_LIMIT` set, `ENABLE_SHARE_API=false` and
`ENABLE_OPEN_API=false` if no script needs them, `AUDIT_LOG=true` shipped
to a SIEM, TLS with `HSTS=true`, and an OIDC provider with MFA.

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
  With `STATUS_ACCESS=signed-in` the status page needs a sign-in and shows
  only to the creator, the responsible people and those who opened the
  secret; with `STATUS_ACCESS=link` whoever has the link sees it and may
  burn the secret.
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
