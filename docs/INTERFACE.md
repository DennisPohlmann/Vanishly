# Interfaces

## REST API

The contract is [openapi/openapi.json](../openapi/openapi.json) (OpenAPI
3.1); a running instance serves it at `/api/openapi.json` and as an API
reference ([Scalar](https://github.com/scalar/scalar)) at `/api/docs`. All endpoints are below `/api`, take and return JSON and are
rate-limited per client IP (`429` with `Retry-After`). Without sign-in
(`AUTH_PROVIDER=none`, the default) they need no authentication: the link
is the permission. With sign-in, creating may need a signed-in user, and a
secret with recipients opens only for one of them: `401 login_required`
without a session or bearer token, `403 not_recipient` for anybody else,
on `GET /v1/secrets/{id}`, `/reveal` and `/v1/open`; neither uses a view
([CONFIG.md](CONFIG.md#sign-in-and-recipients)). Switched
off parts (`ENABLE_*`, see [CONFIG.md](CONFIG.md#switches-enable_)) answer
`404` with `"error": "endpoint_disabled"` (a wrong path: `not_found`; a known path with another method: `405
method_not_allowed` with an `Allow` header); `GET /api/v1/config` lists them under `features`. Errors look like
`{"error": "not_found", "message": "..."}`. With `CONFIRM_CHECKBOX=true`
a create (`/v1/secrets`, `/v1/share`) needs `"confirmed": true` (the JSON
value, not a string); otherwise `400 confirmation_required`, whose `message`
and `rule` give the rule of the form's checkbox in the language of the request:
`{"error": "confirmation_required", "message": "I confirm that this secret contains only one password: ... Send \"confirmed\": true to confirm.", "rule": "I confirm that ..."}`.

| Method and path | Purpose |
|---|---|
| `GET /api`, `GET /api/v1` | index: name, version, `api: "v1"`, docs and OpenAPI links and the endpoints switched on; a browser goes to `/api/docs` |
| `GET /api/v1/config` | limits and options of this server (`ENABLE_CONFIG_API`) |
| `POST /api/v1/secrets` | store a secret encrypted by the client |
| `POST /api/v1/share` | encrypt on the server and store (for scripts) |
| `POST /api/v1/open` | open a secret link, with its passphrase, on the server (for scripts) |
| `GET /api/v1/secrets/{id}` | check a secret without using a view; passphrase parameters (`ENABLE_SECRET_META_API`) |
| `POST /api/v1/secrets/{id}/reveal` | take one view, get the ciphertext |
| `GET /api/v1/receipts/{id}` | status for the sender (token scope `status`; `STATUS_ACCESS=signed-in`: creator, responsible, openers after sign-in; `ENABLE_RECEIPT_API`) |
| `POST /api/v1/receipts/{id}/burn` | destroy the secret now (token scope `burn`; `STATUS_ACCESS=signed-in`: creator and responsible only) |
| `GET /api/v1/me` | who is signed in (sign-in on; `ENABLE_ME_API`) |
| `GET /api/v1/me/secrets?status=&from=&to=&limit=` | the signed-in user's secrets (created by them, or for them or one of their groups) from the audit stream, metadata only, same shape as `/admin/secrets` (`MY_SECRETS`, `AUDIT_LOG_REDIS`; session only) |
| `GET /api/v1/groups?q=` | search groups for recipients (`RECIPIENT_GROUPS`: the listed groups, with `*` the directory) |
| `GET /api/v1/people?q=` | search people for recipients (`RECIPIENT_USER_GROUP`, in the provider's directory): `{ people: [{ name, user, mail }] }`, put `user` into `recipients` |
| `GET/POST /api/v1/tokens`, `POST /api/v1/tokens/{id}/revoke` | personal API tokens (`API_TOKENS`; session only), see [API tokens](#api-tokens-and-admin-api) |
| `GET /api/v1/admin/audit`, `/admin/audit/verify`, `/admin/tokens` | audit log and all tokens for admins (`ADMIN_USERS`, `ADMIN_GROUPS`) |

With `AUDIT_LOG` every answer carries `X-Run-Id` and `X-Request-Id` (the
caller's own or a new UUID) and each action is an audit event
([Audit log](#audit-log)). With `API_TOKENS` scripts authenticate with
`Authorization: Bearer vnly_...`; with `API_TOKEN_REQUIRED=true` only so
(`401 token_required`). Refusals: `401 invalid_token` / `token_expired`,
`403 ip_not_allowed` / `insufficient_scope`; `403 ip_denied` when the
client IP may not create, read or use the admin area
([`*_ALLOWED_IPS` / `*_DENIED_IPS`](CONFIG.md#ip-access)); with `AUDIT_LOG_FAIL=closed`
`503 audit_unavailable` when the log cannot be written.

Pages of the sign-in (not part of the API): `GET /auth/login?return=/s/<id>`,
`GET /auth/callback` (the provider's redirect), `POST /auth/logout`. With
`AUTH_PROVIDER=local`: `GET /auth/login` shows the form, `POST /auth/login`
(form fields `user`, `password`, `return`), `GET`/`POST /settings/password`
(`current`, `password`, `repeat`); both posts only from this origin.

### Examples

```bash
# Server-side encryption: returns shareUrl and receiptUrl with the key.
curl -s -X POST https://ots.example.com/api/v1/share \
  -H 'Content-Type: application/json' \
  -d '{"secret":"s3cret","passphrase":"optional","ttl":86400,"views":1}'

# Open a link from a script (also one made in the web form), with its passphrase.
# Uses one view; the server decrypts and forgets link and passphrase.
curl -s -X POST https://ots.example.com/api/v1/open \
  -H 'Content-Type: application/json' \
  -d '{"link":"https://ots.example.com/s/<id>#<key>","passphrase":"optional"}'
# -> {"secret":"s3cret","viewsLeft":0}

# With sign-in and AUTH_API_AUDIENCE: a token of your provider, and recipients.
curl -s -X POST https://ots.example.com/api/v1/share \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"secret":"s3cret","recipients":["bob@example.com"],"recipientGroups":["<group id>"]}'

# The same with responsible people (RESPONSIBLE): they may see the status
# and burn it (STATUS_ACCESS=signed-in).
curl -s -X POST https://ots.example.com/api/v1/share \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"secret":"s3cret","recipients":["bob@example.com"],"responsibleGroups":["<group id>"]}'

# Status and burn with the receipt id from the answer (with
# STATUS_ACCESS=signed-in also with the token of an allowed person)
curl -s https://ots.example.com/api/v1/receipts/<receiptId>
curl -s -X POST https://ots.example.com/api/v1/receipts/<receiptId>/burn
```

For end-to-end encryption from your own code use the functions of
`public/js/vanishly-crypto.js` (works in browsers and Node.js 20+):

```js
import { encryptSecret, decryptSecret, unlockKey, verifierFor } from './public/js/vanishly-crypto.js';

const { key, payload } = await encryptSecret('s3cret', 'optional passphrase');
const res = await fetch('https://ots.example.com/api/v1/secrets', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...payload, ttl: 3600, views: 1 }),
}).then((r) => r.json());
const link = `https://ots.example.com${res.secretPath}#${key}`;
```

### Versioning

The API has one version, `v1` (the `/api/v1` prefix, `"api": "v1"` in the
index). Within `v1` changes are only additive: new endpoints, new optional
request fields, new answer fields and new error codes. Clients ignore
fields they do not know and must not depend on the order of fields.
A breaking change (an endpoint or field removed or renamed, a type or
meaning changed, an optional field made required) comes only with a new
prefix, `/api/v2`; `v1` is then still served for at least one more major
release. An operation that is going away is marked `deprecated` in the
OpenAPI document and answers with a `Deprecation` header (RFC 9745), and
with `Sunset` (RFC 8594) once the date is set; the release notes
(`CHANGELOG.md`, GitHub releases) say so. The endpoints available on one
server also depend on its switches (`ENABLE_*`); `/api/v1` and
`/api/openapi.json` list exactly those.

## MCP and OAuth endpoints

Outside `/api` and not in the OpenAPI document; what they do and how to
set them up: [CONFIG.md](CONFIG.md#mcp-server). The `/.well-known/oauth-*`
and `/oauth/*` endpoints exist only with `MCP_OAUTH`; `/oauth/*` has its
own rate limit (`RATE_LIMIT_READ`, bucket `oauth`).

| Method and path | Purpose |
|---|---|
| `POST /mcp` | MCP server (`ENABLE_MCP`): one JSON-RPC message per request, answered as JSON (Streamable HTTP without sessions); tools `create_secret`, `get_secret_status`, `burn_secret`. With `CONFIRM_CHECKBOX=true` `create_secret` (2026-07-28 only) answers first with `resultType: "input_required"` and `inputRequests.confirm`, an `elicitation/create` in form mode (`message`: warnings by kind and the rule; schema `{"confirm": boolean}`); the client retries with `params.inputResponses.confirm` = `{"action": "accept", "content": {"confirm": true}}`, then the server sends `"confirmed": true` to the API. The tool has no `confirmed` argument; tool errors `confirmation_declined` (decline, cancel) and `confirmation_unavailable` (older protocol or no elicitation in form mode). Switched off: `404` with a JSON-RPC error. With `MCP_OAUTH` and no valid token: `401` with `WWW-Authenticate: Bearer resource_metadata="<BASE_URL>/.well-known/oauth-protected-resource/mcp", scope="create status"`; a tool without the token's scope: `403` with `error="insufficient_scope"` and JSON-RPC `-32001`. Versions `MCP_PROTOCOL_VERSIONS`; errors: `-32020` missing or differing `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` header, `-32022` unsupported version (`data.supported`, `data.requested`), `-32602` bad params or missing `_meta` (2026-07-28), `-32600` bad message or an `id` that is not a string or integer, all with `400`; `-32601` unknown method (`404` with 2026-07-28); `GET`/`DELETE` `405`. Own rate limit counter (bucket `mcp`) |
| `GET /.well-known/oauth-protected-resource`, `.../oauth-protected-resource/mcp` | protected resource metadata (RFC 9728): `resource` `<BASE_URL>/mcp`, this server as authorization server, the scopes |
| `GET /.well-known/oauth-authorization-server` | authorization server metadata (RFC 8414): the endpoints below, `code` with PKCE `S256`, public clients only (`none`) |
| `POST /oauth/register` | dynamic client registration (RFC 7591): `redirect_uris` (1 to 5 loopback URIs), `client_name`, `application_type` only `native` (or left out) → `201` with a signed `client_id` (nothing is stored) |
| `GET /oauth/authorize` | starts the sign-in: `client_id`, `redirect_uri`, `response_type=code`, `code_challenge` + `code_challenge_method=S256`, `state`, `scope`, optional `resource`; sends the browser to `/oauth/<id>` |
| `GET/POST /oauth/<id>` | sign-in if needed, the consent page "Allow access"; allow or deny, then back to the client's `redirect_uri` with `code` (or `error`), `state` and `iss` |
| `POST /oauth/token` | `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, `code_verifier` (form-encoded), optional `resource` (must be `<BASE_URL>/mcp`, else `invalid_target`) → `{access_token, token_type: "Bearer", expires_in, scope}`; the access token is a personal API token (`vnly_...`) valid only at `/mcp` (audience `mcp`), lifetime `MCP_OAUTH_TOKEN_EXPIRY`, scopes `create`/`status` at most, no refresh token |

## Crypto format v1

| Part | Definition |
|---|---|
| key | 32 random bytes, base64url (43 characters), only in the URL fragment |
| salt | 16 random bytes |
| pk | without passphrase: empty; with passphrase: PBKDF2-HMAC-SHA256(passphrase, salt, iterations = 600000, 32 bytes) |
| encryption key | HKDF-SHA256(ikm = key ‖ pk, salt, info = `vanishly v1 enc`), AES-256 |
| verifier | HKDF-SHA256(ikm = pk, salt, info = `vanishly v1 auth`, 32 bytes); the server stores SHA-256(verifier) |
| ciphertext | AES-256-GCM(encryption key, iv = 12 random bytes, aad = `vanishly v1`), with the 16-byte tag |

All binary values are base64url without padding. The server has the
ciphertext and the verifier hash but never the key; the verifier cannot
decrypt anything without the key.

## Redis keys

All keys start with `REDIS_PREFIX` (default `vanishly:`).

| Key | Type | Content | Lifetime |
|---|---|---|---|
| `s:<id>` | hash | `ct`, `iv`, `salt`, `it`, `vh` (verifier hash), `views` left, `attempts`, `rid`, `created`, `expires`, `to` (recipients as HMAC-SHA256 with `AUTH_SECRET`, only when restricted) | until expiry, last view or burn |
| `r:<rid>` | hash | `sid`, `created`, `expires`, `maxViews`, `viewsLeft`, `state`, `pass`, `burned`, `rc` (number of recipients), `cm` (the comment, `AUDIT_COMMENT`), with `STATUS_ACCESS=signed-in` `cr` (creator), `rs` (responsible, HMAC-SHA256 like `to`) and `who` (names and addresses of creator and responsible, to show) | expiry + `RECEIPT_KEEP` |
| `r:<rid>:o` | set | HMACs of who opened the secret signed in (`STATUS_ACCESS=signed-in`: they may see the status) | like `r:<rid>` |
| `r:<rid>:v` | list | view times (ms); with `RECEIPT_SHOW_VIEWER` `time<TAB>name<TAB>address` of the signed-in viewer | like the receipt |
| `sess:<hash>` | hash | a sign-in: `name`, `user`, `mail` (only with `ENTRA_SHOW_ADDRESS=mail` and a mail address other than `user`), `ids` (the recipient hashes of the user's addresses and groups), `created`, with `AUTH_LOGOUT=provider` `it` (the ID token, only sent back to the provider as `id_token_hint` at sign-out); the key is the SHA-256 of the cookie | `AUTH_SESSION_TTL` |
| `oidc:<state>` | hash | a sign-in in progress: PKCE verifier, nonce, return path | 10 minutes, used once |
| `oauth:req:<id>` | hash | an MCP client's sign-in in progress (`MCP_OAUTH`): `c` (client id), `r` (redirect URI), `ch` (PKCE challenge), `st` (state), `sc` (scopes asked) | 10 minutes, used once |
| `oauth:code:<sha256>` | hash | an authorization code (only its SHA-256 as key): `u`, `n`, `ids` (the person), `c`, `r`, `ch`, `sc` (scopes granted) | 1 minute, used once |
| `rl:<bucket>:<hash>` | string | request counter per client IP (buckets `create`, `read`, `mcp`, with sign-in `auth`, `all` and `oauth`); the IP is stored only as a truncated HMAC-SHA256 with `RATE_LIMIT_KEY` | `RATE_LIMIT_WINDOW` |
| `rl:tok:<hash>` | string | calls of one API token (`API_TOKEN_RATE_LIMIT`) | `RATE_LIMIT_WINDOW` |
| `tok:<id>` | hash | an API token: `h` (HMAC-SHA256 of the token with a key derived from `AUTH_SECRET`, never the token), `own`/`nm` (owner address and name; `svc:<name>` for a technical user), `svc` (the technical user), `ids` (the owner's recipient hashes, renewed at each sign-in), `name`, `created`, `expires`, `ips`, `scopes`, `v` (`2`; without it `status` also means `burn`), `aud` (`mcp`: a token from `MCP_OAUTH`, valid only at `/mcp`; empty: everywhere), `used`, `revoked`, `by` | until 30 days after expiry or revocation; without expiry kept |
| `tokpol:<hash>` | hash | token permissions of a user or group (`API_TOKEN_ADMIN_POLICY`): `type`, `subject` (address or group), `scopes`, `max`, `by`, `at`, `v` (as for `tok:<id>`); the hash is the recipient hash of the address or group | kept |
| `tokpol:all` | set | the hashes of all token permissions | kept |
| `svc:<name>` | hash | a technical user: `name`, `desc`, `resp` (responsible address), `ips` (default networks), `on`, `max`, `created`, `by`, `updated` | kept |
| `svc:all` | set | the names of all technical users | kept |
| `luser:<address>` | hash | a local account (`AUTH_PROVIDER=local`): `user`, `name`, `pw` (`scrypt$N$r$p$salt$hash`, never the password), `role` (`admin`/`user`), `groups` (one per line), `off`, `created`, `updated`, `sv` (session version: a new password or disabling changes it and ends the sessions) | kept |
| `luser:all` | set | the addresses of all local accounts | kept |
| `rl:login:<hash>` | string | failed sign-ins of a local account in this window (HMAC of the address, `LOCAL_LOGIN_ATTEMPTS`) | the window |
| `tok:u:<hash>`, `tok:all` | set | token ids of a user (HMAC of the address) and of all users | as long as the tokens |
| `audit` | stream | `AUDIT_LOG_REDIS`: field `e`, the audit event as written | kept (`AUDIT_LOG_REDIS_MAXLEN` trims) |
| `audit:head:<instance>` | string | `{"seq":n,"hash":"..."}`: the chain head of an instance, to continue after a restart | kept |

A view is taken by one Lua script (`EXISTS`, verifier compare with
`HINCRBY attempts` and `DEL` at the limit, `HINCRBY views -1`, `DEL` at zero,
receipt update), so parallel requests cannot read a one-view secret twice or
guess more often than `PASSPHRASE_ATTEMPTS`.

## Audit log

`AUDIT_LOG=true` (settings: [CONFIG.md](CONFIG.md#audit-log-audit_log-audit_comment)).
One JSON object per event, one per line (`AUDIT_LOG_PRETTY=true`: indented),
in UTF-8, keys in a fixed order, empty values left out, times in ISO 8601
UTC with milliseconds.

### Events

| Type | When | Outcome |
|---|---|---|
| `system.startup`, `system.shutdown` | start (with the settings that shape the log), stop | success |
| `audit.checkpoint` | every `AUDIT_LOG_CHECKPOINT` events: `details.head_seq`, `head_hash` | success |
| `secret.created` | a secret was stored: creator, recipients (addresses, groups), responsible, comment, `details` (`encrypted` browser/server, `ttl_s`, `expires`, `max_views`, `passphrase` yes/no, `restricted`, `size` bucket) | success |
| `secret.revealed` | a view was handed out (`details.via` browser/server, `views_left`) | success |
| `secret.reveal_denied` | `login_required`, `not_recipient`, `bad_passphrase` (`attempts_left`), `not_found` | denied |
| `secret.burned` | `reason`: `manual` (status page), `admin` (an admin, `details.admin`; `ADMIN_BURN`) or `passphrase_attempts` | success |
| `secret.burn_denied`, `receipt.viewed`, `receipt.denied` | the status page | success / denied |
| `auth.login`, `auth.logout`, `auth.failed` | sign-in; with `AUTH_PROVIDER=local` `auth.failed` has `reason` `bad_credentials`, `disabled`, `locked` or `wrong_password` (and `details.user` only when the account exists) | success / denied |
| `auth.password_changed` | a local account changed its own password | success |
| `admin.user_created`, `admin.user_changed` (old, new), `admin.user_disabled`, `admin.user_enabled`, `admin.user_password_reset`, `admin.user_deleted` | local accounts (`AUTH_PROVIDER=local`); the first admin as `admin.user_created` by `system` with `reason` `bootstrap`. Never a password | success |
| `api.token_created`, `api.token_revoked`, `api.token_create_denied` | the API token page (`details.token` id and name, `expires`, `networks`, `scopes`); denied with `reason` `not_enabled` (API_TOKEN_USERS/GROUPS) or `limit_reached` (`details.active`, `details.max`); a token an MCP client got by signing in (`MCP_OAUTH`) has `details.via` `oauth` and `details.client` (its name), with the person as actor | success / denied |
| `api.token_used` | every call with a token, with `http.response.status_code` and the error `reason` | success / denied / error |
| `api.token_audience_denied` | a token bound to `/mcp` (`MCP_OAUTH`) used on the API; `details.audience` | denied |
| `mcp.tool_called` | every MCP `tools/call`: `details.tool`, `scope`, `method`, `request_id`, `protocol_version`, `client` (name, version from `clientInfo`); `reason` on refusals (`unknown_tool`, `invalid_arguments`, `invalid_receipt`, `insufficient_scope`, `confirmation_declined`, `confirmation_unavailable`, the API's error code), route `/mcp`; with `CONFIRM_CHECKBOX` `details.confirmation` `requested` (with `details.warned`: whether the question warned about access data; not which, nothing of the content) or `accepted`. The API call it makes has its own events | success / denied / error |
| `mcp.request`, `mcp.request_denied` | any other MCP method (`initialize`, `server/discover`, `tools/list`, ...); refused messages with `reason` `origin_not_allowed`, `header_mismatch`, `unsupported_protocol_version`, `invalid_params`, `invalid_request`, `invalid_request_id` and the HTTP status; `mcp.request` with `reason` `unknown_method` | success / denied |
| `api.token_denied`, `api.token_expired`, `api.ip_denied` | refused token (`reason`: unknown, revoked, malformed; expired; other address, with the allowed networks) | denied |
| `api.scope_denied` | a token call outside its scopes; `reason` `not_granted` (the token lacks it) or `policy` (the owner's policy took it away), `details.scope` | denied |
| `admin.token_policy_changed`, `admin.token_policy_deleted` | token permissions of a user or group (`details.subject_type`, `subject`, `old`, `new`) | success |
| `api.denied`, `api.request_denied` | `API_TOKEN_REQUIRED` without a token; any other 401/403/429 of the API | denied |
| `admin.audit_viewed`, `admin.audit_exported`, `admin.audit_verified`, `admin.secrets_viewed`, `admin.tokens_listed`, `admin.token_revoked`, `admin.denied` | the admin interface and API | success / denied |
| `admin.service_created`, `admin.service_changed` (old, new), `admin.service_deleted`, `admin.service_token_issued`, `admin.service_token_rotated` | technical users | success |

Not logged: a secret that expires unopened (Redis drops it; its receipt
shows `expired`).

### Formats

| Content | `ecs` (default) | `otel` | `plain` |
|---|---|---|---|
| time | `@timestamp` | `Timestamp`, `ObservedTimestamp` | `ts` |
| event | `event.action`, `event.id`, `event.category`, `event.type`, `event.outcome` (success/failure), `event.reason`, `vanishly.event.outcome` (success/denied/error) | `Attributes["event.name"]` = `vanishly.<type>`, `vanishly.event.*` | `type`, `id`, `outcome`, `reason` |
| level | `log.level` (info, warn, error) | `SeverityText`, `SeverityNumber` (9, 13, 17) | from `outcome` |
| text | `message` | `Body` | `message` |
| actor | `user.id`/`user.name`/`user.email` (address), `user.full_name`, `vanishly.actor.type`, `.token`, `.on_behalf_of`, `labels.token_name` | `user.*`, `vanishly.actor.*` | `actor` |
| for whom | `vanishly.recipients`, `vanishly.responsible`, `related.user` | `vanishly.recipients.*` | `recipients`, `responsible` |
| secret | `vanishly.secret.ref`, `.receipt_ref` (HMACs) | `vanishly.secret.*` | `secret` |
| request | `source.ip`, `user_agent.original`, `http.request.method`, `http.request.id` (run id), `url.path` (route, no ids), `http.response.status_code`, `trace.id`, `labels.run_id` | `client.address`, `user_agent.original`, `http.request.method`, `http.route`, `http.response.status_code`, `TraceId`, `SpanId`, `vanishly.run_id` | `source`, `http`, `run_id`, `trace_id` |
| service | `service.name`, `.version`, `.node.name` | `Resource["service.*"]` | `service` |
| chain | `vanishly.audit.{schema,seq,instance,prev_hash,hash,sig}` | `Attributes["vanishly.audit.*"]` | `audit.*` |

The OTLP exporter (`AUDIT_LOG_OTLP_URL`) sends the same events as OTLP/JSON
`resourceLogs` (attributes flattened, `traceId` from `traceparent`); syslog
(`AUDIT_LOG_SYSLOG`) as RFC 5424 with the event JSON as message, MSGID the
event type; the webhook the event (Splunk: `{"time", "host", "source",
"sourcetype": "_json", "event"}`).

### Hash chain and verify

```
hash = SHA-256( canonical JSON of the event without hash and sig )   # keys sorted, no spaces
sig  = HMAC-SHA256( AUDIT_LOG_HMAC_KEY, hash )                         # optional
prev_hash of the first event of an instance = 64 × "0", seq = 1
```

```sh
npm run audit:verify -- /var/log/vanishly/audit.jsonl [--key-file key] [--json] [--expect-head vanishly-0=<hash>]
# /var/log/vanishly/audit.jsonl: OK - 1532 events, signatures checked
#   instance vanishly-0: seq 1..1532 (1532 events, 1532 signed), head 3c1e...
```

Exit 0: intact; 1: changed, missing, inserted or moved events (line and
reason listed); 2: usage or read error. The check works for every format
and for files with several instances. The admin page runs the same check
("Check the hash chain") on `AUDIT_LOG_FILE`.

What it proves and what not: without the HMAC key an attacker with write
access could rewrite the whole file from the changed event on; with
`AUDIT_LOG_HMAC_KEY` (kept away from where the log is stored) that fails
the signature check. Removing events at the end is only visible against a
copy elsewhere (stdout shipping, syslog, OTLP, Redis, a checkpoint) and
`--expect-head`.

## API tokens and admin API

| Endpoint | Who | What |
|---|---|---|
| `GET /api/v1/tokens` | session | own tokens, `active` (how many count against the limit), the choices (lifetimes, scopes, IP binding, `maxPerUser`), `yourIp` |
| `POST /api/v1/tokens` | session | `{name, expires, ips, scopes}` → `201 {token, ...}` (token shown once) |
| `POST /api/v1/tokens/{id}/revoke` | session | revoke an own token |
| `GET /api/v1/admin/tokens`, `POST /api/v1/admin/tokens/{id}/revoke` | admin session | all tokens |
| `GET/POST /api/v1/admin/token-policies` | admin session | token permissions per user and group (`API_TOKEN_ADMIN_POLICY`) |
| `GET /api/v1/admin/audit?type=&outcome=&actor=&recipient=&runId=&q=&from=&to=&limit=&format=json\|csv\|jsonl` | admin session | the audit log, newest first; CSV cells that start with `= + - @` are prefixed with `'` |
| `GET /api/v1/admin/audit/verify` | admin session | the chain check of `AUDIT_LOG_FILE` |

A token never manages tokens. Calls with a token:
`Authorization: Bearer vnly_<id>_<secret>`; optional headers `X-Run-Id`
(or `X-Request-Id`), `X-Audit-Comment` (UTF-8 percent-encoded or ASCII),
`X-On-Behalf-Of`, `traceparent`.

## Admin API

Every admin function is also an API (`/api/v1/admin/...`, in
[openapi.json](../openapi/openapi.json), tag `admin`). Callers: a signed-in
admin (session), or a technical user's token with the scope `admin`
(`API_ADMIN_TOKENS=true`; from its networks, with `X-Audit-Comment` unless
`API_ADMIN_COMMENT=optional`). Personal tokens, technical users without
`admin` and other sessions get `403` on every admin route (logged as
`api.scope_denied`). Every call is in the audit log with the admin or the
technical user and token, the comment and the run id.

| Endpoint | What |
|---|---|
| `GET /admin/status` | what is on, Redis persistence, warnings |
| `GET /admin/audit`, `GET /admin/audit/verify` | audit log (filter, `format=csv\|jsonl`), chain check |
| `GET /admin/secrets?creator=&recipient=&status=&from=&to=&limit=` | secrets overview from the audit stream (metadata only; `AUDIT_LOG_REDIS`) |
| `POST /admin/secrets/{ref}/burn` | burn a secret by its `ref` from the overview (`ADMIN_BURN`, `ENABLE_BURN`): `200 {state: "burned"}`, `409 gone` (already opened, expired or burned), `404` unknown |
| `GET /admin/tokens`, `POST /admin/tokens/{id}/revoke` | all tokens |
| `GET /admin/users`, `POST /admin/users` | `AUTH_PROVIDER=local`: the accounts (no hashes), `me` (the caller's own address), `minPasswordLength`; create `{user, password, name, role, groups, disabled}` |
| `POST /admin/users/{user}`, `POST /admin/users/{user}/password`, `POST /admin/users/{user}/delete` | change `{name, role, groups, disabled}` (disabling ends the sessions and revokes the tokens), reset the password `{password}`, delete; `409 last_admin` for the last active admin, `409 self` for your own account |
| `GET /admin/service-accounts`, `POST /admin/service-accounts` | technical users; create `{name, description, responsible, ips, enabled, max}` |
| `POST /admin/service-accounts/{name}`, `POST /admin/service-accounts/{name}/delete` | change (also `enabled: false`: revokes its tokens), delete |
| `GET/POST /admin/service-accounts/{name}/tokens` | its tokens; issue `{name, scopes, expires, ips}` (scopes `create`, `read`, `status`, `burn`, `admin`) |
| `POST /admin/service-accounts/{name}/tokens/{id}/rotate` | new token with the same settings; `graceSeconds` (0 to 604800) keeps the old one that long |
| `GET/POST /admin/token-policies` | token permissions per user and group |

```sh
curl -s https://ots.example.com/api/v1/admin/secrets?status=opened \
  -H "Authorization: Bearer vnly_..." -H "X-Audit-Comment: weekly review" -H "X-Run-Id: review-42"
```
