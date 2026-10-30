# Configuration

All settings are environment variables. `docker-compose/standalone/docker-compose.yml` lists every
one with its default under `environment:` (change it there, or put
`NAME=value` into `.env` next to it); `.env.example` lists them too, with a
comment each, and is the template for `/etc/vanishly/vanishly.env`
(systemd). An empty value means the default.

**Checked at start:** a value that is not valid (`PORT=abc`, `HSTS=maybe`,
`DEFAULT_LANG=fr`, an unknown template, contradicting settings) or a name a
letter or two off a real one (`ENABLE_VEIWS`) stops Vanishly with exit code
78 and a message naming the variable, e.g.
`Vanishly: invalid setting: ENABLE_VEIWS: unknown setting, did you mean ENABLE_VIEWS?`.
The container then does not come up (`docker compose logs vanishly`).

| Variable | Default | Meaning |
|---|---|---|
| `BASE_URL` | (from the request) | Public address, e.g. `https://ots.example.com`; used for the links that `POST /api/v1/share` returns |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection, any host: with password `redis://:change-me@host:6379`, with an ACL user `redis://app:change-me@host:6379`, database 2 `redis://host:6379/2`, TLS `rediss://host:6380` (certificate checked against the system CAs) |
| `REDIS_URL_FILE` | (none) | File with the URL (first line) instead of `REDIS_URL`, e.g. a Docker secret, so the password is not in the environment |
| `REDIS_TLS_CA_FILE` | (none) | PEM file of an own CA for `rediss://` (e.g. a company CA); the certificate is always checked |
| `REDIS_PREFIX` | `vanishly:` | Prefix of all keys, to share one Redis with other apps |
| `HOST` | `0.0.0.0` | Listen address (`127.0.0.1` in the systemd unit) |
| `PORT` | `3000` | Listen port |
| `TRUST_PROXY` | `false` | Reverse proxies in front: a number of hops (`1`), `loopback`, or address ranges; needed for correct client IPs in the rate limits |
| `HSTS` | `false` | Send `Strict-Transport-Security` (only if served via HTTPS) |
| `TEMPLATE` | `default` | Design template, see [templates/README.md](../templates/README.md) |
| `DEFAULT_MODE` | (the template's `defaultMode`, usually `auto`) | Light or dark at the first visit: `auto` (the visitor's system setting), `light` or `dark`. A visitor's own choice with the button wins (unless `ENABLE_THEME_TOGGLE=false`) |
| `TEMPLATES_DIR` | `/var/lib/vanishly/templates` | Folder with own templates; searched before the built-in `templates/` |
| `LANGUAGES` | (all translations: `en,de`) | Languages served, comma-separated. Only these count for `?lang=`, the `lang` cookie and `Accept-Language`. One language (`LANGUAGES=en`) serves every page in it and hides the language link. A code without a translation stops the start |
| `DEFAULT_LANG` | `en` (or the first of `LANGUAGES` without `en`) | Language when the browser names none of `LANGUAGES` (and no `?lang=` or cookie decides); must be one of `LANGUAGES` |
| `TRANSLATIONS_DIR` | `/var/lib/vanishly/translations` | Folder with own translations: `<code>.json` (e.g. `fr.json`) adds a language, `de.json` replaces single German texts; missing keys come from English. Plain JSON files (`"key": "text"`) up to 512 KB, no symbolic links |
| `TTL_OPTIONS` | (built-in steps) | Entries of the expiry dropdown, comma-separated: `15m,1h,1d,3d,7d` (`m`, `h`, `d`, `w`, or seconds; 1 minute to 1 year). Without it the form offers 5m, 1h, 1d, 3d, 7d, 14d, 30d, 90d up to `MAX_TTL` |
| `DEFAULT_TTL` | 1 day, or the option closest to it | Preselected expiry, also used by the API without `ttl`; with `TTL_OPTIONS` it must be one of them (`1d` or seconds) |
| `MAX_TTL` | `604800`, or the largest of `TTL_OPTIONS` | Longest expiry the API accepts (seconds, at most one year) |
| `MAX_VIEWS` | `10` | Most views a secret can have (1 to 100) |
| `MAX_SECRET_CHARS` | `10000` | Longest secret in characters |
| `MIN_SECRET_CHARS` | `1` | Shortest secret in characters, e.g. `12` to refuse short passwords ([details](#minimum-lengths-and-passphrase-rules)) |
| `MIN_PASSPHRASE_LENGTH` | `0` | Shortest passphrase in characters; `0` = any ([details](#minimum-lengths-and-passphrase-rules)) |
| `PASSPHRASE_COMPLEXITY` | (none) | Character classes the passphrase must contain, comma-separated: `upper`, `lower`, `digit`, `symbol`, or `all` ([details](#minimum-lengths-and-passphrase-rules)) |
| `REQUIRE_PASSPHRASE` | `false` | `true`: every secret needs a passphrase. `unless-recipients`: every secret without recipients needs one; with recipients (sign-in) it is optional. The form shows the field as required until a recipient is chosen; the API answers `passphrase_required` ("A passphrase is required when no recipients are given"). Without sign-in this means: always |
| `CONFIRM_CHECKBOX` | `false` | `true`: the sender must tick a confirmation before creating the link; the API then needs `"confirmed": true` and otherwise answers `confirmation_required` with the same text as the checkbox |
| `CONFIRM_TEXT_EN`, `CONFIRM_TEXT_DE` | (built-in text) | Own text of the confirmation per language; `CONFIRM_TEXT` sets both. Default: "I confirm that this secret contains only one password: not several passwords, no user name and no links that together give access to a whole system." |
| `PASSPHRASE_ATTEMPTS` | `5` | Wrong passphrases before the secret is destroyed |
| `GENERATOR_LENGTH` | `20` | Length of the password of the "Generate" button (8 to 128) |
| `GENERATOR_COMPLEXITY` | `all` | Character classes of the generated password: `upper`, `lower`, `digit`, `symbol` or `all`; each chosen class appears at least once. Look-alikes (0/O, 1/l/I) are left out |
| `RECEIPT_KEEP` | `604800` | How long a receipt stays after its secret expired (seconds) |
| `RATE_LIMIT_CREATE` | `30` | New secrets per client IP and window; `0` = off |
| `RATE_LIMIT_READ` | `120` | Reads, reveals, receipts and burns per client IP and window; with sign-in also `/auth/login` and `/auth/callback` (own counter). With sign-in, all requests of one client IP together (not static files, `/healthz`) may reach 10 × the larger of `RATE_LIMIT_READ` and `RATE_LIMIT_CREATE` per window. `0` = off |
| `RATE_LIMIT_WINDOW` | `600` | Window of the rate limits (seconds) |
| `ACCESS_LOG` | `true` | One line per request to stdout (method, path with ids replaced by `:id`, status, time) |

### Switches (`ENABLE_*`)

Everything is on by default; `false` (or `0`, `no`, `off`) switches it off.

| Variable | Off means |
|---|---|
| `ENABLE_API` | No public API: every API endpoint and `/api/openapi.json` answer 404, except the calls of this server's own pages; also switches off `ENABLE_API_DOCS`, `ENABLE_SHARE_API`, `ENABLE_OPEN_API` and the footer link ([details](#api-access)) |
| `ENABLE_API_DOCS` | No API reference page at `/api/docs` (`API_DOCS` is the older name) |
| `ENABLE_API_LINK` | No "API" link in the footer; the API itself stays |
| `ENABLE_SHARE_API` | `POST /api/v1/share` (server-side encryption for scripts) answers 404 |
| `ENABLE_OPEN_API` | `POST /api/v1/open` (scripts open a link with its passphrase on the server) answers 404 |
| `ENABLE_SECRET_META_API` | `GET /api/v1/secrets/{id}` (a secret's state and passphrase parameters without using a view) answers 404; the reveal page gets what it needs with the page itself |
| `ENABLE_CONFIG_API` | `GET /api/v1/config` (limits and options) answers 404; the pages do not use it |
| `ENABLE_ME_API` | `GET /api/v1/me` (who is signed in) answers 404; the pages do not use it |
| `ENABLE_CREATE_API` | `POST /api/v1/secrets` only for this server's form: scripts get 404 |
| `ENABLE_REVEAL_API` | `POST /api/v1/secrets/{id}/reveal` only for this server's reveal page: scripts get 404 |
| `ENABLE_RECEIPT_API` | `GET /api/v1/receipts/{id}` and `.../burn` only for this server's status page: scripts get 404 |
| `ENABLE_API_INDEX` | `GET /api` and `GET /api/v1` (the index) answer 404 |
| `ENABLE_PASSPHRASE` | No passphrase field; the API refuses passphrases (`passphrase_disabled`). Cannot be combined with `REQUIRE_PASSPHRASE`, `MIN_PASSPHRASE_LENGTH` or `PASSPHRASE_COMPLEXITY` |
| `ENABLE_VIEWS` | No views dropdown: every secret can be opened once (`MAX_VIEWS` becomes 1) |
| `ENABLE_RECEIPTS` | No status page for the sender: no receipt is stored, `/r/...` and the receipt endpoints answer 404, `receiptId` is `null`. Also switches off the next three |
| `ENABLE_BURN` | No "Burn now" button; the burn endpoint answers 404 |
| `ENABLE_VIEW_LOG` | The status page shows no view times, and none are stored |
| `ENABLE_RECEIPT_SHARE_LINK` | The status page does not offer the share link again, and the receipt link no longer carries the key |
| `ENABLE_GENERATOR` | No "Generate" button |
| `ENABLE_LANG_SWITCH` | No language link in the header; `?lang=` and the `lang` cookie no longer count, the browser language and `DEFAULT_LANG` still decide. To serve one language only, use `LANGUAGES` |
| `ENABLE_THEME_TOGGLE` | No light/dark button; the template's `defaultMode` or the system setting decides |
| `ENABLE_GITHUB_LINK` | No "Powered by Vanishly" link to GitHub in the footer |

**Every API endpoint and its switch.** All are on by default. A switched-off
endpoint answers `404 {"error": "endpoint_disabled", ...}` (a wrong path:
`not_found`); the answer does not name the variable. The served
`/api/openapi.json`, the API reference (`/api/docs`) and the index (`/api`)
list only the endpoints that are on. Endpoints the web pages need are, when
switched off, still answered for this server's own pages (the browser's
`Sec-Fetch-Site` header; a guard against casual use, no access control).

| Endpoint | Switch | Off |
|---|---|---|
| `GET /api`, `GET /api/v1` | `ENABLE_API_INDEX` | 404 |
| `GET /api/openapi.json`, `/api/docs` | `ENABLE_API_DOCS` (docs page), `ENABLE_API` (everything) | 404 |
| `GET /api/v1/config` | `ENABLE_CONFIG_API` | 404 |
| `POST /api/v1/secrets` | `ENABLE_CREATE_API` | 404 for scripts, the form keeps working |
| `POST /api/v1/share` | `ENABLE_SHARE_API` | 404 |
| `GET /api/v1/secrets/{id}` | `ENABLE_SECRET_META_API` | 404 (the reveal page does not need it) |
| `POST /api/v1/secrets/{id}/reveal` | `ENABLE_REVEAL_API` | 404 for scripts, the reveal page keeps working |
| `POST /api/v1/open` | `ENABLE_OPEN_API` | 404 |
| `GET /api/v1/receipts/{id}` | `ENABLE_RECEIPT_API` (`ENABLE_RECEIPTS` also removes the status page) | 404 for scripts, the status page keeps working |
| `POST /api/v1/receipts/{id}/burn` | `ENABLE_RECEIPT_API`, `ENABLE_BURN` | as above; `ENABLE_BURN=false` removes it for all |
| `GET /api/v1/me` | `ENABLE_ME_API` (only with sign-in) | 404 |
| `GET /api/v1/groups` | `RECIPIENT_GROUPS=*` (only then) | 404 |
| `GET /api/v1/people` | `RECIPIENT_USER_GROUP` (only then) | 404 |

**Create and reveal only.** To offer nothing but creating a secret and
revealing it, in the form and for scripts:

```bash
ENABLE_SHARE_API=false        # no server-side encryption for scripts
ENABLE_OPEN_API=false         # no server-side reveal for scripts
ENABLE_SECRET_META_API=false  # no state lookup of a secret
ENABLE_CONFIG_API=false       # no limits and options
ENABLE_ME_API=false           # no "who is signed in"
ENABLE_RECEIPT_API=false      # status page only in the browser
ENABLE_API_INDEX=false        # no index under /api
```

For the web form only, without any scripts, also set
`ENABLE_CREATE_API=false` and `ENABLE_REVEAL_API=false`, or `ENABLE_API=false`
for the whole API.

### Sign-in and recipients (`AUTH_*`, `ENTRA_*`, `OIDC_*`, `DIRECTORY_*`, `RECIPIENT*`)

Off by default (`AUTH_PROVIDER=none`): no login anywhere, and setting any
of the others then stops the start. With a provider, senders sign in and
can name the people who may open a secret; see
[Sign-in and recipients](#sign-in-and-recipients) below. Setup per
provider (app registration, groups claim, directory access, the settings
only that provider has) and what each supports:
[providers/README.md](providers/README.md).

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_PROVIDER` | `none` | `none`, `entra` (Microsoft Entra ID), a preset (`keycloak`, `okta`, `auth0`, `google`, `ping`, `jumpcloud`, `cognito`) or `oidc` (any other OpenID Connect provider). The presets use the `OIDC_*` settings and know the provider's issuer format, groups claim and directory ([providers](providers/README.md)). Needs `BASE_URL`: the redirect URI is `<BASE_URL>/auth/callback` |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` (`_FILE`), `ENTRA_AUTHORITY`, `ENTRA_GRAPH`, `ENTRA_GRAPH_URL` | | `entra` only: tenant, app registration, national clouds, Microsoft Graph for the group and people search ([entra.md](providers/entra.md#settings)) |
| `OIDC_ISSUER` | (required for `oidc` and the presets) | Issuer URL, e.g. `https://sso.example.com/realms/main`; its `/.well-known/openid-configuration` must be reachable. Auth0 and JumpCloud keep their trailing `/` |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | (required for `oidc` and the presets) | The confidential client; `OIDC_CLIENT_SECRET_FILE` instead of the secret |
| `OIDC_SCOPES` | `openid profile email` | Scopes to ask for (must include `openid`); add the scope that puts the groups into the ID token if your provider needs one |
| `OIDC_GROUPS_CLAIM` | `groups` (`cognito:groups` for `cognito`, none for `auth0` and `google`) | The ID token claim with the user's groups, e.g. a namespaced claim of an Auth0 Action |
| `AUTH_ALLOWED_DOMAINS` | (any) | Only accounts with an address of these domains sign in, e.g. `example.com`. Required for `google` (also checks the Workspace domain, `hd`) |
| `DIRECTORY_API` | `false` | `true`: use the provider's directory for the people search, the group search and (Google) the groups of a user. Presets only; Entra uses `ENTRA_GRAPH`. Access per provider: [providers](providers/README.md) |
| `DIRECTORY_CLIENT_ID`, `DIRECTORY_CLIENT_SECRET` | the sign-in client | `keycloak`, `auth0`, `ping`: a client of its own for the directory (service account, machine-to-machine app, worker); `DIRECTORY_CLIENT_SECRET_FILE` instead of the secret |
| `DIRECTORY_API_TOKEN` (`_FILE`), `DIRECTORY_GOOGLE_CREDENTIALS_FILE`, `DIRECTORY_GOOGLE_ADMIN`, `AWS_*` | | The directory access of `okta` and `jumpcloud` (API token), `google` (service account) and `cognito` (AWS credentials); see their pages in [providers](providers/README.md) |
| `DIRECTORY_URL` | from the issuer | The directory API's address, where it differs (Auth0 with a custom domain, JumpCloud EU, an internal Keycloak admin address) |
| `AUTH_SECRET` | (required) | At least 32 random characters (`openssl rand -base64 48`); or `AUTH_SECRET_FILE`. Keys the hashes of the recipients: changing it locks every open restricted secret |
| `AUTH_SESSION_TTL` | `28800` | Lifetime of a sign-in in seconds (5 minutes to 7 days) |
| `AUTH_LOGOUT` | `provider` (Entra: `local`) | `provider`: "Sign out" also ends the session at the provider, which then asks again at the next sign-in; needs `<BASE_URL>/auth/logged-out` as post logout redirect URI there. `local`: only Vanishly signs out (with Entra the default, as the Microsoft session is shared with Microsoft 365) |
| `AUTH_AUTO_LOGIN` | `false` | `true`: a visitor who is not signed in is signed in automatically when the provider still knows them (silent sign-in, `prompt=none`, once per browser tab); otherwise the page stays as it is. A sign-out in that tab is not undone |
| `AUTH_CREATE` | `signed-in` | Who may create secrets: `signed-in` or `anyone` (restricting a secret always needs a sign-in) |
| `RECIPIENTS` | `optional` | `off` (no recipients field), `optional`, or `required` (every secret must name someone) |
| `RECIPIENTS_MAX` | `10` | Most recipients (addresses and groups) per secret, 1 to 50 |
| `RECIPIENT_GROUPS` | (none) | Groups a sender may pick: `Name=<id>,...` (Entra: the group's object id; otherwise the value in the groups claim), or `*` for a search over all groups in the directory (Entra with `ENTRA_GRAPH=true`; `keycloak`, `okta`, `google`, `cognito` with `DIRECTORY_API=true`) |
| `RECIPIENT_USER_GROUP` | (none) | People search in the form: the group whose members the form suggests while typing a name (Entra: object id; Keycloak: path or id; Okta, PingOne, JumpCloud: group id; Auth0: role id; Google: group address; Cognito: group name). Needs `ENTRA_GRAPH=true` or `DIRECTORY_API=true` ([details](#people-search)) |
| `RECIPIENT_DOMAINS` | (any) | Allowed e-mail domains of recipients, e.g. `example.com,example.de` |
| `AUTH_API_AUDIENCE` | (none) | Accept bearer tokens on the API with this audience, e.g. `api://<client id>` ([details](#api-with-sign-in)) |
| `RECEIPT_SHOW_VIEWER` | `false` | `true`: the status page shows the name and address of the signed-in person who opened the secret (stored with the view time) |
| `RESPONSIBLE` | `off` | People or groups who look after a secret: `off`, `optional` or `required` (every secret must name one). In the form a folded "Responsible" section with the same picker as the recipients; on the API `responsible` and `responsibleGroups`. Checked like recipients, stored as keyed hashes |
| `STATUS_ACCESS` | `signed-in` with sign-in, else `link` | Who may see the status page: `link` (whoever has the status link, as before) or `signed-in` (the creator, the responsible people and who opened the secret, after sign-in; only creator and responsible may burn it). See [Status page](#status-page) |

### Audit log (`AUDIT_LOG*`, `AUDIT_COMMENT*`)

Off by default (nothing changes for existing setups). Details, event list
and format: [Audit log](#audit-log) below and
[INTERFACE.md](INTERFACE.md#audit-log); shipping to Loki, Elastic, Splunk
or an OpenTelemetry Collector: [INSTALLATION.md](INSTALLATION.md#11-audit-log-shipping).

| Variable | Default | Meaning |
|---|---|---|
| `AUDIT_LOG` | `false` | `true`: write an audit event for every action (who, what, when, for whom, comment, run id, source address), tamper-evident (hash chain). Works with and without sign-in |
| `AUDIT_LOG_FORMAT` | `ecs` | `ecs` (Elastic Common Schema: `@timestamp`, `event.action`, `user.name`, `source.ip`, `trace.id`, ...), `otel` (OpenTelemetry log data model: `Timestamp`, `SeverityText`, `Body`, `Attributes` with semantic conventions) or `plain` (Vanishly's own, short keys) |
| `AUDIT_LOG_PRETTY` | `false` | `true`: pretty-printed JSON over several lines (for development; log shippers want one event per line). The verify command reads both |
| `AUDIT_LOG_FILE` | (none) | Append-only file, one event per line, e.g. `/var/log/vanishly/audit.jsonl` (created with mode 0640). The chain continues there after a restart |
| `AUDIT_LOG_FSYNC` | `true` | Flush every event to disk before the action goes on |
| `AUDIT_LOG_STDOUT` | `true` when no file and no Redis, else `false` | Events on stdout too (Kubernetes / Docker log shipping) |
| `AUDIT_LOG_REDIS` | `false` | Also into the Redis stream `<prefix>audit`; feeds the admin view across all replicas |
| `AUDIT_LOG_REDIS_MAXLEN` | `0` | Keep about this many events in the stream (`0`: all; nothing is ever deleted unless set) |
| `AUDIT_LOG_HMAC_KEY` (`_FILE`) | (none) | At least 32 characters: every event also gets an HMAC signature (`sig`), so a changed log cannot be re-chained without the key. Also keys the secret references and IP hashes (else `AUTH_SECRET`, else a random key per start) |
| `AUDIT_LOG_FAIL` | `closed` | `closed`: an action whose event cannot be written (file, Redis) is refused or undone (503 `audit_unavailable`; a new secret is deleted again, a secret is not handed out, a sign-in is not completed). `open`: go on, report on stderr |
| `AUDIT_LOG_IP` | `full` | Source address in events: `full`, `hash` (HMAC) or `off` |
| `AUDIT_LOG_USER_AGENT` | `true` | Browser / client name in events |
| `AUDIT_LOG_INSTANCE` | (host name) | Name of this instance in the chain (one chain per instance); set a stable one per replica (StatefulSet name, systemd host) so a restart continues the same chain |
| `AUDIT_LOG_CHECKPOINT` | `100` | Every n events an `audit.checkpoint` event with the current head hash, an anchor in the external copies (`0`: off) |
| `AUDIT_LOG_SYSLOG` | (none) | Forward to syslog (RFC 5424, facility authpriv): `udp://host:514`, `tcp://host:514` or `tls://host:6514`; best effort with retries |
| `AUDIT_LOG_SYSLOG_CA_FILE` | (system CAs) | PEM file of the CA for `tls://` |
| `AUDIT_LOG_OTLP_URL` | (none) | Send to an OTLP/HTTP logs endpoint (JSON), e.g. `http://otel-collector:4318/v1/logs` |
| `AUDIT_LOG_OTLP_HEADERS` (`_FILE`) | (none) | Extra headers, `name=value,name=value` (e.g. `authorization=Bearer change-me`) |
| `AUDIT_LOG_WEBHOOK_URL` | (none) | POST every event as JSON to this address |
| `AUDIT_LOG_WEBHOOK_AUTH` (`_FILE`) | (none) | `Authorization` header of the webhook, e.g. `Bearer change-me` or `Splunk change-me` |
| `AUDIT_LOG_WEBHOOK_FORMAT` | `json` | `json` (the event) or `splunk` (HTTP Event Collector envelope, batches) |
| `AUDIT_COMMENT` | `off` | Comment field per secret (form and API, `comment` / `X-Audit-Comment`): `off`, `optional` or `required`. Needs `AUDIT_LOG`. It goes into the audit log and onto the status page, never into the secret |
| `AUDIT_COMMENT_MAX` | `500` | Most characters of a comment (10 to 2000) |

### API tokens and admins (`API_TOKEN*`, `ADMIN_*`)

Need sign-in. See [API tokens](#api-tokens) below.

| Variable | Default | Meaning |
|---|---|---|
| `API_TOKENS` | `false` | `true`: signed-in users make personal API tokens on the page "API tokens" (user menu). A token acts as its owner, is shown once and stored only as an HMAC |
| `API_TOKEN_REQUIRED` | `false` | `true`: outside this server's own pages the API takes only these tokens: no anonymous calls, no session cookies from scripts, no other bearer tokens (`AUTH_API_AUDIENCE`) |
| `API_TOKEN_USERS`, `API_TOKEN_GROUPS` | (everyone signed in) | Only these addresses / groups (as in the groups claim; Entra: object ids) may make tokens: the "activation" by the admins |
| `API_TOKEN_IP_BINDING` | `optional` | `required`: every token must name the IP addresses or networks (IPv4/IPv6 CIDR) it works from; any other address is refused (403) and logged, which stops passing tokens on |
| `API_TOKEN_EXPIRY_OPTIONS` | `30d,60d,90d,never` | Lifetimes a user may pick: `d` days, `m` calendar months, `y` calendar years, `never` (note: `m` is months here, minutes in `TTL_OPTIONS`) |
| `API_TOKEN_DEFAULT_EXPIRY` | `90d` (or the longest choice) | Preselected lifetime; added to the choices if missing |
| `API_TOKEN_MAX_EXPIRY` | `never` (no cap) | Longest lifetime allowed, e.g. `1y`: longer choices and `never` disappear, the server refuses them |
| `API_TOKEN_MAX_PER_USER` | `10` | Active tokens per user, 0 to 1000 (`0`: no limit). Only active tokens count; revoked and expired ones do not. At the limit the API tokens page shows "10 of 10 active tokens" and a notice instead of the form, and the API refuses with `400 too_many_tokens` (logged as `api.token_create_denied`, reason `limit_reached`) |
| `API_TOKEN_RATE_LIMIT` | `0` (off) | Calls per token per `RATE_LIMIT_WINDOW` |
| `API_TOKEN_COMMENT` | `optional` | `required`: every POST with a token needs a comment (`X-Audit-Comment` or `comment`); needs `AUDIT_LOG` |
| `API_TOKEN_ALLOWED_SCOPES` | `create,read,status` | What users may give their tokens: `create` (create secrets), `read` (retrieve/open them), `status` (status page and burn), or `none`. The form then offers only "only create", "only retrieve", "both" and the status box as far as allowed |
| `API_TOKEN_DEFAULT_SCOPES` | `create,status` (within the allowed ones) | Preselected in the form and used when the API call names no `scopes`; must be within `API_TOKEN_ALLOWED_SCOPES` |
| `API_TOKEN_SCOPES_BY_GROUP` | (none) | Other scopes for the members of groups, wins over `API_TOKEN_ALLOWED_SCOPES` (several groups add up): `<group>=<scopes>;...`, e.g. `/support=read;/it=create,read,status` (Entra: object ids). For GitOps |
| `API_TOKEN_ADMIN_POLICY` | `false` | `true`: admins set the scopes and the token limit per user and per group on `/admin` ("Token permissions", stored in Redis). Order: user > group > `API_TOKEN_SCOPES_BY_GROUP` > `API_TOKEN_ALLOWED_SCOPES` / `API_TOKEN_MAX_PER_USER`. Needs `ADMIN_USERS` or `ADMIN_GROUPS` |
| `ADMIN_USERS`, `ADMIN_GROUPS` | (none) | Admins get the whole admin interface (`/admin`, "Administration" in the user menu) and the admin API. `ADMIN_GROUPS` as in the groups claim, like `RECIPIENT_GROUPS` (Keycloak: `/vanishly-admins`; Entra: the object id); see [Admin interface](#admin-interface) |
| `ADMIN_UI` | `true` | The admin interface and the admin API at all (`false`: neither) |
| `AUDIT_ADMIN_VIEW` | `true` | The "Audit log" tab; needs `AUDIT_LOG` with `AUDIT_LOG_FILE` or `AUDIT_LOG_REDIS=true` |
| `API_SERVICE_ACCOUNTS` | `true` | Technical users: API-only accounts (e.g. `api_aap`) that admins make on `/admin` and issue tokens for; they cannot sign in |
| `API_ADMIN_TOKENS` | `false` | The scope `admin` for technical users' tokens: every admin function over the API. Only a signed-in admin can give it |
| `API_ADMIN_TOKEN_REQUIRE_IP` | `true` | Admin tokens must name the IP networks they work from |
| `API_ADMIN_TOKEN_MAX_EXPIRY` | `90d` | Longest lifetime of an admin token (`d`, `m`, `y`) |
| `API_ADMIN_TOKEN_CAN_ISSUE_ADMIN` | `false` | `true`: an admin token may issue further admin tokens |
| `API_ADMIN_COMMENT` | `required` | Every admin API call with a token needs `X-Audit-Comment` (`optional`: not) |

The container sets `NODE_ENV=production`, `HOST=0.0.0.0`, `PORT=3000` and
`TEMPLATES_DIR=/var/lib/vanishly/templates`.

## Redis

Vanishly needs Redis 7 or newer (Valkey works too). Every key expires on its
own, so no cleanup job is needed.

The Compose file runs Redis **without persistence** (`--save ""
--appendonly no`): secrets never touch the disk, and a Redis restart drops
the open ones. To keep secrets across restarts, accept that the ciphertext
lands on disk and change the command to `redis-server --appendonly yes`
with a volume for `/data`. The ciphertext alone is useless without the key
in the link.

`--maxmemory-policy volatile-ttl` lets Redis drop the secrets closest to
expiry first if memory runs out; raise `--maxmemory` for heavy use.

**External Redis** (a managed service, a shared cluster): point `REDIS_URL`
(or `REDIS_URL_FILE`) at it, e.g.
`rediss://app:change-me@redis.example.com:6380/0`, with `REDIS_TLS_CA_FILE`
for an own CA and `REDIS_PREFIX` to share it with other apps. With Docker
Compose, remove the `redis` service and the `depends_on: [redis]` line of
`vanishly` from your copy of `docker-compose/standalone/docker-compose.yml` and set `REDIS_URL` in
`.env`. With Helm: `redis.enabled=false` and `redis.external.url` or
`redis.external.existingSecret` (see the chart README). The Redis user needs
the commands `GET`, `SET`, `HSET`, `HGETALL`, `HMGET`, `EXPIRE`/`PEXPIREAT`,
`DEL`, `EVAL`/`EVALSHA` (the view script) and `PING` on keys with the prefix;
`+@all ~vanishly:*` is the simple ACL.

## Outgoing proxy

With sign-in, Vanishly calls the provider (discovery, token, keys) and,
with a directory, its API. Behind an outgoing HTTP(S) proxy set the
standard variables; Node.js uses them only with `NODE_USE_ENV_PROXY=1`:

```sh
NODE_USE_ENV_PROXY=1
HTTPS_PROXY=http://proxy.example.com:3128
HTTP_PROXY=http://proxy.example.com:3128
NO_PROXY=localhost,127.0.0.1,redis
```

Compose passes them from `.env`; with Helm put them into `extraEnv`. Redis
is reached directly (not through the proxy). A reverse proxy in front of
Vanishly is a different matter: `TRUST_PROXY` and `BASE_URL`, see
[INSTALLATION.md](INSTALLATION.md).

## Minimum lengths and passphrase rules

`MIN_SECRET_CHARS`, `MIN_PASSPHRASE_LENGTH`, `PASSPHRASE_COMPLEXITY` and
`REQUIRE_PASSPHRASE` show on the form ("At least 12 characters. Must contain
an upper-case letter, a digit.", "Passphrase (required)") and the browser
refuses input that breaks them, with a message. The classes are
Unicode-aware (`Ä` counts as upper case); a space is not a symbol.

The server enforces them as far as it can see the data:

- `POST /api/v1/share` (plaintext from scripts): all rules.
- `POST /api/v1/secrets` (encrypted in the browser): the secret length is
  judged from the size of the ciphertext (UTF-8 bytes; a secret with enough
  characters is never refused, a very short one with many multi-byte
  characters can pass), a missing passphrase is refused with
  `REQUIRE_PASSPHRASE`. The passphrase length and complexity cannot be checked: the
  passphrase never leaves the browser, which is the point of the end-to-end
  encryption.

## API access

- **Default:** the API is open like the web form; whoever can reach the
  site can create secrets with it, from a browser or a script.
- **`ENABLE_API=false`:** the API answers only the pages of this server.

The server recognises its own pages by the
`Sec-Fetch-Site: same-origin` header that browsers send. A script can fake
it, so `ENABLE_API=false` keeps honest scripts and casual
users out, but it does not lock the site: anyone who can open the form can
create secrets with it. To limit who may create secrets, use the built-in
[sign-in](#sign-in-and-recipients) (`AUTH_PROVIDER`), or put a login in
front of `/` and `/api/v1/secrets` in the reverse proxy (or keep the site in
your VPN) and leave `/s/`, `/api/v1/secrets/{id}` and the static files open
for the recipients.

## Sign-in and recipients

With any `AUTH_PROVIDER`:

- **Senders** sign in with the "Sign in" link (`AUTH_CREATE=signed-in`, the
  default), then see the field "Only for these people". They add e-mail
  addresses (the user name, UPN or e-mail of the account) and, with
  `RECIPIENT_GROUPS`, groups. Without anybody listed, the secret works as
  before: anyone with the link.
- **Recipients** of a restricted secret see "Sign in to show it". After the
  sign-in they come back to the same link (the key after `#` is kept in
  the browser tab meanwhile) and can open it if one of their addresses or
  groups is on the list. Anybody else gets "not shared with your account"
  and the API answers `401 login_required` or `403 not_recipient`; neither
  uses a view or a passphrase attempt.
- The key stays in the link: the server still cannot read a secret, the
  sign-in is a second lock on top.
- The server compares the addresses case-insensitively with names the
  account cannot pick itself: the verified `email` (Entra: the sign-in
  name). A sign-in without such an address is refused. The groups come
  from the groups claim of the ID token or, for Google, from the
  directory. What each provider sends and how to set it up:
  [providers](providers/README.md).
- `AUTH_ALLOWED_DOMAINS` limits who may sign in at all, by the domain of
  the address (Google: and the Workspace domain).
- With `RECIPIENT_GROUPS=*` the form offers a search over the groups of
  the directory, and every signed-in sender can see the group names.
- With `RECIPIENT_USER_GROUP` the address field also searches people, see
  [People search](#people-search).
- Redis stores the recipients only as keyed hashes (HMAC with
  `AUTH_SECRET`), the sessions under a hash of the cookie, with the name,
  the user name and these hashes, with `AUTH_LOGOUT=provider` also the ID
  token (for the sign-out at the provider). No access or refresh tokens are kept.
- **Sign out** ends the session in Vanishly and, with `AUTH_LOGOUT=provider`,
  at the provider (OpenID Connect RP-initiated logout), so the next sign-in
  asks for the account again. Register `<BASE_URL>/auth/logged-out` as post
  logout redirect URI at the provider. "Sign in with another account" always
  asks the provider again (`prompt=login`; Entra and Google: the account
  picker). Providers without a logout endpoint (Google, Cognito,
  JumpCloud): there only Vanishly signs out.
- **Automatic sign-in** (`AUTH_AUTO_LOGIN=true`): on the first page in a
  browser tab the page asks the provider without showing anything
  (`prompt=none`). Whoever is signed in there (e.g. in Microsoft 365 or the
  company Keycloak) is signed in to Vanishly and lands on the same page, a
  secret link keeps its key; everybody else sees the page as before and
  can use "Sign in".
- While nobody is signed in and creating needs a sign-in
  (`AUTH_CREATE=signed-in`), the header shows no "New secret" link.

### People search

With `RECIPIENT_USER_GROUP` and a directory (Entra with `ENTRA_GRAPH=true`,
a preset with `DIRECTORY_API=true`) the field "Name or e-mail address"
suggests people while the sender types (from 2 letters on): the members of
that group whose name, e-mail or user name starts with the text. Arrow
keys and Enter or a click add a person; several people can be added, and a
full e-mail address still works. A group with the whole company makes the
whole company searchable.

- The person is added with the address they sign in with, so it matches
  their sign-in.
- At most 10 hits per search, only for signed-in users; nothing goes to
  Redis ([how the search works](providers/README.md#how-the-search-works)).
- The directory access is read-only and differs per provider: see
  [providers](providers/README.md).
- Privacy: every signed-in sender can look up names and addresses of that
  group's members. Pick a group that may be visible to all senders.
- The API keeps taking e-mail addresses in `recipients`; the search
  (`GET /api/v1/people?q=`) is meant for the form.
- Generic `oidc` has no people search; senders type the address.

### Status page

With `STATUS_ACCESS=link` (without sign-in the only choice) the status link
is the key: whoever has it sees the state and may burn the secret.

With `STATUS_ACCESS=signed-in` (the default when sign-in is on) the status
page asks for a sign-in and shows the status only to:

| Who | Sees the status | May burn |
|---|---|---|
| the creator (the signed-in sender) | yes | yes |
| the responsible people and groups (`RESPONSIBLE`) | yes | yes |
| who opened the secret (signed in) | yes | no |
| anybody else | no (`403 not_allowed`) | no |
| not signed in | no (`401 login_required`, the page shows "Sign in") | no |

The page then also shows who created it, who is responsible and, with
`RECEIPT_SHOW_VIEWER=true`, the name and address of each person who opened
it, as a history. These names and addresses are kept with the receipt
(until `RECEIPT_KEEP` ends), the access rules as keyed hashes. A secret
created without a sign-in (`AUTH_CREATE=anyone`) and without responsible
people, or before this setting existed, keeps the link access.

**Our case: only named people open it, named people look after it.**

```bash
AUTH_PROVIDER=entra            # or keycloak, oidc, ...
RECIPIENTS=required            # every secret names who may open it
RESPONSIBLE=required           # and who looks after it
STATUS_ACCESS=signed-in        # status only for creator, responsible, openers
RECEIPT_SHOW_VIEWER=true       # show who opened it, with name and address
# The API only creates and reveals; the pages keep working:
ENABLE_SHARE_API=false
ENABLE_OPEN_API=false
ENABLE_SECRET_META_API=false
ENABLE_CONFIG_API=false
ENABLE_ME_API=false
ENABLE_API_INDEX=false
```

### API with sign-in

Pages use the session cookie. For scripts, set `AUTH_API_AUDIENCE`: the API
then accepts an access token of your provider as `Authorization: Bearer
<token>`, checked against the provider's keys, issuer, audience, expiry
and (Entra) tenant. Per provider: [Entra](providers/entra.md#api-tokens)
(expose an API, `api://<client id>`), [Cognito](providers/cognito.md#api-tokens)
(no audience: the app client id). A token for a user can create restricted secrets and open those meant for
that user; a token of an app (client credentials) can create secrets, but
has no user and so cannot open restricted ones. Without
`AUTH_API_AUDIENCE`, scripts can only create secrets with
`AUTH_CREATE=anyone` and cannot open restricted ones.

## Audit log

`AUDIT_LOG=true` writes one JSON event per action, for example (format
`plain`, pretty-printed; the default `ecs` carries the same content under
ECS names):

```json
{
  "ts": "2026-10-29T21:40:12.418Z",
  "id": "4f0a8f0e-6f52-4b8e-9a8a-1d3c9f0b7a21",
  "type": "secret.created",
  "outcome": "success",
  "actor": { "type": "api_token", "user": "alice@example.com", "name": "Alice Example", "token": { "id": "3f9c0d2a7b1e4c55", "name": "api_aap" } },
  "secret": { "ref": "qL1o0b8c2mJm9wKQe1xXrA", "receipt_ref": "Jx8h1d0a0uQyW3n5cV2pTg" },
  "recipients": { "users": ["bob@example.com"] },
  "details": { "encrypted": "server", "ttl_s": 3600, "expires": "2026-10-29T22:40:12.418Z", "max_views": 1, "passphrase": false, "restricted": true, "size": "<=64B" },
  "comment": "reset a user pw",
  "run_id": "run-4711",
  "source": { "ip": "203.0.113.10", "user_agent": "curl/8.5.0" },
  "http": { "method": "POST", "route": "/api/v1/share" },
  "service": { "name": "vanishly", "version": "1.3.0" },
  "message": "secret.created success by alice@example.com via token api_aap for bob@example.com",
  "audit": { "schema": 1, "seq": 42, "instance": "vanishly-0", "prev_hash": "9b1f...", "hash": "c07a...", "sig": "5e2d..." }
}
```

- **Never in the log:** the secret, its ciphertext, key, passphrase,
  verifier, the URL fragment, a full API token, or a secret/receipt id.
  Secrets are referred to by `ref`, an HMAC of the id: the `secret.created`
  and the later `secret.revealed` of the same secret carry the same `ref`.
- **Tamper evidence:** each event holds its place in the chain of its
  instance (`seq`, `prev_hash`) and `hash` = SHA-256 over the event in
  canonical JSON (keys sorted) without `hash` and `sig`; with
  `AUDIT_LOG_HMAC_KEY` also `sig` = HMAC-SHA256 of the hash. `npm run
  audit:verify -- <file>` (or `node src/audit-verify.js`, in the image
  `docker compose exec vanishly node src/audit-verify.js /path`) reports any
  changed, removed, added or moved event. A cut-off end is found with the
  external copies (checkpoints) and `--expect-head <instance>=<hash>`.
- **Fail closed:** with `AUDIT_LOG_FAIL=closed` (the default) nothing
  happens without its event: see the table above.
- **Run id:** callers send `X-Run-Id` (or `X-Request-Id`); it is in every
  event of the call and comes back in both headers. A W3C `traceparent`
  gives the trace id (`trace.id` / `TraceId`).
- **Several replicas:** each instance keeps its own chain
  (`AUDIT_LOG_INSTANCE`); one file per replica, or the Redis stream /
  stdout for all. A new instance name starts a new chain.
- **Retention:** Vanishly deletes no audit events (unless
  `AUDIT_LOG_REDIS_MAXLEN` trims the Redis stream). Rotate the file with
  `logrotate` (`copytruncate`; the writes continue in the emptied file, so
  it starts mid-chain: verify the rotated files together in order, e.g.
  `cat audit.jsonl.2 audit.jsonl.1 audit.jsonl | node src/audit-verify.js /dev/stdin`)
  and keep them as your rules require; the events hold personal data
  (names, addresses, IPs).

```sh
AUDIT_LOG=true
AUDIT_LOG_FILE=/var/log/vanishly/audit.jsonl
AUDIT_LOG_REDIS=true                      # admin view across replicas
AUDIT_LOG_HMAC_KEY_FILE=/run/secrets/audit_hmac_key
AUDIT_COMMENT=required
ADMIN_GROUPS=/vanishly-admins
```

## API tokens

With `API_TOKENS=true` every signed-in user (or only `API_TOKEN_USERS` /
`API_TOKEN_GROUPS`) opens "API tokens" in the user menu and makes a token:
name (e.g. `api_aap`), lifetime, allowed addresses, scopes (create secrets,
open secrets, status and burn). The token (`vnly_<id>_<secret>`) is shown
once; Redis keeps only an HMAC of it. The list shows each token with its
expiry, last use, addresses and state; a click revokes it. A user may have
`API_TOKEN_MAX_PER_USER` active tokens (default 10; revoked and expired ones
do not count); the page shows how many are in use.

**What a token may do** is chosen per token: "only create" (secrets),
"only retrieve" (open/pull secrets), "both", plus "status and burn". Which
of these a user may pick: `API_TOKEN_ALLOWED_SCOPES` for everyone,
`API_TOKEN_SCOPES_BY_GROUP` per group, and with `API_TOKEN_ADMIN_POLICY=true`
per user or group on `/admin` (also the token limit), in this order: user,
group (several add up), `API_TOKEN_SCOPES_BY_GROUP`, the defaults. The
policy of today counts at every call: when an admin takes a scope away,
existing tokens lose it at once (the list marks it "no longer allowed",
calls get `403 insufficient_scope` and `api.scope_denied`); "Also revoke
existing tokens" revokes them instead. Every change is logged
(`admin.token_policy_changed` / `_deleted` with old and new). Admins see and
revoke all tokens on `/admin`.

```sh
curl -s -X POST https://ots.example.com/api/v1/share \
  -H "Authorization: Bearer vnly_..." \
  -H "X-Run-Id: run-4711" -H "X-Audit-Comment: reset a user pw" \
  -H "Content-Type: application/json" \
  -d '{"secret":"s3cret","ttl":3600,"recipients":["bob@example.com"]}'
```

- The audit log shows the owner as actor, with the token's name and id
  (`actor.type: api_token`), the comment, the run id and the address; every
  call also as `api.token_used` with its answer.
- Refused and logged: an unknown or revoked token (`api.token_denied`), an
  expired one (`api.token_expired`), a call from another address
  (`api.ip_denied`, 403 `ip_not_allowed`), a missing scope
  (`insufficient_scope`).
- Strict setup: `API_TOKEN_REQUIRED=true`, `API_TOKEN_GROUPS=<api group>`,
  `API_TOKEN_IP_BINDING=required`, `API_TOKEN_MAX_EXPIRY=1y`,
  `API_TOKEN_COMMENT=required`. Behind a reverse proxy set `TRUST_PROXY`
  right, or the proxy's address is checked instead of the caller's.
- A token picks up the owner's groups at each sign-in of the owner.

## Admin interface

Admins (`ADMIN_USERS`, or members of `ADMIN_GROUPS`) find "Administration"
in the user menu (`/admin`), with tabs:

| Tab | What | Needs |
|---|---|---|
| Audit log | filter, export (CSV, JSON lines), hash chain check | `AUDIT_LOG` with a file or `AUDIT_LOG_REDIS` |
| Secrets | every secret with creator, recipients, comment, expiry, state (not opened, opened, expired, burned) and who opened it when and how (web page, API, token); never content or keys | `AUDIT_LOG_REDIS=true` |
| API tokens | all tokens of all users and technical users: owner, scopes, created, last used, expiry, networks, state; revoke | `API_TOKENS` |
| Technical users | API-only accounts: create, change, disable, delete (revokes their tokens); issue, rotate (with a grace period) and revoke their tokens | `API_SERVICE_ACCOUNTS` |
| Token permissions | scopes and token limit per user and group | `API_TOKEN_ADMIN_POLICY` |

Everything there is in the audit log with the admin's name, and also
available over the API (`/api/v1/admin/...`, [INTERFACE.md](INTERFACE.md#admin-api)).

**Admin group with Keycloak:** put the admins into a group (e.g.
`vanishly-admins`), make sure the client's groups mapper puts it into the
`groups` claim (as for `RECIPIENT_GROUPS`), and set
`ADMIN_GROUPS=/vanishly-admins` (a name without path counts with `/` in
front). Members are admins from their next sign-in.

**Redis must keep its data.** The secrets tab, the tokens, technical users
and token permissions live in Redis. Without persistence they are gone
after a Redis restart; `/admin` then shows a warning. Use Redis with an
append-only file (`--appendonly yes`) or snapshots: an external Redis, the
Compose file with a volume, or the Helm chart's `redis.persistence.enabled`.
Note that the (encrypted) secrets are then on disk too.

**Admin tokens** (`API_ADMIN_TOKENS=true`): a signed-in admin issues a
technical user a token with the scope `admin` (bound to networks, at most
90 days by default). It can do every admin function over the API, each
call with `X-Audit-Comment`; it cannot issue further admin tokens
(`API_ADMIN_TOKEN_CAN_ISSUE_ADMIN`). Personal tokens never get `admin`.

## Languages

English and German are built in (`translations/en.json`,
`translations/de.json`). Which one a visitor gets:

1. the link in the header (`?lang=de`, remembered in the `lang` cookie),
   while the language link is on (`ENABLE_LANG_SWITCH`, more than one
   language);
2. otherwise the browser (`Accept-Language`): German for a German browser,
   English for every other one;
3. otherwise `DEFAULT_LANG` (`en`).

Only the languages in `LANGUAGES` are served (default: all translations).
`LANGUAGES=en` makes every page English: `?lang=`, the cookie and the
browser are ignored and the language link disappears.

Own translations go into `TRANSLATIONS_DIR` (with Docker Compose a mounted
folder, e.g. `./custom-translations:/var/lib/vanishly/translations:ro`):
`fr.json` adds French, `de.json` replaces single German texts. Each file is
a JSON object of texts with the keys of `translations/en.json`; missing keys
come from English, `lang.name` is the name shown in the language link. The
files are checked at start (plain files up to 512 KB, valid JSON, a
language code as name); an error stops the start. A template can still
override single texts per language in its `template.json` (`strings`).
