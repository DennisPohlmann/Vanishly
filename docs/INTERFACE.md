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
`404`; `GET /api/v1/config` lists them under `features`. Errors look like
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
| `GET /api/v1/receipts/{id}` | status for the sender |
| `POST /api/v1/receipts/{id}/burn` | destroy the secret now |
| `GET /api/v1/me` | who is signed in (sign-in on; `ENABLE_ME_API`) |
| `GET /api/v1/groups?q=` | search groups for recipients (`RECIPIENT_GROUPS=*`) |
| `GET /api/v1/people?q=` | search people for recipients (`RECIPIENT_USER_GROUP`): `{ people: [{ name, user, mail }] }`, put `user` into `recipients` |

Pages of the sign-in (not part of the API): `GET /auth/login?return=/s/<id>`,
`GET /auth/callback` (the provider's redirect), `POST /auth/logout`.

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

# Status and burn with the receipt id from the answer
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
| `r:<rid>` | hash | `sid`, `created`, `expires`, `maxViews`, `viewsLeft`, `state`, `pass`, `burned`, `rc` (number of recipients) | expiry + `RECEIPT_KEEP` |
| `r:<rid>:v` | list | view times (ms); with `RECEIPT_SHOW_VIEWER` `time<TAB>name` of the signed-in viewer | like the receipt |
| `sess:<hash>` | hash | a sign-in: `name`, `user`, `ids` (the recipient hashes of the user's addresses and groups), `created`; the key is the SHA-256 of the cookie | `AUTH_SESSION_TTL` |
| `oidc:<state>` | hash | a sign-in in progress: PKCE verifier, nonce, return path | 10 minutes, used once |
| `rl:<bucket>:<hash>` | string | request counter; the IP is stored only as a truncated SHA-256 | `RATE_LIMIT_WINDOW` |

A view is taken by one Lua script (`EXISTS`, `HINCRBY views -1`, `DEL` at
zero, receipt update), so parallel requests cannot read a one-view secret
twice.
