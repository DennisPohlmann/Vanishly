# Clients

Vanishly has client libraries. All of them
encrypt and decrypt on the user's machine, like the web pages: the
secret, the key and the passphrase never reach the server (crypto format
v1, [INTERFACE.md](INTERFACE.md#crypto-format-v1)). The key is only in
the part of the link after `#`, which browsers and clients do not send.

So the clients need neither `POST /api/v1/share` nor `POST /api/v1/open`,
which are off by default because there the server sees the plaintext
([CONFIG.md](CONFIG.md#switches-enable_)). Each client can still use them
(`--server-side`, `share()`, `open_on_server()`, ...) when the server
switches them on.

| Language | Package | Install | Source |
|---|---|---|---|
| Go | `github.com/DennisPohlmann/vanishly/clients/go/v3` | `go get github.com/DennisPohlmann/vanishly/clients/go/v3` | [clients/go](../clients/go) |

The packages are prepared for these registries but are not published yet
([Publishing](#publishing)); until then, install from the source folder
(see the README of each package).

Every library has the same parts:

- `create(secret, passphrase, options)`: encrypts here and stores the
  ciphertext (`POST /api/v1/secrets`); returns the server's answer plus
  `shareUrl` (for the recipient) and `receiptUrl` (status page, with key).
  Options: `ttl`, `views`, `confirmed`, `recipients`, `recipientGroups`,
  `responsible`, `responsibleGroups`, `comment`.
- `open(link, passphrase)`: takes one view and decrypts here; returns the
  secret and `viewsLeft`. With a passphrase it first reads salt and
  iterations (`GET /api/v1/secrets/{id}`, `ENABLE_SECRET_META_API`).
- One method per endpoint of the [API](INTERFACE.md#rest-api) (receipts,
  burn, me, my secrets, groups, people, tokens, admin, audit, service
  accounts, users, downloads) and a generic `request(method, path, body,
  query)` for any other.
- The crypto alone (`encrypt_secret` / `decrypt_secret` and friends).
- An API token (`vnly_...`) as second argument, and the audit headers
  `X-Run-Id`, `X-Audit-Comment`, `X-On-Behalf-Of`.
- Errors with the API's `status`, `error` and `message`.

Each package has a README with an example. All libraries check themselves
against the same test vectors, `clients/testvectors.json`, made from the web
pages' `public/js/vanishly-crypto.js` (`node clients/testvectors.mjs`).

## Development

```bash
cd clients/go && go test ./...
```

`tools/check-all.sh` runs those whose toolchain is installed; the CI (job
`clients`) runs all of them. The server's tests check that the test
vectors and the versions are current. A release (semantic-release) sets the version
of every package with `clients/set-version.sh`, including the Go module's
major version suffix (`/v3`), and tags the Go module (`clients/go/vX.Y.Z`).

## Publishing

A release publishes the Go module (its tag) itself.
What each registry needs:

| Registry | Once | Per release |
|---|---|---|
| Go | nothing | the release run pushes `clients/go/vX.Y.Z`; `proxy.golang.org` fetches it on the first `go get` |

The names are not reserved: check each before the first upload.
