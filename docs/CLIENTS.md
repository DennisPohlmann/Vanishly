# Clients

Vanishly has a command line client and client libraries. All of them
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
| Command line (Go) | binaries for 14 platforms | `<your server>/downloads` or the GitHub release | [clients/go/cmd/vanishly](../clients/go/cmd/vanishly) |
| Python 3.9+ | `vanishly` (PyPI), with the command line tool | `pip install vanishly` | [clients/python](../clients/python) |
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

## Command line

The command line client `vanishly` is a single binary without
dependencies (Go, [download](#download-page)):

```bash
export VANISHLY_URL=https://ots.example.com   # or --url
export VANISHLY_TOKEN=vnly_...                # with sign-in, or --token

printf '%s' 's3cret' | vanishly share --ttl 3600 --views 1   # prints the link
vanishly share --passphrase-file pw.txt --recipient alice@example.com < secret.txt
vanishly open 'https://ots.example.com/s/<id>#<key>'
vanishly status 'https://ots.example.com/r/<receipt id>#<key>'
vanishly burn   'https://ots.example.com/r/<receipt id>#<key>'
vanishly meta <id>            # state without using a view
vanishly config               # limits and options of the server
vanishly me                   # who is signed in
vanishly downloads            # the clients the server offers, with checksums
vanishly api GET /v1/me/secrets --query limit=10
vanishly api POST /v1/tokens --data '{"name":"ci","scopes":["create"]}'
vanishly --json share ...     # the whole answer as JSON
vanishly help
```

The Python package (`pip install vanishly`) installs the same `vanishly` command.

The secret comes from the argument or, without one (or `-`), from
standard input; an argument is visible in the process list and the shell
history. The passphrase: `--ask` (asked without echo), `--passphrase-file
FILE`, the environment variable `VANISHLY_PASSPHRASE`, or `--passphrase`
(visible in the process list). `--server-side` uses `/api/v1/share` and
`/api/v1/open` instead. The status link goes to standard error, the
secret link to standard output. Exit codes: `0` done, `1` refused or
failed, `2` wrong usage.

## Download page

`<BASE_URL>/downloads` lists the binaries in the image's `/app/downloads`
(`ENABLE_DOWNLOADS`, on by default), each with its size and five checksums:
SHA-256, SHA-512, SHA3-256, SHA3-512 and BLAKE2b-512 (MD5 and SHA-1 are
broken and left out). The checksum files are next to them in the format of
`sha256sum`: `SHA256SUMS`, `SHA512SUMS`, `SHA3-256SUMS`, `SHA3-512SUMS`,
`B2SUMS`. `GET /api/v1/downloads` gives the same as JSON
([INTERFACE.md](INTERFACE.md#rest-api)).

| File | Platform |
|---|---|
| `vanishly-linux-amd64`, `-386`, `-arm64`, `-armv7`, `-armv6` | Linux x86-64, x86 (32-bit), ARM64, ARMv7, ARMv6 (Raspberry Pi 1/Zero) |
| `vanishly-windows-amd64.exe`, `-386.exe`, `-arm64.exe` | Windows x86-64, x86 (32-bit), ARM64 |
| `vanishly-macos-amd64`, `-arm64` | macOS Intel, Apple silicon |
| `vanishly-freebsd-amd64`, `-386`, `-arm64`, `-armv7` | FreeBSD x86-64, x86 (32-bit), ARM64, ARMv7 |

The binaries are not signed for Windows (Authenticode) or notarized for
macOS: Windows SmartScreen may warn, and macOS needs
`xattr -d com.apple.quarantine vanishly-macos-arm64` (or right-click, Open)
the first time.

## Checking a binary

A checksum from the same server only shows that the download is complete.
That it is the genuine binary built from this repository shows the
signature, which does not depend on the server:

- **Reproducible build.** The binaries are built with
  `clients/go/build.sh` (`CGO_ENABLED=0`, `-trimpath`, no build id, no VCS
  stamp), in the Dockerfile's stage `clients` with a fixed Go image. The
  same source, version and Go release give the same bytes, so the binary
  in the image has the checksum of the one in the GitHub release; the
  release run checks this for every file.
- **Sigstore.** The release run signs every binary and checksum file
  keyless with [cosign](https://docs.sigstore.dev): the signature
  (`<file>.sigstore.json` in the GitHub release) is bound to this
  repository's workflow `build.yml` and logged in the public transparency
  log Rekor.
- **GitHub artifact attestations.** The release run also records a
  build provenance (SLSA) for every file.

```bash
# The checksums (from the server or the release):
sha256sum -c --ignore-missing SHA256SUMS
b2sum -c --ignore-missing B2SUMS

# Built by this repository's GitHub Actions (needs the GitHub CLI):
gh attestation verify vanishly-linux-amd64 --repo DennisPohlmann/vanishly

# Or with cosign and the bundle from the GitHub release:
cosign verify-blob vanishly-linux-amd64 \
  --bundle vanishly-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/DennisPohlmann/vanishly/\.github/workflows/build\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Both work for a binary from any server, as long as it has not been
changed: verify the file you downloaded, not the server.

The tar.gz archive has no binaries. `make clients` (needs Go) builds them
into `downloads/`; copy that folder to `/opt/vanishly/downloads`, or the
signed ones from the GitHub release. Without them the page says so and the
footer link is hidden.

## Client versions

Every client sends `X-Vanishly-Client: <name>/<version>`, e.g.
`cli/3.2.0` or `go/3.2.0`. The server can then
([CONFIG.md](CONFIG.md#client-versions)):

- recommend a newer one (`CLIENT_RECOMMENDED_VERSION`): the request works,
  the answer has `X-Vanishly-Client-Recommended`, the command line client
  prints `a newer client is recommended (...)` with the link to
  `/downloads` on standard error, and the libraries keep it (Go:
  `RecommendedVersion`, see the README of each package);
- refuse older ones (`CLIENT_MIN_VERSION`): `426 client_outdated` with
  `minVersion` and `downloadUrl`; the command line client prints the link.

Requests without the header (curl, own code) are not affected: this keeps
the clients current, it is no access control. The version of every client
is the version of the app.

## Development

```bash
cd clients/go && go test ./... && ./build.sh /tmp/out    # all 14 binaries
cd clients/python && pip install -e . && python -m unittest discover -s tests
```

`tools/check-all.sh` runs those whose toolchain is installed; the CI (job
`clients`) runs all of them. The server's tests check that the test
vectors and the versions are current. A release (semantic-release) sets the version
of every package with `clients/set-version.sh`, including the Go module's
major version suffix (`/v3`), and tags the Go module (`clients/go/vX.Y.Z`).

## Publishing

A release publishes the Go module (its tag) and the binaries (GitHub
release) itself.
The Python package goes to PyPI in the same run (job `pypi`).
What each registry needs:

| Registry | Once | Per release |
|---|---|---|
| PyPI | A [trusted publisher](https://docs.pypi.org/trusted-publishers/) for project `vanishly`: owner `DennisPohlmann`, repository `vanishly`, workflow `build.yml`, environment `pypi` (also create the environment `pypi` in the repository settings) | automatic: job `pypi` of the release run |
| Go | nothing | the release run pushes `clients/go/vX.Y.Z`; `proxy.golang.org` fetches it on the first `go get` |

The names are not reserved: check each before the first upload.
