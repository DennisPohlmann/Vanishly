# Security policy

Vanishly holds other people's secrets, so a security problem is taken
seriously and fixed first. How a secret is protected, and the limits of
that protection, is described in [docs/SECURITY.md](../docs/SECURITY.md).

## Supported versions

| Version | Supported |
|---|---|
| latest release (`latest`, newest `<major>.<minor>`) | yes |
| `edge` (current `main`) | yes, fixes land here first |
| older releases | no, please update |

Fixes are released as a new patch or minor version; there are no
backports. The Helm chart has the same version as the app.

## Reporting a vulnerability

Please **do not open a public issue, discussion or pull request** for a
vulnerability.

Report it privately on GitHub: **Security** tab of the repository,
**Report a vulnerability**
([direct link](https://github.com/DennisPohlmann/Vanishly/security/advisories/new)).

Helpful to include:

- the affected version or image tag, and how Vanishly runs (Compose,
  Helm, tar.gz) with the settings that matter (`AUTH_PROVIDER`,
  `AUDIT_LOG`, `API_TOKENS`, ...);
- the steps to reproduce, and what an attacker gains;
- whether you plan to publish it, and when.

Never include a real secret link, key, passphrase, API token, session
cookie or a production audit log; made-up values from a local test
instance are enough.

## What happens next

- You get an answer within **7 days**.
- The problem is confirmed or explained, and a fix is planned together
  with you. The aim is a fixed release within **90 days**, much sooner for
  a problem that exposes secrets.
- The advisory is published with the fixed release, with credit to you
  unless you prefer not to be named.

## In scope

Everything in this repository: the server, the browser code (encryption,
pages), the API, sign-in and recipient checks, the audit log, API tokens,
the container image, the Helm chart and the Compose examples. Especially
anything that lets the server, Redis, a log or a third party learn a key
or a plaintext, opens a secret more often than allowed, skips the
recipient or passphrase check, or breaks the audit hash chain unnoticed.

Out of scope: the demo users and passwords of `docker-compose/keycloak`
(made for local trying only), problems that need a changed server or
browser, and findings of scanners without a way to exploit them in
Vanishly (those are welcome as a normal issue).
