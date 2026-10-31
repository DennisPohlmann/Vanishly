# Vanishly documentation

| Topic | File | What is in it |
|---|---|---|
| Installation | [INSTALLATION.md](INSTALLATION.md) | Compose, container, tar.gz with systemd, Helm, reverse proxy, own templates, update, troubleshooting, removal, sign-in in three steps, shipping the audit log (Loki, Elastic, Splunk, OpenTelemetry, syslog) |
| Configuration | [CONFIG.md](CONFIG.md) | every setting with its default; Redis, passphrase rules, API access, sign-in, recipients, responsible people, status page, audit log, API tokens, languages |
| Usage | [USAGE.md](USAGE.md) | the pages (also API tokens and the audit log page), how sharing works, the status page, health and monitoring |
| Interface and API | [INTERFACE.md](INTERFACE.md) | REST API with examples, crypto format v1, Redis keys, audit events and formats, hash chain and `audit:verify`, token API; the contract is [openapi.json](../openapi/openapi.json), the reference is served at `/api/docs` |
| Security | [SECURITY.md](SECURITY.md) | how a secret is protected: encryption in the browser, what Redis stores, passphrase, sign-in, status access, audit log and API tokens, limits |
| Accessibility | [ACCESSIBILITY.md](ACCESSIBILITY.md) | accessibility statement: WCAG 2.2 AA target, what the pages do, how it is checked, known limits, feedback |
| Development | [DEVELOPMENT.md](DEVELOPMENT.md) | local development, tests, CI, security checks, releases |
| Templates | [templates/README.md](../templates/README.md) | own designs: logo, CSS, pictures, views |
| Translations | [CONFIG.md](CONFIG.md#languages) | languages, browser detection, own translations (`TRANSLATIONS_DIR`, [translations/](../translations/en.json)) |
| Helm | [charts/vanishly/README.md](../charts/vanishly/README.md) | the chart: install from ghcr.io, all values, Redis, own templates |
| Compose examples | [docker-compose/standalone](../docker-compose/standalone/docker-compose.yml), [docker-compose/keycloak](../docker-compose/keycloak/README.md) | Vanishly with Redis; a local demo with Keycloak sign-in, groups and people search |
| Sign-in providers | [providers/README.md](providers/README.md) | what each provider supports, and one page each: [none](providers/none.md), [Entra ID](providers/entra.md), [Keycloak](providers/keycloak.md), [Okta](providers/okta.md), [Auth0](providers/auth0.md), [Google](providers/google.md), [PingOne](providers/ping.md), [JumpCloud](providers/jumpcloud.md), [Cognito](providers/cognito.md), [other OIDC](providers/oidc.md) |
| Screenshots | [screenshots/](screenshots/) | the pages in the built-in templates |

Also in the repository root: [README.md](../README.md) (overview, quick
start), [CHANGELOG.md](../CHANGELOG.md), [THIRD-PARTY-LICENSES.md](../THIRD-PARTY-LICENSES.md). In `.github/`:
[CONTRIBUTING.md](../.github/CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](../.github/CODE_OF_CONDUCT.md),
[SECURITY.md](../.github/SECURITY.md) (how to report a vulnerability),
issue forms and the pull request template.
