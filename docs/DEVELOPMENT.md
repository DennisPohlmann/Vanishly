# Development

## Local setup

```bash
npm ci
npm run vendor                                # vendor/scalar.js for /api/docs
redis-server --save "" --appendonly no &      # or: docker run -p 6379:6379 redis:8-alpine
npm run dev                                   # node --watch, http://localhost:3000
```

Project layout:

| Path | Content |
|---|---|
| `src/server.js` | entry point |
| `src/app.js` | routes: pages, API, static files, security headers |
| `src/store.js` | Redis: secrets, receipts, rate limits |
| `src/theme.js` | templates, rendering, translations |
| `src/config.js` | environment variables |
| `src/auth.js` | optional sign-in: OpenID Connect, sessions, bearer tokens, recipients |
| `public/js/vanishly-crypto.js` | crypto format v1 (browser and server) |
| `public/js/app.js` | browser logic of the pages |
| `public/css/base.css` | layout and components (uses the template variables) |
| `views/` | default HTML views |
| `translations/` | texts, one JSON file per language (en, de); more via `TRANSLATIONS_DIR` |
| `templates/` | built-in templates (`default`, `example-brand`) |
| `openapi/openapi.json` | API contract |
| `tests/` | `node:test` tests |
| `charts/vanishly/` | Helm chart (values, schema, unit tests in `tests/`, ct values in `ci/`) |

## Checks

```bash
npm run lint    # tsc --checkJs over src, public/js, tests (jsconfig.json)
npm test        # node --test; API tests need Redis: REDIS_URL or a redis-server in PATH
npx --yes @redocly/cli@2.72.0 lint --extends=minimal openapi/openapi.json
npx playwright install chromium && npm run test:a11y   # accessibility, needs Redis too
```

Without Redis the API tests are skipped (and say so); CI always runs them
against a Redis service. The sign-in tests (`tests/auth.test.js`, and the
sign-in flow in `tests/a11y.e2e.js`) run against `tests/oidc-mock.js`, a
small stand-in for Entra ID / an OpenID provider with Microsoft Graph
(the other directories: stand-ins in `tests/directory.test.js`); no
tenant is needed. To click through the sign-in by hand, use the test login
server of `docker-compose/standalone/docker-compose.auth-test.yml`
([INSTALLATION.md](INSTALLATION.md#try-it-locally-with-a-test-login-server)).

## CI (`.github/workflows/build.yml`)

- **check:** `npm ci`, `npm run vendor`, type check, tests against a Redis service, OpenAPI
  lint; on every push, pull request, weekly schedule and manual run.
- **image-scan:** `trivy config` on the Dockerfile, builds the image and
  scans it; fixable HIGH/CRITICAL findings fail the build (`.trivyignore`
  for accepted ones, with reason and expiry).
- **release** (push to `main`): semantic-release reads the Conventional
  Commits since the last tag; `feat` → minor, `fix`/`perf` → patch, `!` or
  `BREAKING CHANGE` → major. It updates `VERSION`, `package.json`,
  `package-lock.json`, `CHANGELOG.md`, commits `chore(release): vX.Y.Z [skip
  ci]`, tags and creates the GitHub release as a draft (releases are
  immutable once published, so assets are added first).
- **package:** `make package`, uploads the tar.gz and `.sha256` as artifact
  and to the release.
- **image:** pushes `ghcr.io/dennispohlmann/vanishly` with `edge` (main),
  `<version>`, `<major>.<minor>`, `latest` (release), SBOM and provenance;
  the SPDX SBOM goes into the release.
- **publish-release:** after package and image, publishes the draft
  release.

`.github/workflows/chart.yml` checks the Helm chart when `charts/` changes
(push, pull request): `helm lint --strict` with every `ci/*-values.yaml`,
the unit tests (`helm unittest charts/vanishly`), that
`charts/vanishly/README.md` is what `helm-docs` generates from
`values.yaml`, kubeconform, `ct lint` and `ct install` in a kind cluster
with an image built from the commit (with `helm test`). For a release,
`build.yml` calls it as job **chart** after **image**: it pushes the chart
with the release version to `oci://ghcr.io/dennispohlmann/charts/vanishly`
and adds the `.tgz` to the draft release. semantic-release writes the
version into `charts/vanishly/Chart.yaml` (`version` and `appVersion`).

Chart checks locally:

```bash
helm lint --strict charts/vanishly
helm plugin install https://github.com/helm-unittest/helm-unittest.git && helm unittest charts/vanishly
helm-docs --chart-search-root charts      # after a change of values.yaml
```

## Accessibility

The web interface aims at **WCAG 2.2 level AA**, which is what BITV 2.0 and
EN 301 549 require. What the code does for it:

- Every field has a label; hints and rules are tied to their field
  (`aria-describedby`); errors are read out (`role="alert"`), mark the
  field (`aria-invalid`) and move the focus to it.
- Keyboard: everything works without a mouse, the first Tab reaches "Skip to
  content", focus is always visible. After "Create" the focus lands on the
  link, after "Show" on the secret.
- Screen readers: landmarks (header, menu, main, footer), the page language
  (and `lang` on the language link), status messages ("Copied", "Your link
  is ready") through a live region, the light/dark button reports its
  state (`aria-pressed`).
- Colours: contrast at least 4.5:1 for text and 3:1 for controls, in
  light and dark mode of every built-in template; Windows high contrast
  (`forced-colors`) keeps every control visible.
- Works at 320 px width and 400 % zoom without sideways scrolling; touch
  targets at least 24 px (most 44 px); animations only without
  `prefers-reduced-motion`.

`npm run test:a11y` (CI job `check`, step "accessibility") opens every page
and state (form, error, link ready, reveal, wrong passphrase, revealed,
status page, gone, 404) in every built-in template, light and dark, at
desktop size and at 320 px, and checks them with
[axe-core](https://github.com/dequelabs/axe-core) against WCAG 2.0 to 2.2
A/AA plus best practices, the reflow, the skip link and the focus on
errors. Automated tests find about half of all problems; a formal BITV
check also needs a person with a screen reader (NVDA, VoiceOver). The
API reference (Scalar) at `/api/docs` is a third-party page for developers and not part
of this check. Own templates: keep the contrast and check them with
`TEMPLATES_DIR=/path/to/templates A11Y_TEMPLATES=my-brand npm run test:a11y`.

## Security checks

| Check | Where | Fails the build on |
|---|---|---|
| `npm audit --omit=dev --audit-level=high` | build.yml, check | known HIGH/CRITICAL advisories in production packages |
| CodeQL, `security-extended` queries | codeql.yml (push, PR, weekly) | findings go to the Security tab |
| `trivy fs` (secrets, `package-lock.json`, misconfigurations) | build.yml, image-scan | committed secrets, fixable HIGH/CRITICAL |
| `trivy config` (Dockerfile) | build.yml, image-scan | HIGH/CRITICAL misconfigurations |
| `trivy image` (the built image) | build.yml, image-scan | fixable HIGH/CRITICAL vulnerabilities |
| `trivy image` (the Redis image of `docker-compose/standalone/docker-compose.yml`) | build.yml, image-scan | fixable HIGH/CRITICAL vulnerabilities |
| nightly `trivy image` of `latest` and `edge` | image-scan.yml | opens/updates an issue labelled `security` |
| Dependabot | dependabot.yml | PRs for npm, actions, base image, Redis image |
| `trivy fs` misconfigurations of the Helm chart, kubeconform, `ct install` | build.yml, chart.yml | HIGH/CRITICAL findings, invalid manifests, a failing `helm test` |

Accepted findings go into `.trivyignore` with a reason and an expiry date.
Both containers run without root: the app as `node` (uid 1000), Redis as
`redis` (uid 999, set with `user:` in compose, because the official image
would otherwise stay root when its capabilities are dropped), with
read-only file systems, all capabilities dropped and `no-new-privileges`.

`.github/workflows/image-scan.yml` scans `latest` and `edge` every night,
uploads SARIF to code scanning and opens/updates/closes one issue labelled
`security`. Dependabot (`.github/dependabot.yml`) updates npm packages,
actions, the Node base image and the Redis image.

The repository needs: Actions with "Read and write permissions" for
`GITHUB_TOKEN` (release commit, tags, packages), and the packages
`vanishly` and `charts/vanishly` on ghcr.io linked to the repository and
public (a new package starts private: Package settings, Change visibility).

## Releases

Never edit `VERSION`, `CHANGELOG.md` or the version in `package.json` by
hand, never tag by hand. Write Conventional Commits; the pipeline does the
rest. Before pushing `feat`/`fix` commits to `main`, run the
`release-security-gate` skill (`.claude/skills/`).

## Claude skills

`.claude/skills/` holds the project's skills:
`pre-commit-checklist`, `security-check`, `release-security-gate`,
`security-privacy-audit`. `CLAUDE.md` says when they are mandatory.
