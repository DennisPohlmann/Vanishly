---
name: release-security-gate
description: Full security pass over Vanishly before release-relevant commits are pushed to main (semantic-release then bumps, tags and releases). Use whenever a release is being prepared; ends with a go/no-go report and never tags or pushes on its own.
---

# Release security gate (Vanishly)

Run all steps over the whole repository, not only the last diff. Report a
table with the 14 points of `security-check` (ok / finding / n.a.) and a
go/no-go.

Releases are made by semantic-release in CI: every push to `main` with a
`feat`, `fix` or breaking-change commit bumps the version, writes
`CHANGELOG.md`, tags `vX.Y.Z`, publishes the GitHub release with the tar.gz
and the container image. So this gate runs **before pushing release-relevant
commits to `main`**, without asking first. Never tag by hand, never edit the
version files or `CHANGELOG.md`, do not push to `main` yourself: report the
result and the version semantic-release will make (`feat` → minor, `fix` →
patch, `!`/`BREAKING CHANGE` → major), then ask Dennis for the go.

## Steps

1. **Clean tree and version:** `git status` is clean; `VERSION`,
   `package.json` and the top `CHANGELOG.md` entry agree with the latest
   tag (`git describe --tags --abbrev=0`).
2. **Checks:** `npm ci`, `npm run lint`, `npm test` (with Redis),
   `npx --yes @redocly/cli@<version from build.yml> lint --extends=minimal openapi/openapi.json`.
3. **Secrets in the whole history:** `gitleaks detect --source . --log-opts="--all"`
   (or `trufflehog git file://. --only-verified`); without them
   `git log -p --all | grep -nEi '(password|secret|token|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]' | grep -v change-me`.
4. **Dependencies:** `npm audit --omit=dev` and `npm outdated`; report each
   advisory with package, severity and fixed version.
5. **Route inventory:** list every route in `src/app.js` and compare with
   `openapi/openapi.json`; each one validates its input and is rate-limited
   where it touches Redis.
6. **Attack the running app** (`make up` or
   `npm start` with a local Redis):
   - reveal the same one-view secret from two clients at once → one wins;
   - wrong passphrase `PASSPHRASE_ATTEMPTS` times → burned, no view used
     before;
   - `/s/../x`, `/s/<23 chars>`, `/api/v1/secrets/%00/reveal`, huge JSON,
     invalid JSON → 404/400/413, no stack trace;
   - rate limit with changing `X-Forwarded-For` while `TRUST_PROXY=false` →
     still limited;
   - response headers: CSP, `no-store`, `no-referrer`, no `X-Powered-By`;
   - a link preview (GET of `/s/:id` only) does not burn the secret;
   - access log shows `:id` instead of ids, no IPs.
7. **Packaging and image:** every `FROM` and the Redis image pinned by
   digest; `.env.example` only placeholders; build and scan as CI does
   (`docker build -t vanishly:gate .`, `trivy config --severity HIGH,CRITICAL --exit-code 1 .`,
   `trivy image --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 vanishly:gate`).
   A fixable HIGH or CRITICAL is a no-go unless `.trivyignore` lists it with
   a reason and an unexpired date; also report open issues labelled
   `security` and open code-scanning alerts.
8. **The 14 points:** go through the `security-check` list for the whole
   code base, with extra attention on `git log --oneline <last-tag>..HEAD`.
9. **Security and privacy audit:** the `security-privacy-audit` skill over
   the whole repository, the commits since the last release and the
   `CHANGELOG.md` entry semantic-release will write. Any `BLOCKED` is a
   no-go.
10. **Report:** go/no-go, the audit summary, findings with file:line and fix,
    the version semantic-release will make, then ask Dennis for the go.
