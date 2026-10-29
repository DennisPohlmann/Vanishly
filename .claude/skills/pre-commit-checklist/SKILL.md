---
name: pre-commit-checklist
description: Mandatory checklist before EVERY commit in Vanishly: README/docs check, Conventional Commit message, dependency/toolchain update check (suggest only), third-party license check. Use before every git commit, together with security-check and security-privacy-audit.
---

# Pre-commit checklist (Vanishly)

Run this before every commit, also for small fixes, together with the
`security-check` and `security-privacy-audit` skills. Scope is the diff that
goes into the commit (`git status --short`, `git diff HEAD`). Do the steps,
then commit; in the answer report one line per step (done / nothing to do /
suggestion).

## 1. README.md and docs/

- Read the parts of `README.md`, `docs/*.md` (INSTALLATION, CONFIG, USAGE,
  INTERFACE, DEVELOPMENT), `templates/README.md` and
  `openapi/openapi.json` that the diff touches: features, settings,
  defaults, endpoints, commands, paths, examples.
- Update them in the same commit when behaviour, a setting, a default, an
  endpoint or a requirement changed. A new setting gets a row in
  `docs/CONFIG.md` and a line in `.env.example`; a new or changed endpoint
  is changed in `openapi/openapi.json` (the tests check the paths).
- Fix wrong statements and dead links you notice on the way.

## 2. Commit message (Conventional Commits)

`CHANGELOG.md`, `VERSION`, the version in `package.json` and the tags are
written by semantic-release in CI. Never edit them by hand, never tag.

- Format: `<type>(<optional scope>): <summary>`, English, imperative, lower
  case, no full stop, at most ~72 characters. Body: what changed for users
  and what they have to do.
- Types: `feat` (minor release), `fix` and `perf` (patch release),
  `refactor`, `docs`, `test`, `build`, `ci`, `chore` (no release). Security
  fixes are `fix(security): ...`.
- Breaking change: `feat!:` / `fix!:` or a `BREAKING CHANGE: <what to do>`
  footer (major release). A change of the crypto format v1, the API or a
  setting's meaning is breaking.
- One logical change per commit.
- Say in the answer which type you chose and whether it triggers a release;
  a `feat` or `fix` on `main` needs the `release-security-gate` skill and
  Dennis' go before the push.

## 3. Dependencies and toolchain: check, suggest, do not update on your own

- `npm outdated`, `npm audit --omit=dev` (after `npm ci`).
- Node.js: compare `engines.node` in `package.json`, the Node version in
  `.github/workflows/build.yml` and the `Dockerfile` base image with the
  current Node LTS. Redis: the image in `docker-compose/standalone/docker-compose.yml`
  and `docker-compose/keycloak/docker-compose.yml`; Keycloak there too.
- GitHub Actions in `.github/workflows/*.yml`: note newer major versions.
- Report available updates as a short list (name, current → newest,
  patch/minor/major, advisories) and recommend. Do not change versions
  without Dennis' OK unless the commit is about that update or a security
  advisory forces it. Without network access say that the check was not
  possible.

## 4. Licenses of third-party code

- `THIRD-PARTY-LICENSES.md` lists every production npm package
  (`npm ls --omit=dev --all`) grouped by license, plus the base images and
  Redis; keep it in step with `package-lock.json`.
- A new third-party component (library, copied code, font, icon, image)
  needs, in the same commit: name, version, SPDX license, URL, use, and the
  license text where the license requires it.
- Compatible with GPL-3.0-or-later: MIT, BSD, ISC, Apache-2.0, MPL-2.0,
  LGPL, GPL-2.0-or-later, GPL-3.0. GPL-2.0-only, AGPL, SSPL,
  "non-commercial" or unknown licenses inside the app: stop and ask Dennis.
  (Redis runs as a separate service and is not part of the app.)
- Code taken over from other projects keeps its copyright header and is
  credited where its license requires it.

## 5. Security and privacy audit

- Run the `security-privacy-audit` skill over the working tree, the staged
  diff (`git diff --cached`), touched docs and the commit message.
- Use `gitleaks protect --staged` if gitleaks is installed; otherwise say so
  and rely on the targeted searches.
- A `BLOCKED` finding stops the commit. Report only category and location.
- End the answer with the audit summary from that skill.
