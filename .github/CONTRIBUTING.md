# Contributing to Vanishly

Thank you for helping. Bug reports, ideas, translations, templates,
documentation and code are all welcome.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## Reporting

- **Security problem:** never as an issue; see the
  [security policy](SECURITY.md).
- **Bug, idea, accessibility problem:** open an
  [issue](https://github.com/DennisPohlmann/Vanishly/issues/new/choose)
  with the matching form. Search the open issues first.
- Never paste a real secret link, key, passphrase, API token, IP address
  or audit log entry into an issue; replace them with made-up values.

## Changing code

1. Fork the repository and make a branch from `main`.
2. Set up and run it locally as in
   [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md#local-setup).
3. Make the change, with tests (`tests/`, `node:test`).
4. Run the checks:

   ```bash
   npm run lint
   npm test                 # needs Redis: REDIS_URL or a redis-server in PATH
   npm run test:a11y        # for changes of pages, CSS, templates or texts
   ```

   For a changed Helm chart also `helm lint --strict charts/vanishly` and
   `helm unittest charts/vanishly`.
5. Open a pull request against `main` and fill in the template. CI runs the
   same checks plus CodeQL and Trivy.

## Rules the code keeps

`CLAUDE.md` lists the invariants in full. The most important ones:

- The server never gets the key or the plaintext. Nothing sends, logs or
  stores `location.hash`.
- A view is only taken by the Lua script in `src/store.js`; a `GET` of
  `/s/:id` takes no view.
- Logs never contain secret ids, IPs, user agents, keys or secrets (the
  optional audit log is the one exception for IPs and user agents).
- No inline scripts or styles (Content Security Policy); template output
  stays escaped.
- The crypto format is versioned; a change needs a new version and keeps
  decrypting the old one.
- Accessibility: WCAG 2.2 AA, checked by `npm run test:a11y`
  ([docs/ACCESSIBILITY.md](../docs/ACCESSIBILITY.md)).

## Documentation and API

A change of behaviour updates the documentation in the same pull request:
settings in [docs/CONFIG.md](../docs/CONFIG.md) and `.env.example`, the API
in `openapi/openapi.json` and [docs/INTERFACE.md](../docs/INTERFACE.md). A
new setting also gets a key in the Helm chart's `values.yaml` `config`
block and `values.schema.json`; regenerate the chart README with
`helm-docs`. Texts go into `translations/en.json` and `translations/de.json`.

A new dependency needs a reason, a compatible license and an entry in
`THIRD-PARTY-LICENSES.md`.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), because
releases are made from them by semantic-release:

| Type | Effect |
|---|---|
| `feat:` | new minor version |
| `fix:`, `perf:` | new patch version |
| `feat!:` or `BREAKING CHANGE:` | new major version |
| `docs:`, `test:`, `chore:`, `ci:`, `refactor:`, `style:` | no release |

Never change `VERSION`, `CHANGELOG.md` or the version in `package.json`
by hand; the release pipeline does that.

## License

Contributions are released under the project's [license](../LICENSE).
