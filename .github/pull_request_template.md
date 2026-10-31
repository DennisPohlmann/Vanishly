## What and why

<!-- What does this change, and which issue does it close (Closes #123)? -->

## How it was tested

<!-- Tests added or changed, manual steps. -->

- [ ] `npm run lint` and `npm test` pass
- [ ] `npm run test:a11y` passes (pages, CSS, templates or texts changed)
- [ ] Helm chart checked (`helm lint --strict`, `helm unittest`), if changed

## Checklist

- [ ] The title is a [Conventional Commit](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, ...)
- [ ] Documentation, `openapi/openapi.json` and translations are updated
- [ ] A new setting is in `docs/CONFIG.md`, `.env.example`, the chart `values.yaml` and `values.schema.json`
- [ ] New dependencies are in `THIRD-PARTY-LICENSES.md`
- [ ] The [invariants](https://github.com/DennisPohlmann/Vanishly/blob/main/CLAUDE.md#invariants-that-must-not-break) still hold: no key or plaintext reaches the server, no ids, IPs or secrets in logs
- [ ] No real secrets, links, tokens, IP addresses or personal data in code, tests, screenshots or this description
