---
name: security-check
description: Security checklist for every change in Vanishly (Express, Redis, end-to-end encryption in the browser, design templates, behind a reverse proxy). Use before finishing, committing or opening a PR for any route, crypto, store, template, config or packaging change.
---

# Security check for a change (Vanishly)

Scope: the current diff (`git diff` plus staged and untracked files). Walk
the points below, only as deep as the diff reaches, and report the result.

## Steps

1. Read the diff: `git status --short`, `git diff HEAD`.
2. List new or changed entry points in `src/app.js` (pages, `/api/v1/*`,
   static mounts). Every one is reachable by anyone.
3. Check each point below that the diff touches.
4. Run `npm run lint` and `npm test` (needs Redis: `REDIS_URL` or a local
   `redis-server`).
5. Quick secret grep on the diff:
   `git diff HEAD | grep -nEi '(password|secret|token|apikey|api_key|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]'`.
6. Fix what you find, then report: touched points, findings with file:line,
   what you fixed, what is left.

## The checklist, adapted to Vanishly

1. **Zero knowledge:** the server never receives the key or the plaintext
   from the browser. The key stays in the URL fragment; nothing sends
   `location.hash` to the server, to logs or to third parties. Only
   `POST /api/v1/share` sees plaintext and must not store or log it.
2. **Crypto format (`public/js/vanishly-crypto.js`):** AES-256-GCM with a fresh
   random IV and key per secret, HKDF/PBKDF2 parameters unchanged unless the
   format version changes; randomness only from `crypto.getRandomValues` /
   `node:crypto`. Changes here need a second careful read and tests.
3. **One-time semantics:** a view is taken only in the atomic Lua script in
   `src/store.js`; parallel reveals must not return a secret twice (test
   "parallel reveals"). A GET of `/s/:id` never uses a view.
4. **Passphrase:** checked on the server via the verifier hash with
   `timingSafeEqual` before a view is used; wrong attempts are counted and
   end in a burn at `PASSPHRASE_ATTEMPTS`.
5. **Ids:** 128-bit random, validated with `validId()` before any Redis
   call; no Redis key built from unvalidated input.
6. **Input validation:** every API field checked for type, pattern and
   length (`ttl`, `views`, base64url fields, `iterations` bounds), body size
   limited; errors are generic JSON without stack traces.
7. **Rate limits:** `create` and `read` buckets per client IP; the IP comes
   from `req.ip` with `TRUST_PROXY` set to the real proxy setup, otherwise
   `X-Forwarded-For` can be forged.
8. **Headers:** CSP without `unsafe-inline` scripts (no inline `<script>`
   or `on*=` attributes in views; JSON data only in
   `<script type="application/json">` with `<` escaped), `Referrer-Policy:
   no-referrer`, `Cache-Control: no-store` on pages and API, no
   `X-Powered-By`, frames denied.
9. **Templates:** values in views go through `{{ }}` (escaped); `{{{ }}}`
   only for HTML the app builds itself. Template files: plain files only, no
   symlinks, size-limited; footer links only `https?:`, `mailto:` or `/`
   paths; asset paths without `..`.
10. **Logs:** no ids (redacted to `:id`), keys, plaintext, passphrases,
    verifiers, IPs or user agents in `console.*`.
11. **Storage:** Redis keys expire (`PEXPIREAT`) with the secret; receipts
    hold no plaintext and no IPs; rate-limit keys hold hashed IPs only.
12. **Dependencies:** a change in `package.json`/`package-lock.json` →
    `npm audit --omit=dev`, say what changed; nothing loaded from a CDN at
    run time.
13. **Container/packaging:** runs as non-root, read-only root file system
    in compose, Redis not published to the host, base images pinned by
    digest, systemd unit keeps `HOST=127.0.0.1` and its hardening.
14. **Attack your own change:** try one hostile input on the changed code
    (`../`, `'`, `<script>`, very long strings, negative or huge numbers,
    a forged `X-Forwarded-For`, two parallel reveals) and check or test it.
