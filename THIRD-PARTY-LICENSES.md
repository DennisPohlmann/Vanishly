# Third-party licenses

Vanishly is licensed under GPL-3.0-or-later (see [LICENSE](LICENSE)). It uses the
components below; their licenses are compatible with the GPL. The full license
texts ship with each package in `node_modules/<package>/LICENSE`.

## Directly used

| Component | Version | License | Use |
|---|---|---|---|
| [Express](https://expressjs.com) | 5.3.0 | MIT | HTTP server and routing |
| [node-redis](https://github.com/redis/node-redis) | 6.3.0 | MIT | Redis client |
| [Scalar API Reference](https://github.com/scalar/scalar) (@scalar/api-reference) | 1.76.2 | MIT | API documentation page `/api/docs`; its browser bundle is shipped as `vendor/scalar.js` |
| [openid-client](https://github.com/panva/openid-client) | 6.8.8 | MIT | sign-in with OpenID Connect (optional, `AUTH_PROVIDER`) |
| [jose](https://github.com/panva/jose) | 6.2.13 | MIT | checks API bearer tokens (optional, `AUTH_API_AUDIENCE`) |
| [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) (docker-compose.auth-test.yml, separate container) | 6.1.3 | MIT | test login server, only for trying the sign-in locally; not part of the image |
| [Node.js](https://nodejs.org) (container base image) | 24 LTS | MIT and others | runtime |
| [Alpine Linux](https://alpinelinux.org) (container base image) | | various (GPL-2.0, MIT, ...) | container OS |
| [Redis](https://redis.io) (docker compose and Helm chart, separate container) | 8 | RSALv2 / SSPLv1 / AGPLv3 (tri-license) | storage; runs as its own service, not linked into Vanishly |

`vendor/scalar.js` is built from the development package by `npm run vendor`, without the web fonts that Scalar loads from its own servers. It bundles the packages Scalar needs in the browser (Vue and others, under MIT, BSD, ISC and Apache-2.0 licenses); their notices are in the bundle and in the [Scalar repository](https://github.com/scalar/scalar).

## All production npm packages (`npm ls --omit=dev --all`)

### BSD-3-Clause (1)

qs 6.17.0

### ISC (4)

inherits 2.0.4, once 1.4.0, setprototypeof 1.2.0, wrappy 1.0.2

### MIT (69)

@redis/bloom 6.3.0, @redis/client 6.3.0, @redis/json 6.3.0, @redis/search 6.3.0, @redis/time-series 6.3.0, accepts 2.0.0, body-parser 2.4.0, bytes 3.1.2, call-bind-apply-helpers 1.0.2, call-bound 1.0.4, content-disposition 2.0.1, content-type 2.1.0, cookie 0.7.2, cookie-signature 1.2.2, debug 4.4.3, depd 2.0.0, dunder-proto 1.0.1, ee-first 1.1.1, encodeurl 2.0.0, es-define-property 1.0.1, es-errors 1.3.0, es-object-atoms 1.1.2, escape-html 1.0.3, etag 1.8.1, express 5.3.0, finalhandler 2.1.1, forwarded 0.2.0, fresh 2.0.0, function-bind 1.1.2, get-intrinsic 1.3.0, get-proto 1.0.1, gopd 1.2.0, has-symbols 1.1.0, hasown 2.0.4, http-errors 2.0.1, iconv-lite 0.7.3, ipaddr.js 1.9.1, is-promise 4.0.0, jose 6.2.13, math-intrinsics 1.1.0, media-typer 1.1.1, merge-descriptors 2.0.0, mime-db 1.54.0, mime-types 3.0.2, ms 2.1.3, negotiator 1.1.0, oauth4webapi 3.8.8, object-inspect 1.13.4, on-finished 2.4.2, openid-client 6.8.8, parseurl 1.3.3, path-to-regexp 8.4.2, proxy-addr 2.0.8, range-parser 1.3.0, raw-body 3.0.2, redis 6.3.0, router 2.2.0, safer-buffer 2.1.2, send 1.2.1, serve-static 2.2.1, side-channel 1.1.1, side-channel-list 1.0.1, side-channel-map 1.0.1, side-channel-weakmap 1.0.2, statuses 2.0.2, toidentifier 1.0.1, type-is 2.1.0, unpipe 1.0.0, vary 1.1.2
