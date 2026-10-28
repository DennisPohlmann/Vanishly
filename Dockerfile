# Vanishly - container image.
#
#   docker build -t vanishly .
#   docker run -d --name vanishly -p 127.0.0.1:3000:3000 \
#     -e REDIS_URL=redis://redis:6379 vanishly
#
# Or everything with Redis: docker compose up -d (docker-compose.yml).
# All settings are environment variables, see .env.example.

# Base image (Node.js LTS on Alpine) written out in both FROM lines, pinned by
# digest, so Dependabot can update it (a new digest behind the same tag is an
# Alpine or Node patch). Pure JavaScript, no native modules.
FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /src
COPY package.json package-lock.json ./
COPY scripts ./scripts
# All packages for vendor/scalar.js (the API reference page), then only the
# production ones remain for the image.
RUN npm ci --ignore-scripts \
 && npm run vendor \
 && npm prune --omit=dev --ignore-scripts \
 && find node_modules -type d -empty -delete

FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53
ARG VERSION=dev
LABEL org.opencontainers.image.title="vanishly" \
      org.opencontainers.image.description="Vanishly - one-time secrets, end-to-end encrypted, stored in Redis" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"
WORKDIR /app
# Alpine security updates newer than the base image. npm, npx, corepack and
# yarn are not needed at run time and only add packages for the image scan.
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg /root/.npm \
 && mkdir -p /var/lib/vanishly/templates /var/lib/vanishly/translations
ENV NODE_ENV=production \
    VANISHLY_VERSION=${VERSION} \
    HOST=0.0.0.0 \
    PORT=3000 \
    TEMPLATES_DIR=/var/lib/vanishly/templates \
    TRANSLATIONS_DIR=/var/lib/vanishly/translations
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/vendor ./vendor
COPY package.json VERSION LICENSE THIRD-PARTY-LICENSES.md ./
COPY src ./src
COPY public ./public
COPY views ./views
COPY translations ./translations
COPY openapi ./openapi
COPY templates ./templates
# Own templates: mount a folder at /var/lib/vanishly/templates (read-only);
# own or extra translations (fr.json, ...) at /var/lib/vanishly/translations.
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "src/server.js"]
