# Installation

1. [Docker Compose (recommended)](#1-docker-compose-recommended)
2. [Container without Compose](#2-container-without-compose)
3. [tar.gz with systemd](#3-targz-with-systemd)
4. [Kubernetes (Helm)](#4-kubernetes-helm)
5. [Reverse proxy](#5-reverse-proxy)
6. [Own templates](#6-own-templates)
7. [Update](#7-update)
8. [Troubleshooting](#8-troubleshooting)
9. [Removal](#9-removal)
10. [Sign-in with Entra ID or OIDC](#10-sign-in-with-entra-id-or-oidc)

## 1. Docker Compose (recommended)

`docker-compose.yml` starts Vanishly and Redis. Redis is reachable only
inside the Compose network and keeps secrets in memory only.

```bash
git clone https://github.com/DennisPohlmann/Vanishly.git /opt/vanishly-compose
cd /opt/vanishly-compose
cp .env.example .env
```

Edit `.env`: at least `BASE_URL` (your public address) and, behind a reverse
proxy on the same host, `TRUST_PROXY=1` and `HSTS=true`. All settings:
[CONFIG.md](CONFIG.md). Then:

```bash
docker compose up -d             # pulls ghcr.io/dennispohlmann/vanishly
docker compose ps                # vanishly "healthy", redis "running"
```

`docker-compose.yml` only pulls images, so the file works on its own in any
folder, and with `podman-compose` too. To build the image from this folder
instead, add the build override:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

The app listens on `127.0.0.1:3000`.

## 2. Container without Compose

```bash
docker network create vanishly
docker run -d --name vanishly-redis --network vanishly --restart unless-stopped \
  redis:8-alpine redis-server --save "" --appendonly no
docker run -d --name vanishly --network vanishly --restart unless-stopped \
  -p 127.0.0.1:3000:3000 --read-only --tmpfs /tmp \
  -e REDIS_URL=redis://vanishly-redis:6379 -e BASE_URL=https://ots.example.com \
  -e TRUST_PROXY=1 ghcr.io/dennispohlmann/vanishly:latest
```

Image tags: `latest` (newest release), `<major>.<minor>`, `<version>`,
`edge` (newest commit on `main`).

## 3. tar.gz with systemd

Needs Node.js 22 or newer (24 LTS recommended) and a Redis server on the
host (`apt install redis-server`).

```bash
sudo useradd --system --home /opt/vanishly --shell /usr/sbin/nologin vanishly
sudo tar -C / -xzf vanishly-<version>.tar.gz     # /opt/vanishly, unit, /etc/vanishly/vanishly.env
sudo nano /etc/vanishly/vanishly.env              # BASE_URL, REDIS_URL, TRUST_PROXY=1
sudo chmod 640 /etc/vanishly/vanishly.env && sudo chgrp vanishly /etc/vanishly/vanishly.env
sudo mkdir -p /var/lib/vanishly/templates
sudo systemctl daemon-reload && sudo systemctl enable --now vanishly
```

The unit binds to `127.0.0.1` and runs hardened as user `vanishly`.
Release archives come with a `.sha256` file: `sha256sum -c vanishly-<version>.tar.gz.sha256`.

For a Redis on the host used only by Vanishly, disable persistence in
`/etc/redis/redis.conf` (`save ""`, `appendonly no`) so no secret is
written to disk.

## 4. Kubernetes (Helm)

The chart `charts/vanishly` runs Vanishly and, unless you point it to an
external Redis, a Redis that keeps secrets in memory only, both without
root and with read-only file systems. Each release publishes it with the
same version as an OCI package:

```bash
helm install vanishly oci://ghcr.io/dennispohlmann/charts/vanishly \
  --namespace vanishly --create-namespace -f my-values.yaml
helm test vanishly -n vanishly       # /healthz and the start page through the Service
```

`my-values.yaml`, for an ingress controller with cert-manager:

```yaml
config:
  TRUST_PROXY: "10.0.0.0/8"   # the network of the ingress controller
  HSTS: true
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: ots.example.com
      paths:
        - path: /
  tls:
    - secretName: ots-example-com-tls
      hosts: [ots.example.com]
```

Every setting of [CONFIG.md](CONFIG.md) is a key of `config`; `BASE_URL`
follows the first ingress host. An external Redis:
`redis.enabled=false` and `redis.external.existingSecret` (a Secret with
the key `redis-url`). Own templates go into `templates.files`; Gateway API,
autoscaling, PodDisruptionBudget, NetworkPolicies, labels, annotations
and overrides of every object: [charts/vanishly/README.md](../charts/vanishly/README.md).

Update: `helm upgrade vanishly oci://ghcr.io/dennispohlmann/charts/vanishly -n vanishly --reuse-values`
(open secrets survive as long as the Redis pod keeps running).
Removal: `helm uninstall vanishly -n vanishly`.

## 5. Reverse proxy

TLS is required: the secret key travels in the link. Example for nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name ots.example.com;
    # ssl_certificate ... ; ssl_certificate_key ... ;

    client_max_body_size 1m;
    access_log off;   # Vanishly logs requests itself, without ids and IPs

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, do not append
    }
}
```

Caddy: `ots.example.com { reverse_proxy 127.0.0.1:3000 }`.

Set `TRUST_PROXY=1` (one proxy) so the rate limits see the client address;
with `TRUST_PROXY=false` behind a proxy all clients share one limit.

## 6. Own templates

With Compose, next to `docker-compose.yml`:

```bash
mkdir -p custom-templates && cp -r /path/to/my-brand custom-templates/
chmod -R a+rX custom-templates   # the container reads as uid 1000
echo TEMPLATE=my-brand >> .env
docker compose up -d             # or: podman-compose up -d
```

The container reads the files as uid 1000; under rootless Podman that is a
different user than yours, so the files must be readable for others
(`a+rX`). Check the log (`docker compose logs vanishly`) for
`template "my-brand"`. A wrong name or an unreadable folder makes the
container exit with code 78 (Compose restarts it again and again); the reason
is in the log. With SELinux (Fedora, RHEL)
mount the folder with `:ro,Z` instead of `:ro` in `docker-compose.yml`.
Without Compose the folder is `/var/lib/vanishly/templates`
(`TEMPLATES_DIR`). How to build one:
[templates/README.md](../templates/README.md).

Own translations work the same way: put `fr.json` (adds French) or
`de.json` (replaces single German texts) into a folder, mount it with
`- ./custom-translations:/var/lib/vanishly/translations:ro` and restart; the
file format is in [CONFIG.md](CONFIG.md#languages). To serve English only,
set `LANGUAGES=en`.

## 7. Update

Compose: `docker compose pull && docker compose up -d` (built from a
checkout: `git pull` and the build command from section 1). Redis uses the tag `redis:8-alpine`, the latest
Redis 8: `docker compose pull redis && docker compose up -d redis` brings its
updates (open secrets are lost, as Redis keeps them in memory only).
Container: pull the new tag and recreate. tar.gz:
unpack the new archive over `/opt/vanishly` (your `/etc/vanishly/vanishly.env`
is replaced by the example, so back it up first, or unpack without `etc/`:
`tar -C / -xzf vanishly-<version>.tar.gz ./opt`) and `systemctl restart vanishly`.

Open secrets survive an app update; a restart of Redis without persistence
drops them (see [CONFIG.md](CONFIG.md#redis)).

## 8. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `/healthz` answers 503 | Redis not reachable, read-only or out of memory: check `REDIS_URL`, `docker compose logs redis` |
| Vanishly stops with exit code 69 | At start Redis was not reachable within 10 s or refused writes; the message names the reason. Docker restarts the container until Redis is ready |
| Start fails with `template "x" not found` | the folder is missing in `TEMPLATES_DIR` and `templates/`, or has no `theme.css` |
| Podman: `unknown mount option "uid=999"`, or `podman-compose up` hangs | an older `docker-compose.yml`: Podman refuses `uid=` on the Redis tmpfs; with `mode=0700` alone Redis (uid 999) cannot read `/data` and exits ("Permission denied"), and the old `condition: service_healthy` then waits for it forever. Use the current file (`/data:mode=1777`, plain `depends_on`) |
| Redis exits with `can't open the RDB file ... Permission denied` | `/data` is not readable for uid 999; use `/data:mode=1777` as in the current `docker-compose.yml` |
| Start fails with `invalid number` | a numeric setting is out of range ([CONFIG.md](CONFIG.md)) |
| "The link is incomplete" | the part after `#` was cut off by the mail or chat program; send the whole link |
| Everyone gets "Too many requests" | behind a proxy without `TRUST_PROXY`, all clients share one address |
| Links of `/api/v1/share` point to `http://` | set `BASE_URL` |
| Page without JavaScript shows nothing | the encryption needs JavaScript; this is on purpose |
| "The sign-in did not work" | the log says why (`auth: sign-in failed: ...`): wrong client secret, redirect URI not registered as `<BASE_URL>/auth/callback`, token of another tenant, or an account without an e-mail address / user name |
| "The sign-in service is not reachable" | Vanishly cannot fetch `<issuer>/.well-known/openid-configuration`: check `ENTRA_TENANT_ID` / `OIDC_ISSUER` and outgoing HTTPS |
| A recipient in a group gets "not shared with your account" | no `groups` claim in the token: add "Group claims" in the app registration, or `ENTRA_GRAPH=true` for users in more than 200 groups |

Logs: `docker compose logs -f vanishly` or `journalctl -u vanishly -f`.

## 9. Removal

Compose: `docker compose down` (removes the containers; the in-memory secrets
are gone). tar.gz: `systemctl disable --now vanishly`, then remove
`/opt/vanishly`, `/etc/vanishly`, `/etc/systemd/system/vanishly.service`,
`/var/lib/vanishly` and the user `vanishly`.

## 10. Sign-in with Entra ID or OIDC

Optional; [CONFIG.md](CONFIG.md#sign-in-and-recipients) explains what it
does, [providers/](providers/README.md) what each provider supports. Vanishly must be served via HTTPS with `BASE_URL` set.

### Microsoft Entra ID

1. Entra admin center → **App registrations** → **New registration**:
   name `Vanishly`, "Accounts in this organizational directory only",
   redirect URI **Web** `https://ots.example.com/auth/callback`.
2. **Certificates & secrets** → new client secret; note its value.
3. Optional, for groups as recipients: **Token configuration** → **Add
   groups claim** → "Security groups" (ID token: "Group ID").
4. Optional, for `RECIPIENT_GROUPS=*` and users in more than 200 groups:
   **API permissions** → Microsoft Graph → **Application permissions** →
   `GroupMember.Read.All` → **Grant admin consent**, and set
   `ENTRA_GRAPH=true`.
   For the people search (`RECIPIENT_USER_GROUP=<group object id>`) add
   `User.Read.All` (application) as well.
5. Optional, for scripts: **Expose an API** → Application ID URI
   `api://<client id>`, add a scope (e.g. `Secrets.Use`), and set
   `AUTH_API_AUDIENCE=api://<client id>`. Set "accessTokenAcceptedVersion"
   to 2 in the manifest.
6. Optional: in **Enterprise applications** → Vanishly → Properties, set
   "Assignment required" to limit who can sign in at all.
7. Settings (`.env`):

   ```sh
   BASE_URL=https://ots.example.com
   AUTH_PROVIDER=entra
   ENTRA_TENANT_ID=<directory (tenant) id>
   ENTRA_CLIENT_ID=<application (client) id>
   ENTRA_CLIENT_SECRET=<secret value>
   AUTH_SECRET=<openssl rand -base64 48>
   # RECIPIENT_GROUPS=IT Admins=<group object id>,HR=<group object id>
   # ENTRA_GRAPH=true
   # RECIPIENT_USER_GROUP=<object id of the group whose members are suggested>
   ```

The whole site behind **Entra Application Proxy** (pre-authentication)
works as well, alone or together with this: the proxy keeps everybody
outside the tenant away, the built-in sign-in decides per secret.

### Keycloak, Okta, Auth0, Google Workspace, PingOne, JumpCloud, Cognito

These have presets (`AUTH_PROVIDER=keycloak`, `okta`, ...): one page per
provider with the client setup, the groups claim, the directory access for
the people search and an example is in [providers/](providers/README.md).

### Another OpenID Connect provider

Create a confidential client with the redirect URI
`https://ots.example.com/auth/callback` and the "authorization code" flow,
then set `AUTH_PROVIDER=oidc`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` and `AUTH_SECRET`. For groups, let the provider put a
`groups` claim (a list of strings; another name with `OIDC_GROUPS_CLAIM`)
into the ID token and list the values in `RECIPIENT_GROUPS` (`Ops=ops`).
There is no people search with `oidc`.

### Try it locally with a test login server

`docker-compose.auth-test.yml` adds a test login server
([mock-oauth2-server](https://github.com/navikt/mock-oauth2-server)) where
you can sign in as anybody. Only for your own machine:

```sh
docker compose -f docker-compose.yml -f docker-compose.auth-test.yml up -d --build
```

Open `http://localhost:3000` and click "Sign in". On the test server's page
type any user name and, as claims,
`{"email": "alice@example.com", "name": "Alice", "groups": ["ops"]}`.
Create a secret for `bob@example.com`, open the link in a private window
and sign in there as Bob (or as somebody else, to see it refused).
