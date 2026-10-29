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
10. [Sign-in](#10-sign-in)

## 1. Docker Compose (recommended)

`docker-compose/standalone/docker-compose.yml` starts Vanishly and Redis
(until 1.2.1 the file was at the top of the repository). Redis is reachable
only inside the Compose network and keeps secrets in memory only.

```bash
mkdir -p /opt/vanishly && cd /opt/vanishly
curl -fsSLO https://raw.githubusercontent.com/DennisPohlmann/Vanishly/main/docker-compose/standalone/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/DennisPohlmann/Vanishly/main/.env.example -o .env
```

Edit `.env`: at least `BASE_URL` (your public address) and, behind a reverse
proxy on the same host, `TRUST_PROXY=1` and `HSTS=true`. All settings:
[CONFIG.md](CONFIG.md). Then:

```bash
docker compose up -d             # pulls ghcr.io/dennispohlmann/vanishly
docker compose ps                # vanishly "healthy", redis "running"
```

`docker-compose.yml` only pulls images, so the file works on its own in any
folder, and with `podman-compose` too. To build the image from a checkout
instead, add the build override in `docker-compose/standalone/`:

```bash
cd docker-compose/standalone
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

An example with sign-in through Keycloak and demo users is in
[docker-compose/keycloak](../docker-compose/keycloak/README.md).

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

With Compose, next to `docker-compose.yml` (in `docker-compose/standalone/`
of a checkout that is the folder `custom-templates` already there):

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

## 10. Sign-in

Optional and off by default ([no sign-in](providers/none.md)). Vanishly
must be served via HTTPS with `BASE_URL` set; the provider gets the
redirect URI `<BASE_URL>/auth/callback`.

1. Pick the provider and follow its page: [Entra ID](providers/entra.md),
   [Keycloak](providers/keycloak.md), [Okta](providers/okta.md),
   [Auth0](providers/auth0.md), [Google Workspace](providers/google.md),
   [PingOne](providers/ping.md), [JumpCloud](providers/jumpcloud.md),
   [Cognito](providers/cognito.md) or [any other OpenID Connect
   provider](providers/oidc.md). The [overview](providers/README.md) shows
   what each one supports.
2. Put the settings from that page into `.env` (Compose), the Helm values
   (`config`, secrets in `secretConfig` or `existingSecret`) or
   `/etc/vanishly/vanishly.env` (systemd) and restart. A wrong or missing
   value stops the start with a message.
3. Pick what sign-in should do: who may create, recipients, responsible
   people, the status page ([CONFIG.md](CONFIG.md#sign-in-and-recipients)).

To try it on your own machine: [docker-compose/keycloak](../docker-compose/keycloak/README.md)
(Keycloak with demo users alice, bob and carol) or the
[test login server](providers/oidc.md#try-it-locally).

## 11. Audit log shipping

The audit log (`AUDIT_LOG=true`, see [CONFIG.md](CONFIG.md#audit-log)) is
one JSON object per line, on stdout and/or in `AUDIT_LOG_FILE`; the format
(`AUDIT_LOG_FORMAT`) decides the field names: `ecs` for Elastic and most
others, `otel` for OpenTelemetry pipelines. The chain fields stay inside
every event, so a shipped copy can be checked with `audit:verify` too.
Keep the file on a volume (the container's root file system is read-only):

```yaml
# docker-compose.override.yml
services:
  vanishly:
    environment:
      AUDIT_LOG: "true"
      AUDIT_LOG_FILE: /var/log/vanishly/audit.jsonl
      AUDIT_LOG_STDOUT: "true"
      AUDIT_LOG_HMAC_KEY_FILE: /run/secrets/audit_hmac_key
    volumes:
      - audit:/var/log/vanishly
volumes:
  audit:
```

(The image runs as user `node`, uid 1000: the volume must be writable for it.)

**Grafana Loki (Promtail)**, from the file:

```yaml
scrape_configs:
  - job_name: vanishly-audit
    static_configs:
      - targets: [localhost]
        labels: { job: vanishly-audit, __path__: /var/log/vanishly/audit.jsonl }
    pipeline_stages:
      - json:
          expressions: { ts: '"@timestamp"', action: event.action, outcome: event.outcome, user: user.name }
      - labels: { action: , outcome: }
      - timestamp: { source: ts, format: RFC3339Nano }
```

In Kubernetes the pod logs (`AUDIT_LOG_STDOUT=true`) reach Loki through
Promtail / Grafana Alloy as usual; select them with
`{app="vanishly"} | json | event_dataset="vanishly.audit"`.

**Elastic (Filebeat)** with `AUDIT_LOG_FORMAT=ecs`:

```yaml
filebeat.inputs:
  - type: filestream
    id: vanishly-audit
    paths: [/var/log/vanishly/audit.jsonl]
    parsers:
      - ndjson: { target: "", overwrite_keys: true, expand_keys: true }
output.elasticsearch:
  hosts: ["https://elastic.example.com:9200"]
  index: "logs-vanishly.audit-default"
```

**Splunk (HTTP Event Collector)**, straight from Vanishly:

```sh
AUDIT_LOG_WEBHOOK_URL=https://splunk.example.com:8088/services/collector/event
AUDIT_LOG_WEBHOOK_AUTH_FILE=/run/secrets/splunk_hec   # file content: Splunk <HEC token>
AUDIT_LOG_WEBHOOK_FORMAT=splunk
```

(or the universal forwarder on the file with `sourcetype = _json`).

**OpenTelemetry Collector**, OTLP/HTTP from Vanishly:

```sh
AUDIT_LOG_FORMAT=otel
AUDIT_LOG_OTLP_URL=http://otel-collector:4318/v1/logs
```

```yaml
# collector
receivers:
  otlp:
    protocols: { http: { endpoint: 0.0.0.0:4318 } }
  filelog:                      # or read the file instead
    include: [/var/log/vanishly/audit.jsonl]
    operators: [{ type: json_parser }]
exporters:
  otlphttp/loki: { endpoint: http://loki:3100/otlp }
service:
  pipelines:
    logs: { receivers: [otlp], exporters: [otlphttp/loki] }
```

**Syslog** (rsyslog, syslog-ng, a SIEM): `AUDIT_LOG_SYSLOG=tls://siem.example.com:6514`
(RFC 5424, facility authpriv, the event JSON as message).

The exporters (syslog, OTLP, webhook) are best effort: they retry for
about two minutes and keep up to 10 000 events in memory; the file, stdout
and Redis copies are written before the action goes on.
