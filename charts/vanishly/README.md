# Vanishly Helm chart

Runs [Vanishly](https://github.com/DennisPohlmann/Vanishly) on Kubernetes:
one-time secret links, end-to-end encrypted in the browser, stored in Redis.
The chart brings its own Redis (in memory only, password protected) or uses
an external one. Everything can be changed through values; whatever the
values do not cover can be patched with `overrides` or added with
`extraObjects`.

The chart is released together with the app, with the same version, as an
OCI package on GitHub Container Registry.

## Install

```sh
helm install vanishly oci://ghcr.io/dennispohlmann/charts/vanishly \
  --namespace vanishly --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=ots.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set config.TRUST_PROXY=10.0.0.0/8
```

A specific version: `--version <version>`. Show the values of a version:
`helm show values oci://ghcr.io/dennispohlmann/charts/vanishly`. Check a
running release: `helm test vanishly -n vanishly`.

From a checkout: `helm install vanishly ./charts/vanishly`.

Update: `helm upgrade vanishly oci://ghcr.io/dennispohlmann/charts/vanishly -n vanishly --reuse-values`.
Uninstall: `helm uninstall vanishly -n vanishly`.

## What it runs

- **Vanishly** as a Deployment (any number of pods; all state is in Redis)
  as uid 1000 with a read-only root file system, no capabilities, no
  service account token and the RuntimeDefault seccomp profile. A
  checksum of the settings is in the pod annotations, so a changed setting
  rolls the pods.
- **Redis** (`redis.enabled`, default) as one pod, `redis:8-alpine` as uid
  999, read-only, without snapshots or append-only file: secrets live only
  in memory, and a Redis restart drops open secrets (as with
  docker-compose/standalone/docker-compose.yml). A password is generated on the first install and
  kept across upgrades. Vanishly pods wait in an init container until
  Redis answers.
- Optional: Ingress, Gateway API HTTPRoute, HorizontalPodAutoscaler,
  PodDisruptionBudget, NetworkPolicies, a `helm test` pod.

There is no ServiceMonitor: Vanishly has no metrics endpoint. Probes use
`/healthz` (200 when Redis accepts writes); the liveness probe is a TCP
check, so a Redis outage takes pods out of the Service without restarting
them all.

## Settings

Every Vanishly setting of [docs/CONFIG.md](../../docs/CONFIG.md) is a key
of `config` with the same name; an empty value means the app's default.
They go into a ConfigMap and reach the pod as environment variables.
Vanishly checks every value at start and stops with a message on a wrong
value or a misspelt name (`kubectl logs`); the chart's `values.schema.json`
already checks types, ranges and patterns at `helm install`.

```yaml
config:
  TRUST_PROXY: "10.0.0.0/8"   # behind an ingress controller; otherwise all clients share one rate limit
  HSTS: true
  TEMPLATE: aurora
  TTL_OPTIONS: 15m,1h,1d,7d
  DEFAULT_TTL: 1d
  REQUIRE_PASSPHRASE: true
```

`BASE_URL` is set to `https://<first ingress or httpRoute host>` when it is
empty (`baseUrlFromIngress`).

Sensitive values: `secretConfig` (a Secret made by the chart),
`existingSecret` / `existingConfigMap` (all their keys as environment
variables), or `extraEnv` / `extraEnvFrom` for anything else. Names
`config` does not list are passed as they are, so settings of a newer app
version work before the chart knows them.

### Redis

```yaml
# bundled, with your own password Secret (key redis-password)
redis:
  auth:
    existingSecret: vanishly-redis

# external
redis:
  enabled: false
  external:
    existingSecret: vanishly-redis-url   # key redis-url: rediss://:password@redis.example.com:6380
```

`redis.external.url` works too; the chart puts it into a Secret. Any Redis
URL works there: another host, `rediss://` (TLS), an ACL user
(`rediss://app:password@host:6380`), a database (`/2`). For an own CA, mount
the PEM file with `extraVolumes`/`extraVolumeMounts` and set
`config.REDIS_TLS_CA_FILE` to its path. With
GitOps tools that render without cluster access (Argo CD), set
`redis.auth.password` or `redis.auth.existingSecret`: a generated password
would change on every render.

### Own design templates

Vanishly reads only plain files, and Kubernetes mounts ConfigMaps as
symbolic links. The chart therefore copies template files into an
`emptyDir` in an init container and mounts that read-only at
`TEMPLATES_DIR`. See [templates/README.md](../../templates/README.md) for
the files of a template.

```yaml
config:
  TEMPLATE: acme
templates:
  files:
    acme/theme.css: |
      :root, html[data-theme="light"] { --accent: #c2410c; }
      html[data-theme="dark"] { --accent: #fb923c; }
    acme/template.json: |
      { "siteName": "ACME Secrets", "logo": "logo.svg" }
    acme/assets/logo.svg: |
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="5"/></svg>
  binaryFiles:
    acme/assets/photo.png: iVBORw0KGgo...   # base64
```

Or from ConfigMaps you manage yourself
(`templates.existingConfigMaps: [{name: acme-theme, items: [{key: theme.css, path: acme/theme.css}]}]`),
or any volume mounted as it is (`templates.volume: {persistentVolumeClaim: {claimName: acme}}`).
ConfigMaps are limited to 1 MiB in total.

Own translations use the same files: put them into a folder below
`TEMPLATES_DIR` that is no template and point `TRANSLATIONS_DIR` at it.

```yaml
config:
  TRANSLATIONS_DIR: /var/lib/vanishly/templates/translations
  LANGUAGES: en,fr
templates:
  files:
    translations/fr.json: |
      { "lang.name": "Français", "home.title": "Partager un secret" }
```

### Labels, annotations and overrides

- `commonLabels` / `commonAnnotations` go on every object; `podLabels`,
  `podAnnotations`, `deploymentLabels`, `service.labels`,
  `ingress.annotations` and the like on single ones. Annotations, affinity
  and the `extra*` lists are rendered with `tpl`, so `{{ .Release.Name }}` works.
- `overrides.<object>` is deep-merged into the rendered object last (lists
  are replaced as a whole), for anything without its own value:

  ```yaml
  overrides:
    deployment:
      spec:
        template:
          spec:
            hostUsers: false
    redisService:
      spec:
        ipFamilyPolicy: PreferDualStack
  ```

  Keys: `deployment`, `service`, `serviceAccount`, `configMap`, `secret`,
  `redisUrlSecret`, `templatesConfigMap`, `ingress`, `httpRoute`, `hpa`,
  `pdb`, `networkPolicy`, `redisDeployment`, `redisService`,
  `redisSecret`, `redisNetworkPolicy`.
- A probe's handler is replaced by setting the old one to `null`
  (`readinessProbe: {httpGet: null, exec: {...}}`).
- `extraObjects` adds any manifest (map or string, rendered with `tpl`).

### Network policies

`networkPolicy.enabled` lets only the Vanishly pods reach Redis and
restricts Vanishly's egress to DNS and Redis (`networkPolicy.egress.extraRules`
for more). `networkPolicy.ingress.from` limits who reaches Vanishly, e.g.
the ingress controller:

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
```

With sign-in (`config.AUTH_PROVIDER`), Vanishly also talks to the identity
provider (and its directory with `ENTRA_GRAPH` or `DIRECTORY_API`, e.g.
Microsoft Graph, the Okta or Google Admin API, Cognito and, on EKS, STS):
allow that with `networkPolicy.egress.extraRules`, port 443. Directory
credentials go into `secretConfig` or `existingSecret`
(`DIRECTORY_CLIENT_SECRET`, `DIRECTORY_API_TOKEN`, `AWS_SECRET_ACCESS_KEY`);
the Google service account key as a file through `extraVolumes`. Setup per
provider: [docs/providers](https://github.com/DennisPohlmann/Vanishly/blob/main/docs/providers/README.md).

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules. |
| args | list | `[]` | Container arguments (default: the image's). |
| autoscaling.behavior | object | `{}` | Scaling behavior. |
| autoscaling.enabled | bool | `false` | Create a HorizontalPodAutoscaler (replaces replicaCount). |
| autoscaling.maxReplicas | int | `10` | Most pods. |
| autoscaling.metrics | list | `[]` | More metrics (autoscaling/v2). |
| autoscaling.minReplicas | int | `2` | Fewest pods. |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU use in percent of the request (null: none). |
| autoscaling.targetMemoryUtilizationPercentage | int | `nil` | Target memory use in percent of the request (null: none). |
| baseUrlFromIngress | bool | `true` | Set BASE_URL to https://<first host> of ingress or httpRoute when config.BASE_URL is empty. |
| command | list | `[]` | Container command (default: the image's). |
| commonAnnotations | object | `{}` | Annotations added to every resource (not to the pods; see podAnnotations). |
| commonLabels | object | `{}` | Labels added to every resource, the pods included. |
| config | object | see values.yaml | Vanishly settings as environment variables, with the names of docs/CONFIG.md. An empty value is left out, so the app uses its default (shown in the comment). Values are passed as strings; true/false and numbers may be written unquoted. Names not listed here are passed too, so settings of newer app versions work without a chart update; the app stops at start on an unknown or misspelt name. REDIS_URL is set from the redis section below. Put sensitive values into secretConfig or existingSecret instead. |
| containerPort.name | string | `"http"` | Name of the container port. |
| deploymentAnnotations | object | `{}` | Annotations of the Deployment. |
| deploymentLabels | object | `{}` | Labels of the Deployment. |
| dnsConfig | object | `{}` | DNS config. |
| dnsPolicy | string | `""` | DNS policy. |
| enableServiceLinks | bool | `false` | Service environment variables (`<SERVICE>_PORT`, ...); off, Vanishly does not use them. |
| existingConfigMap | string | `""` | Existing ConfigMap whose keys are passed as environment variables (envFrom). |
| existingSecret | string | `""` | Existing Secret whose keys are passed as environment variables (envFrom), e.g. for settings you keep out of values. |
| extraContainers | list | `[]` | Sidecar containers. Templated with tpl. |
| extraEnv | list | `[]` | More environment variables (list of EnvVar); they win over config. Templated with tpl. |
| extraEnvFrom | list | `[]` | More envFrom sources (configMapRef/secretRef). Templated with tpl. |
| extraObjects | list | `[]` | More Kubernetes objects (maps or strings); templated with tpl. |
| extraVolumeMounts | list | `[]` | More volume mounts of the Vanishly container. Templated with tpl. |
| extraVolumes | list | `[]` | More volumes of the pod. Templated with tpl. |
| fullnameOverride | string | `""` | Full override of the resource names. |
| global.imagePullSecrets | list | `[]` | Pull secrets for every pod, e.g. `[{name: regcred}]`. |
| global.imageRegistry | string | `""` | Registry that replaces the registry of every image (Vanishly, Redis, init containers). |
| hostAliases | list | `[]` | Host aliases. |
| httpRoute.annotations | object | `{}` | Annotations. |
| httpRoute.enabled | bool | `false` | Create a Gateway API HTTPRoute. |
| httpRoute.hostnames | list | `["ots.example.com"]` | Host names. |
| httpRoute.labels | object | `{}` | Labels. |
| httpRoute.parentRefs | list | `[]` | Gateways to attach to (`[{name, namespace, sectionName}]`). |
| httpRoute.rules | list | `[]` | Rules; an empty list sends everything to the Service. Templated with tpl. |
| image.digest | string | `""` | Image digest (`sha256:...`); wins over the tag. |
| image.pullPolicy | string | `"IfNotPresent"` | Pull policy. |
| image.registry | string | `"ghcr.io"` | Image registry. |
| image.repository | string | `"dennispohlmann/vanishly"` | Image repository. |
| image.tag | string | `""` | Image tag (default: the chart's appVersion). |
| imagePullSecrets | list | `[]` | Pull secrets of the Vanishly pods, in addition to global.imagePullSecrets. |
| ingress.annotations | object | `{}` | Annotations (e.g. cert-manager.io/cluster-issuer). Templated with tpl. |
| ingress.className | string | `""` | Ingress class. |
| ingress.enabled | bool | `false` | Create an Ingress. |
| ingress.extraRules | list | `[]` | More rules, as in an Ingress spec. Templated with tpl. |
| ingress.hosts | list | `[{"host":"ots.example.com","paths":[{"path":"/","pathType":"Prefix"}]}]` | Hosts and their paths; `pathType` defaults to Prefix. |
| ingress.labels | object | `{}` | Labels. |
| ingress.tls | list | `[]` | TLS entries (`[{secretName, hosts}]`). |
| initContainers | list | `[]` | More init containers. Templated with tpl. |
| lifecycle | object | `{}` | Container lifecycle hooks. |
| livenessProbe | object | `{"enabled":true,"failureThreshold":3,"periodSeconds":10,"tcpSocket":{"port":"http"},"timeoutSeconds":3}` | Liveness probe; a TCP check, so a Redis outage does not restart every pod. |
| minReadySeconds | int | `0` | Seconds a new pod must be ready before it counts as available. |
| nameOverride | string | `""` | Partial override of the resource names (keeps the release name). |
| namespaceOverride | string | `""` | Namespace for all resources (default: the release namespace). |
| networkPolicy.egress.dnsPort | int | `53` | DNS port. |
| networkPolicy.egress.enabled | bool | `true` | Restrict egress of the Vanishly pods to DNS and Redis (plus extraRules). |
| networkPolicy.egress.externalRedisTo | list | `[]` | Peers allowed for an external Redis (empty: any address on redis.external.port). |
| networkPolicy.egress.extraRules | list | `[]` | More egress rules (e.g. to an OIDC provider). |
| networkPolicy.enabled | bool | `false` | Create NetworkPolicies for Vanishly and the bundled Redis. |
| networkPolicy.ingress.extraRules | list | `[]` | More ingress rules of the Vanishly pods. |
| networkPolicy.ingress.from | list | `[]` | Who may reach Vanishly (NetworkPolicyPeer list); empty: everybody. E.g. the ingress controller's namespace. |
| nodeSelector | object | `{}` | Node selector. |
| overrides | object | `{}` | Deep-merge patches of the rendered objects, by object (see the comment above). |
| podAnnotations | object | `{}` | Annotations of the pods. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. |
| podDisruptionBudget.maxUnavailable | int|string | `nil` | Pods that may be down (number or percent); wins over minAvailable. |
| podDisruptionBudget.minAvailable | int | `1` | Pods that must stay available (number or percent); used when maxUnavailable is empty. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `""` | IfHealthyBudget or AlwaysAllow. |
| podLabels | object | `{}` | Labels of the pods (in addition to commonLabels). |
| podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. |
| priorityClassName | string | `""` | Priority class. |
| readinessProbe | object | `{"enabled":true,"failureThreshold":3,"httpGet":{"path":"/healthz","port":"http"},"periodSeconds":5,"timeoutSeconds":3}` | Readiness probe; takes the pod out of the Service while Redis is unavailable. |
| redis.affinity | object | `{}` | Affinity rules. |
| redis.auth.enabled | bool | `true` | Require a password (requirepass). |
| redis.auth.existingSecret | string | `""` | Existing Secret with the password (replaces password). |
| redis.auth.existingSecretPasswordKey | string | `"redis-password"` | Key of the password in existingSecret. |
| redis.auth.password | string | `nil` | Password; unset (null): a random one is made once and kept across upgrades. Only URL-safe characters. |
| redis.dataSizeLimit | string | `"64Mi"` | Size limit of the in-memory /data emptyDir (without persistence). |
| redis.deploymentAnnotations | object | `{}` | Annotations of the Deployment. |
| redis.deploymentLabels | object | `{}` | Labels of the Deployment. |
| redis.enabled | bool | `true` | Run the bundled Redis (a single non-root Deployment). false: use redis.external. |
| redis.external.existingSecret | string | `""` | Existing Secret with the URL (replaces url). |
| redis.external.existingSecretUrlKey | string | `"redis-url"` | Key of the URL in existingSecret. |
| redis.external.port | int | `6379` | Port of the external Redis, for networkPolicy egress. |
| redis.external.url | string | `""` | URL of an external Redis, e.g. rediss://:password@redis.example.com:6380. Stored in a Secret. |
| redis.extraArgs | list | `[]` | More redis-server arguments, e.g. `["--loglevel", "warning"]`. |
| redis.extraContainers | list | `[]` | Sidecars of the Redis pod (e.g. an exporter). |
| redis.extraEnv | list | `[]` | More environment variables of the Redis container. |
| redis.extraVolumeMounts | list | `[]` | More volume mounts of the Redis container. |
| redis.extraVolumes | list | `[]` | More volumes of the Redis pod. |
| redis.image.digest | string | `""` | Image digest (`sha256:...`); wins over the tag. |
| redis.image.pullPolicy | string | `"IfNotPresent"` | Pull policy. |
| redis.image.registry | string | `"docker.io"` | Image registry. |
| redis.image.repository | string | `"redis"` | Image repository. |
| redis.image.tag | string | `"8-alpine"` | Image tag (the latest Redis 8 on Alpine, as in docker-compose/standalone/docker-compose.yml). |
| redis.livenessProbe | object | `{"enabled":true,"failureThreshold":3,"periodSeconds":10,"tcpSocket":{"port":"redis"},"timeoutSeconds":3}` | Liveness probe. |
| redis.maxmemory | string | `"200mb"` | Memory limit of Redis (maxmemory); keep it below resources.limits.memory. |
| redis.maxmemoryPolicy | string | `"volatile-ttl"` | Eviction policy when maxmemory is reached. |
| redis.nodeSelector | object | `{}` | Node selector. |
| redis.persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes of the claim. |
| redis.persistence.appendfsync | string | `"everysec"` | appendfsync: always, everysec or no. |
| redis.persistence.enabled | bool | `false` | Keep the data over restarts: append-only file on a PersistentVolumeClaim. Off: memory only. Needed for the admin interface (audit log in Redis, API tokens, technical users, token permissions). Note: the (encrypted) secrets are then written to disk too. |
| redis.persistence.existingClaim | string | `""` | Use an existing claim instead of creating one. |
| redis.persistence.size | string | `"1Gi"` | Size of the volume. |
| redis.persistence.storageClass | string | `""` | Storage class ("" = the cluster default). |
| redis.podAnnotations | object | `{}` | Annotations of the pod. |
| redis.podLabels | object | `{}` | Labels of the pod. |
| redis.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsNonRoot":true,"runAsUser":999,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. |
| redis.priorityClassName | string | `""` | Priority class. |
| redis.readinessProbe | object | `{"enabled":true,"exec":{"command":["sh","-c","redis-cli ping | grep -q PONG"]},"failureThreshold":3,"periodSeconds":5,"timeoutSeconds":3}` | Readiness probe. |
| redis.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Resources. |
| redis.runtimeClassName | string | `""` | Runtime class. |
| redis.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsGroup":1000,"runAsNonRoot":true,"runAsUser":999,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context. |
| redis.service.annotations | object | `{}` | Annotations. |
| redis.service.labels | object | `{}` | Labels. |
| redis.service.port | int | `6379` | Port. |
| redis.startupProbe | object | `{"enabled":true,"exec":{"command":["sh","-c","redis-cli ping | grep -q PONG"]},"failureThreshold":30,"periodSeconds":2,"timeoutSeconds":3}` | Startup probe. |
| redis.terminationGracePeriodSeconds | int | `30` | Seconds between SIGTERM and SIGKILL. |
| redis.tolerations | list | `[]` | Tolerations. |
| redis.topologySpreadConstraints | list | `[]` | Topology spread constraints. |
| redis.waitForRedis | bool | `true` | Wait in an init container of the Vanishly pods until Redis answers, instead of restarting until it is up. |
| redis.waitResources | object | `{"limits":{"memory":"32Mi"},"requests":{"cpu":"10m","memory":"16Mi"}}` | Resources of the wait init container. |
| replicaCount | int | `1` | Pods; ignored while autoscaling.enabled. All state is in Redis, so any number works. |
| resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"96Mi"}}` | Container resources. |
| revisionHistoryLimit | int | `10` | Old ReplicaSets kept for rollbacks. |
| runtimeClassName | string | `""` | Runtime class (e.g. gvisor). |
| schedulerName | string | `""` | Scheduler. |
| secretConfig | object | `{}` | Sensitive settings (NAME: value), stored in a Secret made by the chart and passed as environment variables. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsGroup":1000,"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context. |
| service.annotations | object | `{}` | Annotations. |
| service.clusterIP | string | `""` | Fixed cluster IP. |
| service.externalTrafficPolicy | string | `""` | Local keeps the client IP for NodePort/LoadBalancer. |
| service.internalTrafficPolicy | string | `""` | internalTrafficPolicy. |
| service.ipFamilies | list | `[]` | IP families. |
| service.ipFamilyPolicy | string | `""` | IP family policy. |
| service.labels | object | `{}` | Labels. |
| service.loadBalancerClass | string | `""` | Load balancer class. |
| service.loadBalancerIP | string | `""` | Load balancer IP (if the provider supports it). |
| service.loadBalancerSourceRanges | list | `[]` | Allowed client ranges of a LoadBalancer. |
| service.nodePort | int | `nil` | nodePort for NodePort/LoadBalancer. |
| service.port | int | `80` | Service port. |
| service.portName | string | `"http"` | Port name. |
| service.sessionAffinity | string | `""` | Session affinity. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | Annotations (e.g. for workload identity). |
| serviceAccount.automountServiceAccountToken | bool | `false` | Mount the API token; Vanishly does not talk to the Kubernetes API. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.labels | object | `{}` | Labels. |
| serviceAccount.name | string | `""` | Name (default: the full name, or "default" when create is false). |
| startupProbe | object | `{"enabled":true,"failureThreshold":30,"httpGet":{"path":"/healthz","port":"http"},"periodSeconds":2,"timeoutSeconds":3}` | Startup probe. /healthz answers 200 when Redis accepts writes. |
| templates.binaryFiles | object | `{}` | Binary template files by path, base64 encoded (`my-brand/assets/logo.png: iVBOR...`). |
| templates.copy.image | object | `{}` | Image of the init container that copies the files (default: the Vanishly image). |
| templates.copy.resources | object | `{"limits":{"memory":"32Mi"},"requests":{"cpu":"10m","memory":"16Mi"}}` | Resources of the copy init container. |
| templates.existingConfigMaps | list | `[]` | Existing ConfigMaps with template files; each `{name, items: [{key, path}]}` (path below TEMPLATES_DIR). |
| templates.files | object | `{}` | Text template files by path below TEMPLATES_DIR, e.g. `my-brand/theme.css` with the CSS as value. |
| templates.sizeLimit | string | `"32Mi"` | Size limit of the emptyDir that holds the copied files. |
| templates.volume | object | `{}` | A volume source mounted directly at TEMPLATES_DIR instead (e.g. `persistentVolumeClaim: {claimName: x}`), not with files/existingConfigMaps. Its files must be plain files. |
| terminationGracePeriodSeconds | int | `30` | Seconds between SIGTERM and SIGKILL (Vanishly stops within 5 s). |
| tests.enabled | bool | `true` | Create the `helm test` pod that checks /healthz through the Service. |
| tests.image | object | `{}` | Image of the test pod (default: the Vanishly image). |
| tmpSizeLimit | string | `"64Mi"` | Size limit of the emptyDir at /tmp. |
| tolerations | list | `[]` | Tolerations. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints; an entry without labelSelector gets the pod's selector labels. |
| updateStrategy | object | `{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":0},"type":"RollingUpdate"}` | Deployment strategy. |

## Development

`helm lint --strict charts/vanishly`, unit tests with the
[helm-unittest](https://github.com/helm-unittest/helm-unittest) plugin
(`helm unittest charts/vanishly`), and `ct lint` / `ct install` with the
value files in `ci/`. This README is generated from `README.md.gotmpl` and
the `# --` comments of `values.yaml` with
[helm-docs](https://github.com/norwoodj/helm-docs); `values.schema.json`
checks the values. CI runs all of it (`.github/workflows/chart.yml`).
