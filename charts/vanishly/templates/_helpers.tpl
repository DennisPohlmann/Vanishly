{{/* Names */}}
{{- define "vanishly.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vanishly.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vanishly.redis.fullname" -}}
{{- printf "%s-redis" (include "vanishly.fullname" . | trunc 57 | trimSuffix "-") -}}
{{- end -}}

{{- define "vanishly.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "vanishly.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels */}}
{{- define "vanishly.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vanishly.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: app
{{- end -}}

{{- define "vanishly.redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vanishly.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: redis
{{- end -}}

{{/* Labels of every object without the component; commonLabels win. */}}
{{- define "vanishly.baseLabels" -}}
{{- $labels := dict
  "helm.sh/chart" (include "vanishly.chart" .)
  "app.kubernetes.io/name" (include "vanishly.name" .)
  "app.kubernetes.io/instance" .Release.Name
  "app.kubernetes.io/version" (include "vanishly.imageTag" .)
  "app.kubernetes.io/managed-by" .Release.Service
  "app.kubernetes.io/part-of" "vanishly" -}}
{{- toYaml (merge (include "vanishly.tplvalues" (dict "value" .Values.commonLabels "context" .) | fromYaml) $labels) -}}
{{- end -}}

{{/* Labels of an object. Usage: include "vanishly.labels" (dict "context" $ "component" "app" "extra" .Values.service.labels) */}}
{{- define "vanishly.labels" -}}
{{- $ctx := .context -}}
{{- $labels := include "vanishly.baseLabels" $ctx | fromYaml -}}
{{- $_ := set $labels "app.kubernetes.io/component" (default "app" .component) -}}
{{- $extra := include "vanishly.tplvalues" (dict "value" (default (dict) .extra) "context" $ctx) | fromYaml -}}
{{- toYaml (mergeOverwrite $labels $extra) -}}
{{- end -}}

{{/* Annotations of an object: commonAnnotations plus the object's own. Prints nothing when empty. */}}
{{- define "vanishly.annotations" -}}
{{- $ctx := .context -}}
{{- $common := include "vanishly.tplvalues" (dict "value" $ctx.Values.commonAnnotations "context" $ctx) | fromYaml -}}
{{- $extra := include "vanishly.tplvalues" (dict "value" (default (dict) .extra) "context" $ctx) | fromYaml -}}
{{- $all := mergeOverwrite (dict) $common $extra -}}
{{- if $all -}}
annotations:
  {{- toYaml $all | nindent 2 }}
{{- end -}}
{{- end -}}

{{/* Standard metadata block. Usage: include "vanishly.metadata" (dict "context" $ "name" "x" "component" "app" "labels" .. "annotations" ..) */}}
{{- define "vanishly.metadata" -}}
metadata:
  name: {{ .name }}
  namespace: {{ include "vanishly.namespace" .context }}
  labels:
    {{- include "vanishly.labels" (dict "context" .context "component" .component "extra" .labels) | nindent 4 }}
  {{- with include "vanishly.annotations" (dict "context" .context "extra" .annotations) }}
  {{- . | nindent 2 }}
  {{- end }}
{{- end -}}

{{/* Renders a value (map, list or string) with tpl. Usage: include "vanishly.tplvalues" (dict "value" .Values.x "context" $) */}}
{{- define "vanishly.tplvalues" -}}
{{- if kindIs "string" .value -}}
{{- tpl .value .context -}}
{{- else if .value -}}
{{- tpl (toYaml .value) .context -}}
{{- end -}}
{{- end -}}

{{/*
Prints an object after merging overrides.<key> into it.
Usage: include "vanishly.render" (dict "context" $ "key" "deployment" "object" (include "x" $))
*/}}
{{- define "vanishly.render" -}}
{{- $obj := fromYaml .object -}}
{{- if hasKey $obj "Error" -}}
{{- fail (printf "vanishly: internal error rendering %s: %s" .key (get $obj "Error")) -}}
{{- end -}}
{{- $override := get (default (dict) .context.Values.overrides) .key -}}
{{- if $override -}}
{{- $obj = mergeOverwrite $obj (deepCopy $override) -}}
{{- end -}}
{{- toYaml $obj -}}
{{- end -}}

{{/* Images */}}
{{- define "vanishly.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag | toString | trunc 63 | replace "+" "_" -}}
{{- end -}}

{{/* Usage: include "vanishly.imageRef" (dict "image" .Values.image "global" .Values.global "defaultTag" "x") */}}
{{- define "vanishly.imageRef" -}}
{{- $registry := default .image.registry .global.imageRegistry -}}
{{- $repo := .image.repository -}}
{{- if $registry -}}{{- $repo = printf "%s/%s" $registry $repo -}}{{- end -}}
{{- if .image.digest -}}
{{- printf "%s@%s" $repo .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (toString (default .defaultTag .image.tag)) -}}
{{- end -}}
{{- end -}}

{{- define "vanishly.image" -}}
{{- include "vanishly.imageRef" (dict "image" .Values.image "global" .Values.global "defaultTag" .Chart.AppVersion) -}}
{{- end -}}

{{- define "vanishly.redis.image" -}}
{{- include "vanishly.imageRef" (dict "image" .Values.redis.image "global" .Values.global "defaultTag" "8-alpine") -}}
{{- end -}}

{{/* The image of a helper container: its own image values, otherwise the Vanishly image. */}}
{{- define "vanishly.helperImage" -}}
{{- $ctx := .context -}}
{{- if and .image .image.repository -}}
{{- include "vanishly.imageRef" (dict "image" .image "global" $ctx.Values.global "defaultTag" "latest") -}}
{{- else -}}
{{- include "vanishly.image" $ctx -}}
{{- end -}}
{{- end -}}

{{- define "vanishly.imagePullSecrets" -}}
{{- $secrets := concat (default (list) .Values.global.imagePullSecrets) (default (list) .extra) -}}
{{- with $secrets }}
imagePullSecrets:
  {{- range . }}
  {{- if kindIs "string" . }}
  - name: {{ . }}
  {{- else }}
  - {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{- define "vanishly.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vanishly.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Settings */}}
{{- define "vanishly.port" -}}
{{- $p := toString (default "" .Values.config.PORT) -}}
{{- if $p }}{{ $p }}{{ else }}3000{{ end -}}
{{- end -}}

{{- define "vanishly.templatesDir" -}}
{{- $d := toString (default "" .Values.config.TEMPLATES_DIR) -}}
{{- if $d }}{{ $d }}{{ else }}/var/lib/vanishly/templates{{ end -}}
{{- end -}}

{{/* BASE_URL from the first ingress or httpRoute host when not set. */}}
{{- define "vanishly.baseUrl" -}}
{{- $set := toString (default "" .Values.config.BASE_URL) -}}
{{- if $set -}}
{{- $set -}}
{{- else if .Values.baseUrlFromIngress -}}
{{- if and .Values.ingress.enabled .Values.ingress.hosts (first .Values.ingress.hosts).host -}}
{{- printf "https://%s" (tpl (first .Values.ingress.hosts).host .) -}}
{{- else if and .Values.httpRoute.enabled .Values.httpRoute.hostnames -}}
{{- printf "https://%s" (tpl (first .Values.httpRoute.hostnames) .) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Redis */}}
{{- define "vanishly.redis.passwordSecretName" -}}
{{- default (include "vanishly.redis.fullname" .) .Values.redis.auth.existingSecret -}}
{{- end -}}

{{- define "vanishly.redis.passwordSecretKey" -}}
{{- if .Values.redis.auth.existingSecret -}}
{{- .Values.redis.auth.existingSecretPasswordKey -}}
{{- else -}}
redis-password
{{- end -}}
{{- end -}}

{{/* The password of the bundled Redis: from values, from the Secret of an earlier install, or new. */}}
{{- define "vanishly.redis.password" -}}
{{- if .Values.redis.auth.password -}}
{{- .Values.redis.auth.password -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" (include "vanishly.namespace" .) (include "vanishly.redis.fullname" .) -}}
{{- if and $existing $existing.data (index $existing.data "redis-password") -}}
{{- index $existing.data "redis-password" | b64dec -}}
{{- else -}}
{{- randAlphaNum 40 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Where REDIS_URL comes from: secret name and key. */}}
{{- define "vanishly.redisUrlSecretName" -}}
{{- if and (not .Values.redis.enabled) .Values.redis.external.existingSecret -}}
{{- .Values.redis.external.existingSecret -}}
{{- else -}}
{{- printf "%s-redis-url" (include "vanishly.fullname" . | trunc 53 | trimSuffix "-") -}}
{{- end -}}
{{- end -}}

{{- define "vanishly.redisUrlSecretKey" -}}
{{- if and (not .Values.redis.enabled) .Values.redis.external.existingSecret -}}
{{- .Values.redis.external.existingSecretUrlKey -}}
{{- else -}}
redis-url
{{- end -}}
{{- end -}}

{{/* The settings of the ConfigMap: non-empty config values plus a derived BASE_URL. */}}
{{- define "vanishly.configData" -}}
{{- $data := dict -}}
{{- range $k, $v := .Values.config -}}
{{- if and (ne $k "REDIS_URL") (not (kindIs "invalid" $v)) (ne (toString $v) "") -}}
{{- $_ := set $data $k (toString $v) -}}
{{- end -}}
{{- end -}}
{{- with include "vanishly.baseUrl" . -}}
{{- $_ := set $data "BASE_URL" . -}}
{{- end -}}
{{- toYaml $data -}}
{{- end -}}

{{/* Template files: true when files go through the copy init container. */}}
{{- define "vanishly.templates.copied" -}}
{{- if or .Values.templates.files .Values.templates.binaryFiles .Values.templates.existingConfigMaps -}}true{{- end -}}
{{- end -}}

{{/* A ConfigMap key for a template path (keys cannot hold "/"). */}}
{{- define "vanishly.templates.key" -}}
{{- printf "f-%s" (sha256sum . | trunc 24) -}}
{{- end -}}

{{/* Fills in the selector of topology spread constraints without one. */}}
{{- define "vanishly.topologySpread" -}}
{{- $out := list -}}
{{- range .constraints -}}
{{- $c := deepCopy . -}}
{{- if not $c.labelSelector -}}
{{- $_ := set $c "labelSelector" (dict "matchLabels" ($.selector | fromYaml)) -}}
{{- end -}}
{{- $out = append $out $c -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* A probe: the values without "enabled"; the handler is kept as given. */}}
{{- define "vanishly.probe" -}}
{{- toYaml (omit . "enabled") -}}
{{- end -}}
