#!/usr/bin/env bash
# Runs locally what the CI runs on every push (build.yml job "check",
# image-scan, package, and chart.yml), so a broken build does not get pushed.
# Installed as git pre-push hook by `make hooks`.
#
#   tools/check-all.sh          everything that works on this machine
#   tools/check-all.sh --fast   without accessibility, image and chart install
#
# Needs Node.js and npm; Redis via REDIS_URL, a redis-server in PATH or
# Docker. Docker, Trivy, Helm (with helm-unittest), helm-docs, kubeconform and
# actionlint are used when installed; what is missing is listed at the end
# and left to the CI. Not checked locally at all: ct install in a kind
# cluster, multi-arch images, publishing.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

export NPM_CONFIG_UPDATE_NOTIFIER=false
skipped=()
cleanup=()
on_exit() {
  local c
  for c in "${cleanup[@]+"${cleanup[@]}"}"; do eval "$c" || true; done
}
trap on_exit EXIT

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
docker_ok() { have docker && docker info >/dev/null 2>&1; }
skip() { skipped+=("$1"); printf '    skipped: %s\n' "$1"; }

if [ -n "$(git status --porcelain)" ]; then
  echo "note: uncommitted changes; this checks the working tree, not only what is pushed."
fi

step "whitespace (git diff --check)"
git diff --check "$(git hash-object -t tree /dev/null)"

step "npm ci, vendor"
npm ci --no-fund --no-audit
npm run vendor

step "type check (tsc)"
npm run lint

step "known vulnerabilities in the production dependencies"
npm audit --omit=dev --audit-level=high

# Redis for the API and accessibility tests: REDIS_URL, else a throwaway
# redis-server or container on a free port.
if [ -z "${REDIS_URL:-}" ]; then
  port=$(node -e 'const s=require("net").createServer().listen(0,()=>{console.log(s.address().port);s.close()})')
  if have redis-server; then
    redis-server --port "$port" --save "" --appendonly no --bind 127.0.0.1 >/dev/null &
    cleanup+=("kill $!")
  elif docker_ok; then
    cid=$(docker run -d --rm -p "127.0.0.1:$port:6379" redis:8-alpine)
    cleanup+=("docker stop $cid >/dev/null")
  else
    echo "error: tests need Redis: set REDIS_URL, install redis-server or start Docker." >&2
    exit 1
  fi
  export REDIS_URL="redis://127.0.0.1:$port"
  for _ in $(seq 50); do
    node -e 'const n=require("net").connect(+process.argv[1],"127.0.0.1",()=>process.exit(0));n.on("error",()=>process.exit(1))' "$port" && break
    sleep 0.1
  done
fi

step "tests"
npm test

step "OpenAPI document"
npx --yes @redocly/cli@2.77.0 lint --extends=minimal openapi/openapi.json

if [ "$FAST" = 1 ]; then
  skip "accessibility (--fast)"
else
  step "accessibility"
  npx playwright install chromium
  npm run test:a11y
fi

step "package (make package)"
make package

if have actionlint; then
  step "workflows (actionlint)"
  actionlint
else
  skip "actionlint (not installed)"
fi

if have trivy; then
  step "Trivy: Dockerfile and repository"
  trivy config --severity HIGH,CRITICAL --exit-code 1 .
  trivy fs --scanners vuln,secret,misconfig --skip-dirs node_modules \
    --severity HIGH,CRITICAL --exit-code 1 .
else
  skip "Trivy scans (not installed)"
fi

if [ "$FAST" = 1 ]; then
  skip "image build (--fast)"
elif docker_ok; then
  step "image build"
  docker build --build-arg VERSION=check -t vanishly:check .
  if have trivy; then
    trivy image --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 vanishly:check
  fi
else
  skip "image build (Docker not available)"
fi

if have helm; then
  step "Helm chart"
  helm lint --strict charts/vanishly
  for f in charts/vanishly/ci/*-values.yaml; do helm lint --strict charts/vanishly -f "$f"; done
  if helm plugin list 2>/dev/null | grep -q unittest; then
    helm unittest --strict charts/vanishly
  else
    skip "helm unittest (plugin not installed)"
  fi
  if have helm-docs; then
    helm-docs --chart-search-root charts >/dev/null
    git diff --exit-code -- charts/vanishly/README.md || {
      echo "error: charts/vanishly/README.md is out of date (helm-docs --chart-search-root charts)" >&2; exit 1; }
  else
    skip "helm-docs (not installed)"
  fi
  if have kubeconform; then
    for f in charts/vanishly/ci/*-values.yaml; do
      helm template vanishly charts/vanishly -f "$f" --kube-version 1.33.0 |
        kubeconform -strict -summary -kubernetes-version 1.33.0 -schema-location default \
          -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
    done
  else
    skip "kubeconform (not installed)"
  fi
  helm package charts/vanishly --destination dist >/dev/null
else
  skip "Helm chart checks (helm not installed)"
fi

step "done"
if [ ${#skipped[@]} -gt 0 ]; then
  echo "All checks passed. Left to the CI:"
  printf '  - %s\n' "${skipped[@]}" "ct install in kind (always CI only)"
else
  echo "All checks passed. Left to the CI: ct install in kind."
fi
