#!/bin/sh
# Sets the version of every client library to $1 (semantic-release calls it,
# see .releaserc.json); tests/clients.test.js checks they equal VERSION.
set -eu
v=$1
case "$v" in *[!0-9A-Za-z.+-]*|'') echo "bad version: $v" >&2; exit 2 ;; esac
cd "$(dirname "$0")"
sed -i -E "s/^version = \"[^\"]*\"/version = \"$v\"/" python/pyproject.toml
sed -i -E "s/^__version__ = \"[^\"]*\"/__version__ = \"$v\"/" python/src/vanishly/__init__.py
sed -i -E "s/^var Version = \"[^\"]*\"/var Version = \"$v\"/" go/client.go
# Go: from v2 on the module path ends in /v<major> (go get refuses the tag otherwise).
major=${v%%.*}
suffix=; [ "$major" -ge 2 ] 2>/dev/null && suffix=/v$major
for f in go/go.mod go/cmd/vanishly/main.go go/build.sh go/README.md ../views/downloads.html ../docs/CLIENTS.md; do
  [ -f "$f" ] && sed -i -E "s#github\.com/DennisPohlmann/vanishly/clients/go(/v[0-9]+)?#github.com/DennisPohlmann/vanishly/clients/go$suffix#g" "$f"
done
true
