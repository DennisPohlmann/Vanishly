#!/bin/sh
# Builds the vanishly command line binaries for every platform into $1
# (default downloads/ of the app), reproducibly: the same source, version and Go
# release give the same bytes, so a binary from the Vanishly server has the
# checksum of the one signed in the GitHub release.
#
#   clients/go/build.sh [out dir] [version]
# The Dockerfile (stage "clients") and the CI use this script.
set -eu
cd "$(dirname "$0")"
out=${1:-../../downloads}
version=${2:-$(cat ../../VERSION)}
case "$version" in *[!A-Za-z0-9.+_-]*) echo "bad version: $version" >&2; exit 2 ;; esac
mkdir -p "$out"
# os/arch[/arm version]; file names use macos for darwin and armv6/armv7 for arm.
for t in linux/amd64 linux/386 linux/arm64 linux/arm/7 linux/arm/6 \
         windows/amd64 windows/386 windows/arm64 \
         darwin/amd64 darwin/arm64 \
         freebsd/amd64 freebsd/386 freebsd/arm64 freebsd/arm/7; do
  os=${t%%/*}; rest=${t#*/}; arch=${rest%%/*}; arm=
  [ "$arch" = arm ] && arm=${rest#arm/} && arch=armv$arm
  name=vanishly-$( [ "$os" = darwin ] && echo macos || echo "$os" )-$arch
  [ "$os" = windows ] && name=$name.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=${rest%%/*} GOARM=$arm \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X github.com/DennisPohlmann/vanishly/clients/go/v4.Version=$version" \
      -o "$out/$name" ./cmd/vanishly
done
ls -l "$out"
