#!/usr/bin/env bash
# Cross-compiles a static Linux binary.
#
# CGO is off, so the result has no libc dependency and runs on any glibc or
# musl container image regardless of what it was built on. This is only
# possible because the SQLite driver is the pure-Go one.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
OUT="${1:-dist/securefile}"

mkdir -p "$(dirname "$OUT")"

# The production binary includes the operator admin dashboard and the imported
# -shares (legacy) subsystem, both behind build tags. The public open-source
# build omits these tags and ships without them.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -tags 'admin legacy' \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$OUT" ./cmd/securefile

echo "built ${OUT} (${VERSION})"
ls -lh "$OUT"
