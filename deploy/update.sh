#!/usr/bin/env bash
# Replaces the binary and restarts, run as root inside the container.
#
# The binary is swapped with install(1), which writes to a temporary file and
# renames it into place. A rename is atomic, so a request being served during
# the update never sees a half-written executable.
set -euo pipefail

BIN_SRC="${1:?usage: update.sh <path-to-securefile-binary>}"

install -m 0755 -o root -g root "$BIN_SRC" /usr/local/bin/securefile
systemctl restart securefile

sleep 1
systemctl --no-pager --lines=0 status securefile
