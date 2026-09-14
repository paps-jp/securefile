#!/usr/bin/env bash
# First-time setup, run as root inside the container.
#
# Idempotent: running it again on an existing host updates the unit and leaves
# the data directory alone.
set -euo pipefail

BIN_SRC="${1:?usage: provision.sh <path-to-securefile-binary>}"

if ! id securefile >/dev/null 2>&1; then
  # A system account with no shell and no home: the service needs an identity
  # to own its files, not a login.
  useradd --system --no-create-home --shell /usr/sbin/nologin securefile
fi

install -m 0755 -o root -g root "$BIN_SRC" /usr/local/bin/securefile

install -d -m 0750 -o root -g securefile /etc/securefile
if [ ! -f /etc/securefile/securefile.env ]; then
  install -m 0640 -o root -g securefile \
    "$(dirname "$0")/securefile.env.example" /etc/securefile/securefile.env
  echo "wrote /etc/securefile/securefile.env — review it before starting"
fi

install -d -m 0700 -o securefile -g securefile /var/lib/securefile

install -m 0644 "$(dirname "$0")/securefile.service" /etc/systemd/system/securefile.service
systemctl daemon-reload
systemctl enable securefile

echo "provisioned. start with: systemctl start securefile"
