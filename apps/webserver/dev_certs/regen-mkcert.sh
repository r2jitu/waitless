#!/usr/bin/env bash
# apps/webserver/dev_certs/regen-mkcert.sh — regenerate this app's dev
# cert from mkcert's locally-installed root CA, so browsers trust it.
#
# Thin wrapper over `scripts/regen-dev-cert.sh --mkcert`: it supplies
# this app's output directory and SAN list (the same SANs as regen.sh
# plus `::1` for the IPv6 reachability tests). See that script and
# README.md here for the full story.
#
# Prerequisites: `brew install mkcert nss && mkcert -install`.
# To revert to the committed self-signed cert:
#   git checkout apps/webserver/dev_certs/dev_{cert,key}.{pem,der}

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

exec "$HERE/../../../scripts/regen-dev-cert.sh" --mkcert \
    "$HERE" \
    waitless.local localhost 127.0.0.1 ::1 10.0.2.15
