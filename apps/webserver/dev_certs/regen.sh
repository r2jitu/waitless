#!/usr/bin/env bash
# apps/webserver/dev_certs/regen.sh — regenerate this app's dev cert.
#
# Thin wrapper over the generic scripts/regen-dev-cert.sh: it just
# supplies this app's output directory and SAN list. See that script
# for the ECDSA-P-256 rationale and README.md here for the rest.
#
# Produces dev_cert.{pem,der} + dev_key.{pem,der} in this directory.
# DO NOT USE IN PRODUCTION.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

exec "$HERE/../../../scripts/regen-dev-cert.sh" \
    "$HERE" \
    waitless.local localhost 127.0.0.1 10.0.2.15
