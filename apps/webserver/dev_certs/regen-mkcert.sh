#!/usr/bin/env bash
# apps/webserver/dev_certs/regen-mkcert.sh — regenerate the dev cert
# using mkcert's locally-installed root CA.
#
# Browsers (Chrome, Arc, Edge, Safari, Firefox-with-mkcert-install)
# refuse self-signed dev certs with a hard "Not Secure" / NET::ERR_*
# screen, so reaching `https://localhost:18443` from a browser fails
# with the bundled `regen.sh` cert.
#
# mkcert sidesteps that by issuing a leaf cert from a per-user root
# CA that gets installed into every browser's trust store via
# `mkcert -install`. Run this script once, rebuild the webserver, and
# the same `https://localhost` / `https://[::1]` URLs work in Chrome
# without any in-app warning.
#
# Prerequisites: `brew install mkcert nss && mkcert -install` (the
# `nss` step is only needed for Firefox).
#
# This script overwrites `dev_cert.{pem,der}` and `dev_key.{pem,der}`
# in this directory — the same files `regen.sh` writes — so the
# unikernel's `include_bytes!("../dev_certs/dev_cert.der")` picks
# them up on the next build with no source changes.
#
# To revert to the committed self-signed dev cert, run
# `git checkout apps/webserver/dev_certs/dev_{cert,key}.{pem,der}`.

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v mkcert >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: mkcert is not on PATH.

Install it first:
    brew install mkcert nss
    mkcert -install   # writes the local CA into the system + browser trust stores

Then re-run this script.
EOF
    exit 1
fi

# Same SAN list as regen.sh, plus `[::1]` so the v6 reachability tests
# (`test_http_health_v6` etc.) work against an mkcert-issued cert too.
SANS=(
    waitless.local
    localhost
    127.0.0.1
    ::1
    10.0.2.15
)

echo "==> Generating mkcert-signed leaf (ECDSA P-256)..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# mkcert names its outputs `<first-san>+N.pem` / `<first-san>+N-key.pem`.
# Using a temp dir keeps the working directory tidy regardless of the
# SAN-count math.
(
    cd "$TMP"
    mkcert -ecdsa \
        -cert-file dev_cert.pem \
        -key-file dev_key.pem \
        "${SANS[@]}"
)

cp "$TMP/dev_cert.pem" dev_cert.pem
cp "$TMP/dev_key.pem" dev_key.pem

echo "==> Exporting DER forms..."
openssl pkey -in dev_key.pem -outform DER -out dev_key.der
openssl x509 -in dev_cert.pem -outform DER -out dev_cert.der

echo
echo "Files:"
ls -la dev_key.{pem,der} dev_cert.{pem,der}

echo
echo "Issuer (should be your mkcert root):"
openssl x509 -in dev_cert.pem -noout -issuer

echo
echo "SANs:"
openssl x509 -in dev_cert.pem -noout -ext subjectAltName

echo
echo "Done. Rebuild + restart the webserver:"
echo "    bazel run //apps/webserver:run"
echo
echo "Chrome should now show a green padlock for https://localhost:<port>."
