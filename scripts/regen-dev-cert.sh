#!/usr/bin/env bash
# regen-dev-cert.sh — (re)generate a self-signed dev TLS cert + key.
#
# Writes dev_cert.{pem,der} and dev_key.{pem,der} into an output
# directory: the DER pair is what a unikernel app `include_bytes!`s,
# the PEM pair is for host-side `curl` / `openssl s_client`.
#
# The cert is ECDSA P-256 + SHA-256 — deliberately NOT Ed25519:
# Chromium-family browsers don't advertise ed25519 for server-auth in
# their TLS 1.3 signature_algorithms, so an Ed25519 CertVerify fails
# with illegal_parameter(47); macOS LibreSSL also refuses Ed25519
# verification. P-256 is first in every modern client's list.
#
# Usage:
#   regen-dev-cert.sh [--mkcert] <out-dir> [SAN ...]
#
#   --mkcert   issue from the locally-installed mkcert root CA so
#              browsers trust the cert directly (needs
#              `brew install mkcert nss` + `mkcert -install`). Default
#              is a plain self-signed cert — fine for `curl --cacert`
#              and host-side test code.
#   <out-dir>  directory to write the four files into (created if
#              absent).
#   SAN ...    subject-alternative names — bare hostnames or IPs, each
#              auto-classified DNS:/IP:. Default:
#              waitless.local localhost 127.0.0.1 ::1 10.0.2.15
#
# This is the generic mechanism; per-app `dev_certs/regen.sh` wrappers
# call it with that app's output dir and SAN list. DO NOT USE IN
# PRODUCTION — real certs come from scripts/issue-cert.sh.

set -euo pipefail

MKCERT=0
if [ "${1:-}" = "--mkcert" ]; then
    MKCERT=1
    shift
fi

OUT_DIR="${1:-}"
if [ -z "$OUT_DIR" ]; then
    echo "Usage: $0 [--mkcert] <out-dir> [SAN ...]" >&2
    exit 1
fi
shift

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

SANS=("$@")
if [ "${#SANS[@]}" -eq 0 ]; then
    SANS=(waitless.local localhost 127.0.0.1 ::1 10.0.2.15)
fi

command -v openssl >/dev/null 2>&1 ||
    { echo "Error: 'openssl' not found (brew install openssl)" >&2; exit 1; }

if [ "$MKCERT" = 1 ]; then
    if ! command -v mkcert >/dev/null 2>&1; then
        echo "Error: mkcert not on PATH —" \
            "brew install mkcert nss && mkcert -install" >&2
        exit 1
    fi
    echo "==> mkcert-signed leaf (ECDSA P-256) for: ${SANS[*]}"
    # mkcert names outputs after the first SAN; a temp dir keeps the
    # output directory tidy regardless of that naming.
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    (
        cd "$TMP"
        mkcert -ecdsa \
            -cert-file dev_cert.pem -key-file dev_key.pem "${SANS[@]}"
    )
    cp "$TMP/dev_cert.pem" "$OUT_DIR/dev_cert.pem"
    cp "$TMP/dev_key.pem" "$OUT_DIR/dev_key.pem"
else
    # Build openssl's subjectAltName value, classifying each entry: an
    # IPv4 dotted-quad or anything containing ':' (IPv6) becomes IP:,
    # everything else DNS:.
    san=""
    for s in "${SANS[@]}"; do
        if [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$s" == *:* ]]; then
            san="${san:+$san,}IP:$s"
        else
            san="${san:+$san,}DNS:$s"
        fi
    done
    echo "==> self-signed cert (ECDSA P-256, 10 yr) for: ${SANS[*]}"
    openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve \
        -out "$OUT_DIR/dev_key.pem"
    openssl req -new -x509 -key "$OUT_DIR/dev_key.pem" \
        -out "$OUT_DIR/dev_cert.pem" -days 3650 \
        -subj "/CN=${SANS[0]}/O=Waitless Dev/OU=Development Only" \
        -addext "subjectAltName=$san" \
        -sha256
fi

echo "==> Exporting DER forms → $OUT_DIR"
openssl pkey -in "$OUT_DIR/dev_key.pem" -outform DER -out "$OUT_DIR/dev_key.der"
openssl x509 -in "$OUT_DIR/dev_cert.pem" -outform DER -out "$OUT_DIR/dev_cert.der"

echo ""
echo "Files:"
ls -la "$OUT_DIR"/dev_key.{pem,der} "$OUT_DIR"/dev_cert.{pem,der}
echo ""
echo "Certificate:"
openssl x509 -in "$OUT_DIR/dev_cert.pem" -noout \
    -subject -issuer -dates -ext subjectAltName 2>&1 | sed 's/^/    /'
