#!/usr/bin/env bash
# apps/webserver/dev_certs/regen.sh — regenerate the dev cert + key.
#
# Usage: ./regen.sh  (run from this directory or let it cd into itself)
#
# Produces four files in this directory:
#   dev_key.pem  dev_key.der   — PKCS#8 Ed25519 private key
#   dev_cert.pem dev_cert.der  — X.509 v3 self-signed CA
#
# The .der files are loaded into the unikernel binary via include_bytes!;
# the .pem files exist for host-side `curl` / `openssl s_client` tests.
#
# DO NOT USE IN PRODUCTION. See README.md.

set -euo pipefail
cd "$(dirname "$0")"

# 10-year validity so CI doesn't break on expiry.
DAYS=3650
SUBJECT="/CN=unikernel.local/O=UniKernel Dev/OU=Development Only"
SAN="subjectAltName=DNS:unikernel.local,DNS:localhost,IP:127.0.0.1,IP:10.0.2.15"

echo "==> Generating Ed25519 private key..."
openssl genpkey -algorithm ED25519 -out dev_key.pem

echo "==> Generating self-signed X.509 certificate ($DAYS days)..."
openssl req -new -x509 -key dev_key.pem -out dev_cert.pem -days "$DAYS" \
    -subj "$SUBJECT" \
    -addext "$SAN"

echo "==> Exporting DER forms..."
openssl pkey -in dev_key.pem  -outform DER -out dev_key.der
openssl x509 -in dev_cert.pem -outform DER -out dev_cert.der

echo ""
echo "Files:"
ls -la dev_key.{pem,der} dev_cert.{pem,der}

echo ""
echo "Certificate summary:"
openssl x509 -in dev_cert.pem -noout -subject -issuer -dates -ext subjectAltName
