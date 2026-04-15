#!/usr/bin/env bash
# apps/webserver/dev_certs/regen.sh — regenerate the dev cert + key.
#
# Usage: ./regen.sh  (run from this directory or let it cd into itself)
#
# Produces four files in this directory:
#   dev_key.pem  dev_key.der   — PKCS#8 ECDSA P-256 private key
#   dev_cert.pem dev_cert.der  — X.509 v3 self-signed cert
#
# The .der files are loaded into the unikernel binary via include_bytes!;
# the .pem files exist for host-side `curl` / `openssl s_client` tests.
#
# Why ECDSA P-256 and not Ed25519: Chromium-family browsers (Chrome,
# Arc, Edge, Brave, ...) don't advertise `ed25519` in their TLS 1.3
# `signature_algorithms` extension for server-auth signatures, so an
# Ed25519-signed CertVerify triggers `illegal_parameter(47)` and the
# browser shows ERR_SSL_PROTOCOL_ERROR. ECDSA P-256 + SHA-256 is the
# first scheme in every modern client's preference list, and also
# works with macOS's bundled LibreSSL (which refuses Ed25519 verify).
#
# DO NOT USE IN PRODUCTION. See README.md.

set -euo pipefail
cd "$(dirname "$0")"

# 10-year validity so CI doesn't break on expiry.
DAYS=3650
SUBJECT="/CN=unikernel.local/O=UniKernel Dev/OU=Development Only"
SAN="subjectAltName=DNS:unikernel.local,DNS:localhost,IP:127.0.0.1,IP:10.0.2.15"

echo "==> Generating ECDSA P-256 private key..."
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve \
    -out dev_key.pem

echo "==> Generating self-signed X.509 certificate ($DAYS days)..."
openssl req -new -x509 -key dev_key.pem -out dev_cert.pem -days "$DAYS" \
    -subj "$SUBJECT" \
    -addext "$SAN" \
    -sha256

echo "==> Exporting DER forms..."
openssl pkey -in dev_key.pem  -outform DER -out dev_key.der
openssl x509 -in dev_cert.pem -outform DER -out dev_cert.der

echo ""
echo "Files:"
ls -la dev_key.{pem,der} dev_cert.{pem,der}

echo ""
echo "Certificate summary:"
openssl x509 -in dev_cert.pem -noout -subject -issuer -dates -ext subjectAltName \
    -text 2>&1 | grep -E "Signature Algorithm|Public Key Algorithm|NIST CURVE"
