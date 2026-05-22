#!/usr/bin/env bash
# issue-cert.sh — obtain a TLS certificate for the webserver via ACME
# and stage it for a production build.
#
# The unikernel deliberately ships no ACME client: no outbound TCP
# client, no JSON/DER/JWS, no persistence — and ACME-on-boot would
# burn Let's Encrypt's 5-duplicate-certs/week rate limit on every
# reboot. Issuance is externalised here instead.
#
# This script runs `lego` with the DNS-01 challenge. DNS-01 (vs
# HTTP-01) is what lets the unikernel stay ACME-free: the challenge
# is proved by a TXT record, so the server never has to answer an
# HTTP-01 request and needs no challenge handler. It also works
# before the endpoint is reachable at all — useful for a first
# deploy.
#
# Output: leaf.der, intermediate.der, key.der (PKCS#8) written into
# apps/webserver/prod_certs/. A `--define tls_cert=prod` build bakes
# them in (see apps/webserver/BUILD.bazel). The files are gitignored
# — issuance never edits tracked source.
#
# Usage:
#   ./scripts/issue-cert.sh staging   # Let's Encrypt staging (default)
#   ./scripts/issue-cert.sh prod      # Let's Encrypt production
#
# Staging first: the staging CA has far looser rate limits, so use it
# to validate the whole pipeline (issue → build → deploy → curl)
# before spending a production issuance. Staging certs chain to an
# untrusted root — `curl --cacert` against the staging root, or
# `curl -k`, to verify the live endpoint.
#
# Prerequisites:
#   brew install lego openssl
#   A DNS provider lego can drive. This script uses Google Cloud DNS
#   (the project already deploys on GCE) — the domain's zone must be
#   hosted there.
#
# Required env:
#   WAITLESS_CERT_DOMAIN   fully-qualified domain for the cert
#   WAITLESS_CERT_EMAIL    ACME account email (expiry notices)
#   GCE_PROJECT            GCP project hosting the Cloud DNS zone
#
# Optional env:
#   GCE_SERVICE_ACCOUNT_FILE  path to a service-account JSON key with
#                             the DNS Administrator role. If unset,
#                             lego falls back to application-default
#                             credentials (`gcloud auth
#                             application-default login`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-staging}"
case "$MODE" in
staging)
    ACME_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
    ;;
prod)
    ACME_SERVER="https://acme-v02.api.letsencrypt.org/directory"
    ;;
*)
    echo "Usage: $0 {staging|prod}" >&2
    exit 1
    ;;
esac

# --- Validate environment -------------------------------------------------

_require() {
    local var="$1"
    if [ -z "${!var:-}" ]; then
        echo "Error: required env var $var is not set (see script header)" >&2
        exit 1
    fi
}
_require WAITLESS_CERT_DOMAIN
_require WAITLESS_CERT_EMAIL
_require GCE_PROJECT

for tool in lego openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: '$tool' not found — install it (brew install lego openssl)" >&2
        exit 1
    fi
done

DOMAIN="$WAITLESS_CERT_DOMAIN"
LEGO_DIR="/tmp/waitless-lego"
CERT_DIR="$LEGO_DIR/certificates"
OUT_DIR="$PROJECT_ROOT/apps/webserver/prod_certs"

echo "==> Issuing certificate"
echo "    domain:  $DOMAIN"
echo "    ACME CA: $MODE ($ACME_SERVER)"
echo "    DNS:     Google Cloud DNS (project $GCE_PROJECT)"

# --- Run the ACME DNS-01 flow ---------------------------------------------
#
# `--key-type EC256` matches the server: the TLS stack signs
# CertificateVerify with ECDSA P-256, and `TlsServerConfig` expects a
# P-256 PKCS#8 key. An RSA cert would not load.
#
# `GCE_PROPAGATION_TIMEOUT` is generous — Cloud DNS TXT propagation
# is usually quick but the ACME server's own resolver caching can lag.
#
# lego ≥ 5 takes the certificate flags on the `run` subcommand — only
# `--log.*` / `--config` are global — so `run` comes first.
export GCE_PROJECT
export GCE_PROPAGATION_TIMEOUT="${GCE_PROPAGATION_TIMEOUT:-300}"

# `lego run` skips issuance if a certificate for the domain already
# exists under --path, so clear any prior run's certificate files —
# every invocation must obtain a fresh cert. The ACME account in
# `accounts/` is kept and reused (account registration is itself
# rate-limited). Without this, a staging run leaves files that make a
# later `prod` run silently skip, redeploying the stale staging cert.
rm -f "$CERT_DIR/$DOMAIN".*

lego run \
    --accept-tos \
    --email "$WAITLESS_CERT_EMAIL" \
    --domains "$DOMAIN" \
    --dns gcloud \
    --key-type EC256 \
    --path "$LEGO_DIR" \
    --server "$ACME_SERVER"

# --- Convert PEM → DER and stage into prod_certs/ -------------------------
#
# lego writes PEM: `<domain>.crt` is the leaf followed by the issuer
# chain, `<domain>.issuer.crt` is the issuer (intermediate) only, and
# `<domain>.key` is the private key.
#
#   * `openssl x509` emits only the FIRST certificate of a PEM file,
#     so it extracts the leaf from `.crt` and the intermediate from
#     `.issuer.crt`.
#   * `openssl pkey -outform DER` normalises the key to a PKCS#8
#     `PrivateKeyInfo` DER — the exact shape `TlsServerConfig`'s
#     `extract_p256_d_from_pkcs8` parses (the dev cert's regen.sh
#     does the same).

mkdir -p "$OUT_DIR"

echo "==> Converting to DER → $OUT_DIR"
openssl x509 -in "$CERT_DIR/$DOMAIN.crt" \
    -outform DER -out "$OUT_DIR/leaf.der"
openssl x509 -in "$CERT_DIR/$DOMAIN.issuer.crt" \
    -outform DER -out "$OUT_DIR/intermediate.der"
openssl pkey -in "$CERT_DIR/$DOMAIN.key" \
    -outform DER -out "$OUT_DIR/key.der"

echo ""
echo "    leaf.der         $(wc -c <"$OUT_DIR/leaf.der" | tr -d ' ') bytes"
echo "    intermediate.der $(wc -c <"$OUT_DIR/intermediate.der" | tr -d ' ') bytes"
echo "    key.der          $(wc -c <"$OUT_DIR/key.der" | tr -d ' ') bytes"
echo ""
echo "Certificate summary:"
openssl x509 -in "$CERT_DIR/$DOMAIN.crt" -noout \
    -subject -issuer -dates 2>&1 | sed 's/^/    /'

echo ""
echo "Done. Build the production image with:"
echo "    bazel build //apps/webserver:webserver_iso_x86_64 --define tls_cert=prod"
echo "or run scripts/renew-and-deploy.sh to build and deploy in one step."
