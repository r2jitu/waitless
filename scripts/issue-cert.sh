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
# WAITLESS_PROD_CERTS_DIR (default apps/webserver/prod_certs/). A
# `--define tls_cert=prod` build bakes them in (see the app's
# BUILD.bazel). The files are gitignored — issuance never edits
# tracked source.
#
# Issuance is skipped when prod_certs/ already holds a certificate
# that covers the domain, matches the requested ACME environment, and
# is not yet within its renewal window: re-issuing an equivalent cert
# would only burn a Let's Encrypt rate-limit slot. This makes the
# script idempotent and safe to run unattended. WAITLESS_FORCE_ISSUE=1
# overrides it; see "Reuse an already-valid staged certificate" below.
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
#   WAITLESS_CERT_DOMAINS  space-separated FQDN list for the cert; the
#                          first is the primary (cert CN + the basename
#                          lego writes files under), the rest become
#                          extra SAN names on the one cert — e.g.
#                          "r2jitu.com www.r2jitu.com". The older
#                          single-valued WAITLESS_CERT_DOMAIN is still
#                          accepted as a fallback.
#   WAITLESS_CERT_EMAIL    ACME account email (expiry notices)
#   GCE_PROJECT            GCP project hosting the Cloud DNS zone
#
# Optional env:
#   GCE_SERVICE_ACCOUNT_FILE  path to a service-account JSON key with
#                             the DNS Administrator role. If unset,
#                             lego falls back to application-default
#                             credentials (`gcloud auth
#                             application-default login`).
#   WAITLESS_PROD_CERTS_DIR   directory the leaf/intermediate/key .der
#                             files are staged into. Default
#                             apps/webserver/prod_certs/ (the in-repo
#                             demo app); an external consumer repo
#                             points it at its own app's prod_certs/.
#   WAITLESS_RENEW_DAYS       reuse the staged cert until fewer than
#                             this many days of validity remain
#                             (default 30).
#   WAITLESS_FORCE_ISSUE      set to 1 to always issue a fresh cert,
#                             even when a valid one is already staged.

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
_require WAITLESS_CERT_EMAIL
_require GCE_PROJECT

# Domain(s) the certificate must cover. WAITLESS_CERT_DOMAINS is a
# space-separated list — the first entry is the primary (the cert CN
# and the basename lego writes its files under); any others become
# additional SAN names on the same cert. WAITLESS_CERT_DOMAIN is the
# older single-domain form, still honoured as a fallback.
_domains_raw="${WAITLESS_CERT_DOMAINS:-${WAITLESS_CERT_DOMAIN:-}}"
if [ -z "$_domains_raw" ]; then
    echo "Error: set WAITLESS_CERT_DOMAINS (space-separated) or" \
        "WAITLESS_CERT_DOMAIN (see script header)" >&2
    exit 1
fi
# shellcheck disable=SC2206  # deliberate word-split into the domain list
DOMAINS=($_domains_raw)
PRIMARY="${DOMAINS[0]}"

for tool in lego openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: '$tool' not found — install it (brew install lego openssl)" >&2
        exit 1
    fi
done

LEGO_DIR="/tmp/waitless-lego"
CERT_DIR="$LEGO_DIR/certificates"
OUT_DIR="${WAITLESS_PROD_CERTS_DIR:-$PROJECT_ROOT/apps/webserver/prod_certs}"

# --- Reuse an already-valid staged certificate ----------------------------
#
# A `--define tls_cert=prod` build bakes whatever DER files sit in
# prod_certs/ straight into the image. If that directory already holds
# a certificate that covers this domain, was issued by the requested
# ACME environment, and is not yet inside its renewal window, issuing
# again is pure waste — it spends one of Let's Encrypt's five
# duplicate-certs-per-week slots to mint an equivalent cert. Detect
# that and reuse what is staged, which also makes this script
# idempotent and safe to run on a schedule.
#
#   WAITLESS_RENEW_DAYS     re-issue once fewer than this many days of
#                           validity remain (default 30 — LE certs are
#                           valid 90 days; renewal is due around day 60).
#   WAITLESS_FORCE_ISSUE=1  always issue, ignoring any staged cert.
#
# The ACME-environment check is load-bearing, not cosmetic: staging
# and production certs share the same prod_certs/ filenames, so
# without it a prior `staging` run's cert could be silently reused for
# a `prod` deploy. Staging Let's Encrypt issuers carry "(STAGING)" in
# their name; production issuers do not.
RENEW_DAYS="${WAITLESS_RENEW_DAYS:-30}"

staged_cert_reusable() {
    local leaf="$OUT_DIR/leaf.der"
    [ -s "$leaf" ] && [ -s "$OUT_DIR/intermediate.der" ] && [ -s "$OUT_DIR/key.der" ] ||
        { echo "    prod_certs/ has no complete staged cert"; return 1; }

    openssl x509 -in "$leaf" -inform DER -noout >/dev/null 2>&1 ||
        { echo "    staged leaf.der does not parse"; return 1; }

    # Covers every requested domain? Compare whole SAN entries, not
    # substrings — a multi-name request needs all names on the one cert.
    local _san _d
    _san="$(openssl x509 -in "$leaf" -inform DER -noout \
        -ext subjectAltName 2>/dev/null | tr -d ' ' | tr ',' '\n')"
    for _d in "${DOMAINS[@]}"; do
        printf '%s\n' "$_san" | grep -Fqx "DNS:$_d" ||
            { echo "    staged cert does not cover $_d"; return 1; }
    done

    # Issued by the ACME environment we were asked for?
    local issuer
    issuer="$(openssl x509 -in "$leaf" -inform DER -noout -issuer 2>/dev/null)"
    case "$MODE:$issuer" in
    prod:*'(STAGING)'*)
        echo "    staged cert is a STAGING cert, but prod was requested"
        return 1
        ;;
    staging:*'(STAGING)'*) ;;
    staging:*)
        echo "    staged cert is a production cert, but staging was requested"
        return 1
        ;;
    esac

    # Enough validity left to skip renewal?
    openssl x509 -in "$leaf" -inform DER -noout \
        -checkend "$((RENEW_DAYS * 86400))" >/dev/null 2>&1 ||
        { echo "    staged cert expires within ${RENEW_DAYS} days — renewal is due"; return 1; }

    # Does key.der actually belong to this leaf? A mismatch builds
    # cleanly and then fails the TLS handshake at boot.
    local leaf_pub key_pub
    leaf_pub="$(openssl x509 -in "$leaf" -inform DER -noout -pubkey 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)"
    key_pub="$(openssl pkey -in "$OUT_DIR/key.der" -inform DER -pubout -outform DER 2>/dev/null |
        openssl dgst -sha256)"
    [ -n "$leaf_pub" ] && [ "$leaf_pub" = "$key_pub" ] ||
        { echo "    staged key.der does not match leaf.der"; return 1; }

    return 0
}

echo "==> Checking prod_certs/ for a reusable certificate ($MODE / ${DOMAINS[*]})"
if [ "${WAITLESS_FORCE_ISSUE:-0}" = "1" ]; then
    echo "    WAITLESS_FORCE_ISSUE=1 set — issuing a fresh certificate"
elif staged_cert_reusable; then
    echo ""
    echo "==> Reusing the staged certificate — no ACME issuance needed."
    openssl x509 -in "$OUT_DIR/leaf.der" -inform DER -noout \
        -subject -issuer -dates 2>&1 | sed 's/^/    /'
    echo ""
    echo "Done. Build with --define tls_cert=prod to bake this cert in,"
    echo "or run scripts/renew-and-deploy.sh to build and deploy in one step."
    echo "(Set WAITLESS_FORCE_ISSUE=1 to issue a fresh certificate instead.)"
    exit 0
fi

echo "==> Issuing certificate"
echo "    domain(s): ${DOMAINS[*]}"
echo "    ACME CA:   $MODE ($ACME_SERVER)"
echo "    DNS:       Google Cloud DNS (project $GCE_PROJECT)"

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

# We only reach here once the reuse check above has determined a
# fresh certificate is genuinely needed. `lego run` itself skips
# issuance when a certificate for the domain already exists under
# --path, so clear any prior run's files from the lego working dir to
# force a fresh issuance. The ACME account in `accounts/` is kept and
# reused (account registration is itself rate-limited).
rm -f "$CERT_DIR/$PRIMARY".*

# One --domains flag per name: lego mints a single certificate whose
# SAN carries them all, and names its output files after the first.
_domain_args=()
for _d in "${DOMAINS[@]}"; do
    _domain_args+=(--domains "$_d")
done
lego run \
    --accept-tos \
    --email "$WAITLESS_CERT_EMAIL" \
    "${_domain_args[@]}" \
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
openssl x509 -in "$CERT_DIR/$PRIMARY.crt" \
    -outform DER -out "$OUT_DIR/leaf.der"
openssl x509 -in "$CERT_DIR/$PRIMARY.issuer.crt" \
    -outform DER -out "$OUT_DIR/intermediate.der"
openssl pkey -in "$CERT_DIR/$PRIMARY.key" \
    -outform DER -out "$OUT_DIR/key.der"

echo ""
echo "    leaf.der         $(wc -c <"$OUT_DIR/leaf.der" | tr -d ' ') bytes"
echo "    intermediate.der $(wc -c <"$OUT_DIR/intermediate.der" | tr -d ' ') bytes"
echo "    key.der          $(wc -c <"$OUT_DIR/key.der" | tr -d ' ') bytes"
echo ""
echo "Certificate summary:"
openssl x509 -in "$CERT_DIR/$PRIMARY.crt" -noout \
    -subject -issuer -dates 2>&1 | sed 's/^/    /'

echo ""
echo "Done. Build with --define tls_cert=prod to bake this cert in,"
echo "or run scripts/renew-and-deploy.sh to build and deploy in one step."
