#!/usr/bin/env bash
# renew-and-deploy.sh — obtain a fresh TLS certificate and redeploy
# the webserver with it baked in.
#
# Three steps, one command:
#   1. issue-cert.sh   — ACME DNS-01 issuance → apps/webserver/prod_certs/
#   2. bazel build     — webserver_iso with `--define tls_cert=prod`
#   3. deploy-gcloud.sh — blue/green deploy of the new image
#
# Let's Encrypt certificates are valid 90 days. issue-cert.sh reuses
# the staged cert and re-issues only once it nears expiry (default:
# under 30 days left), so this script is idempotent — safe to run by
# hand any time or unattended from a host cron / CI schedule, e.g.:
#
#   # crontab — renew on the 1st of every other month, 04:17
#   17 4 1 */2 *  WAITLESS_CERT_DOMAINS=example.com \
#                 WAITLESS_CERT_EMAIL=me@example.com \
#                 GCE_PROJECT=my-proj \
#                 /path/to/waitless/scripts/renew-and-deploy.sh prod \
#                 >> /var/log/waitless-renew.log 2>&1
#
# The deploy is zero-downtime: deploy-gcloud.sh (with
# WAITLESS_ZERO_DOWNTIME=1, set below) builds the new image, boots it
# as a second blue/green instance, health-checks it, and only then
# moves the reserved static IP across. A bad build is caught before
# any traffic shifts; the sole outage is the IP move — a couple of
# API calls. See scripts/deploy-gcloud.sh.
#
# Usage:
#   ./scripts/renew-and-deploy.sh staging   # LE staging (default)
#   ./scripts/renew-and-deploy.sh prod      # LE production
#
# Env: see issue-cert.sh (WAITLESS_CERT_DOMAINS, WAITLESS_CERT_EMAIL,
# GCE_PROJECT, WAITLESS_PROD_CERTS_DIR) and deploy-gcloud.sh
# (WAITLESS_GCE_* plus WAITLESS_DEPLOY_REPO / WAITLESS_BUILD_TARGET).
# Deploying an external app — one in its own repo that consumes
# waitless as a Bazel module — is just a matter of pointing
# WAITLESS_DEPLOY_REPO / WAITLESS_BUILD_TARGET / WAITLESS_PROD_CERTS_DIR
# at it; the pipeline is otherwise identical to the in-repo demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-staging}"

case "$MODE" in
staging | prod) ;;
*)
    echo "Usage: $0 {staging|prod}" >&2
    exit 1
    ;;
esac

# Primary cert domain for the closing "verify" hint — first of the
# WAITLESS_CERT_DOMAINS list, or the legacy single WAITLESS_CERT_DOMAIN.
CERT_DOMAIN="${WAITLESS_CERT_DOMAINS:-${WAITLESS_CERT_DOMAIN:-}}"
CERT_DOMAIN="${CERT_DOMAIN%% *}"

echo "=========================================="
echo "  Step 1/3 — issue certificate ($MODE)"
echo "=========================================="
"$SCRIPT_DIR/issue-cert.sh" "$MODE"

echo ""
echo "=========================================="
echo "  Step 2/3 + 3/3 — build (tls_cert=prod) + deploy"
echo "=========================================="
# deploy-gcloud.sh runs `bazel build` then the GCE deploy.
# WAITLESS_BAZEL_DEFINES threads the prod-cert define into that build
# so the cert in prod_certs/ is baked into the image; WAITLESS_ZERO_-
# DOWNTIME=1 selects the blue/green path — health-check the new image
# on a second instance, then flip the static IP — so the cutover is
# seconds and a bad build never reaches production.
#
# A staging cert chains to an untrusted root, so the blue/green HTTPS
# health check must skip verification (WAITLESS_HEALTH_INSECURE=1) — it
# still confirms the server is up. A prod cert verifies clean, so the
# check stays strict and catches a broken prod cert before cutover.
health_insecure=0
[ "$MODE" = "staging" ] && health_insecure=1
WAITLESS_BAZEL_DEFINES="--define tls_cert=prod" \
    WAITLESS_ZERO_DOWNTIME=1 \
    WAITLESS_HEALTH_INSECURE="$health_insecure" \
    "$SCRIPT_DIR/deploy-gcloud.sh" deploy

echo ""
echo "Renewal complete. Verify the live endpoint:"
if [ "$MODE" = "staging" ]; then
    echo "    curl -kv https://<external-ip>/health"
    echo "    (staging certs chain to an untrusted root — -k or --cacert)"
else
    echo "    curl -v https://${CERT_DOMAIN:-<domain>}/health"
fi
