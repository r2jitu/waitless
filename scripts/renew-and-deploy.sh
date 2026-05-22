#!/usr/bin/env bash
# renew-and-deploy.sh — obtain a fresh TLS certificate and redeploy
# the webserver with it baked in.
#
# Three steps, one command:
#   1. issue-cert.sh   — ACME DNS-01 issuance → apps/webserver/prod_certs/
#   2. bazel build     — webserver_iso with `--define tls_cert=prod`
#   3. deploy-gcloud.sh — upload the image and relaunch the GCE VM
#
# Let's Encrypt certificates are valid 90 days. issue-cert.sh reuses
# the staged cert and re-issues only once it nears expiry (default:
# under 30 days left), so this script is idempotent — safe to run by
# hand any time or unattended from a host cron / CI schedule, e.g.:
#
#   # crontab — renew on the 1st of every other month, 04:17
#   17 4 1 */2 *  WAITLESS_CERT_DOMAIN=example.com \
#                 WAITLESS_CERT_EMAIL=me@example.com \
#                 GCE_PROJECT=my-proj \
#                 /path/to/waitless/scripts/renew-and-deploy.sh prod \
#                 >> /var/log/waitless-renew.log 2>&1
#
# Downtime is the unikernel's ~50 ms reboot when the GCE VM relaunches
# on the new image. For true zero downtime, deploy a second instance
# and flip the external IP / forwarding rule — left as a follow-up;
# the brief reboot is acceptable for a personal site.
#
# Usage:
#   ./scripts/renew-and-deploy.sh staging   # LE staging (default)
#   ./scripts/renew-and-deploy.sh prod      # LE production
#
# Env: see issue-cert.sh (WAITLESS_CERT_DOMAIN, WAITLESS_CERT_EMAIL,
# GCE_PROJECT) and deploy-gcloud.sh (WAITLESS_GCE_* overrides).

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

echo "=========================================="
echo "  Step 1/3 — issue certificate ($MODE)"
echo "=========================================="
"$SCRIPT_DIR/issue-cert.sh" "$MODE"

echo ""
echo "=========================================="
echo "  Step 2/3 + 3/3 — build (tls_cert=prod) + deploy"
echo "=========================================="
# deploy-gcloud.sh runs `bazel build` then the GCE upload/relaunch;
# WAITLESS_BAZEL_DEFINES threads the prod-cert define into that build
# so the freshly issued cert from prod_certs/ is baked into the image.
WAITLESS_BAZEL_DEFINES="--define tls_cert=prod" \
    "$SCRIPT_DIR/deploy-gcloud.sh" deploy

echo ""
echo "Renewal complete. Verify the live endpoint:"
if [ "$MODE" = "staging" ]; then
    echo "    curl -kv https://<external-ip>/health"
    echo "    (staging certs chain to an untrusted root — -k or --cacert)"
else
    echo "    curl -v https://${WAITLESS_CERT_DOMAIN:-<domain>}/health"
fi
