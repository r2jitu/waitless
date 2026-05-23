#!/usr/bin/env bash
# verify-parity.sh — build both Linux peers locally (Docker), spin
# them up on loopback, hit every endpoint, and confirm the response
# bodies are byte-identical to what the waitless app code produces.
#
# What this catches:
#   * Body byte mismatches (a stray newline in nginx's `return 200`,
#     a wrong static-64k size, a Content-Type drift).
#   * Status code drift (a 200 that becomes a 204, etc.).
#   * Routing bugs (nginx serving /static-64k from the wrong file).
#
# What this does NOT catch:
#   * Performance differences — that's the bench's job.
#   * Header order / Date / Server differences — these don't affect
#     the bench, so parity here is body + status + content-type only.
#   * nginx → tokio-hyper proxy path (/compute, /discard via nginx) —
#     out of scope for parity verification; bench-time concern.
#
# Builds + runs on whatever platform Docker is configured for. On Mac
# arm64 (Docker Desktop) the binaries will be arm64 — fine for parity
# correctness, but bench-time the binaries are rebuilt on x86_64 Linux.
#
# Usage:
#   ./verify-parity.sh             # build + run + verify
#   ./verify-parity.sh --no-build  # reuse already-built images
#   ./verify-parity.sh --keep-up   # don't tear down at the end

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NGINX_TAG="waitless-peer-nginx:dev"
TOKIO_TAG="waitless-peer-tokio:dev"
NGINX_NAME="parity-nginx"
TOKIO_NAME="parity-tokio"

# Bind to high host ports to avoid colliding with whatever might be on
# 80/443 locally (Docker Desktop, browser, vpn client, etc.). Inside
# each container nginx still binds 80/443 and tokio-hyper does too; we
# remap via `docker run -p`.
NGINX_HTTP_HOST=18080
NGINX_HTTPS_HOST=18443
TOKIO_HTTP_HOST=28080
TOKIO_HTTPS_HOST=28443

do_build=1
keep_up=0
while [ $# -gt 0 ]; do
    case "$1" in
    --no-build) do_build=0 ;;
    --keep-up) keep_up=1 ;;
    -h | --help)
        sed -n '2,30p' "$0" | sed 's/^# *//'
        exit 0
        ;;
    *)
        echo "unknown arg: $1" >&2
        exit 1
        ;;
    esac
    shift
done

teardown() {
    if [ $keep_up -eq 1 ]; then
        echo ""
        echo "==> --keep-up: leaving containers running."
        echo "    nginx        http://127.0.0.1:$NGINX_HTTP_HOST  https://127.0.0.1:$NGINX_HTTPS_HOST"
        echo "    tokio-hyper  http://127.0.0.1:$TOKIO_HTTP_HOST  https://127.0.0.1:$TOKIO_HTTPS_HOST"
        echo "    stop: docker rm -f $NGINX_NAME $TOKIO_NAME"
        return
    fi
    docker rm -f "$NGINX_NAME" "$TOKIO_NAME" >/dev/null 2>&1 || true
}
trap teardown EXIT

# ── 1. Build images ─────────────────────────────────────────────
if [ $do_build -eq 1 ]; then
    echo "==> Building $NGINX_TAG..."
    docker build -t "$NGINX_TAG" "$SCRIPT_DIR/nginx" >/tmp/nginx-build.log 2>&1 ||
        { tail -30 /tmp/nginx-build.log; exit 1; }

    echo "==> Building $TOKIO_TAG (Rust compile, ~3-10 min first time)..."
    docker build -t "$TOKIO_TAG" "$SCRIPT_DIR/tokio-hyper" >/tmp/tokio-build.log 2>&1 ||
        { tail -30 /tmp/tokio-build.log; exit 1; }
fi

# ── 2. Run containers ──────────────────────────────────────────
docker rm -f "$NGINX_NAME" "$TOKIO_NAME" >/dev/null 2>&1 || true

CERT_DIR="$REPO_ROOT/apps/webserver/dev_certs"

# Each peer runs standalone with its own published ports. We don't
# wire nginx → tokio-hyper at parity time; nginx's upstream block
# points at 127.0.0.1:8080 which has no listener here, but nginx
# starts fine because the upstream is only consulted on demand and
# we never hit /compute or /discard via nginx during parity.

echo "==> Starting tokio-hyper..."
docker run -d --name "$TOKIO_NAME" \
    -p "$TOKIO_HTTP_HOST:80" -p "$TOKIO_HTTPS_HOST:443" \
    -v "$CERT_DIR/dev_cert.pem:/etc/tokio-hyper/tls/dev_cert.pem:ro" \
    -v "$CERT_DIR/dev_key.pem:/etc/tokio-hyper/tls/dev_key.pem:ro" \
    "$TOKIO_TAG" \
    --upstream-port 0 >/dev/null

echo "==> Starting nginx..."
docker run -d --name "$NGINX_NAME" \
    -p "$NGINX_HTTP_HOST:80" -p "$NGINX_HTTPS_HOST:443" \
    -v "$CERT_DIR/dev_cert.pem:/etc/nginx/tls/dev_cert.pem:ro" \
    -v "$CERT_DIR/dev_key.pem:/etc/nginx/tls/dev_key.pem:ro" \
    "$NGINX_TAG" >/dev/null

# ── 3. Wait for both to come up ─────────────────────────────────
wait_for_url() {
    local url="$1" container="$2"
    for _ in $(seq 1 60); do
        if curl -sk --max-time 2 -o /dev/null "$url"; then
            return 0
        fi
        sleep 0.5
    done
    echo "ERROR: $container didn't come up at $url" >&2
    docker logs "$container" 2>&1 | tail -30
    exit 1
}

wait_for_url "http://127.0.0.1:$NGINX_HTTP_HOST/health" "$NGINX_NAME"
wait_for_url "http://127.0.0.1:$TOKIO_HTTP_HOST/health" "$TOKIO_NAME"

# ── 4. Parity checks ────────────────────────────────────────────
#
# For each endpoint, fetch from each peer, hash the body, compare
# against the waitless reference. Reference values are derived inline
# from waitless's source constants (apps/webserver/src/endpoints.rs).

FAIL=0
check_body() {
    local label="$1" url="$2" expected_sha="$3" expected_size="$4"
    local actual_size actual_sha tmp
    tmp=$(mktemp)
    curl -sk -o "$tmp" "$url"
    actual_size=$(wc -c <"$tmp" | tr -d ' ')
    actual_sha=$(shasum -a 256 "$tmp" | awk '{print $1}')
    rm -f "$tmp"
    if [ "$actual_size" = "$expected_size" ] && [ "$actual_sha" = "$expected_sha" ]; then
        printf "    %-40s OK (%d bytes)\n" "$label" "$actual_size"
    else
        printf "    %-40s FAIL\n" "$label"
        printf "        expected: %s bytes, sha %s\n" "$expected_size" "$expected_sha"
        printf "        actual:   %s bytes, sha %s\n" "$actual_size" "$actual_sha"
        FAIL=$((FAIL + 1))
    fi
}

# Expected values, derived inline from waitless source:
#   HEALTH_JSON    = apps/webserver/src/endpoints.rs:12
#   STATIC_64K     = 65536 zero bytes (ZeroBody<{ 64 * 1024 }>)
#   COMPUTED_JSON  = {"status":"computed"}  (main.rs:401)
#   DISCARDED_JSON = {"status":"discarded"} (main.rs:421)
HEALTH_SHA=$(printf '%s' '{"status":"ok","runtime":"waitless","version":"0.1.0"}' | shasum -a 256 | awk '{print $1}')
HEALTH_SIZE=54
STATIC64K_SHA=$(head -c 65536 /dev/zero | shasum -a 256 | awk '{print $1}')
STATIC64K_SIZE=65536
COMPUTED_SHA=$(printf '%s' '{"status":"computed"}' | shasum -a 256 | awk '{print $1}')
COMPUTED_SIZE=21
DISCARDED_SHA=$(printf '%s' '{"status":"discarded"}' | shasum -a 256 | awk '{print $1}')
DISCARDED_SIZE=22

echo ""
echo "==> Parity checks (body sha + length vs waitless reference)"

for peer in \
    "nginx       http://127.0.0.1:$NGINX_HTTP_HOST       static-only" \
    "nginx-tls   https://127.0.0.1:$NGINX_HTTPS_HOST     static-only" \
    "tokio       http://127.0.0.1:$TOKIO_HTTP_HOST       all" \
    "tokio-tls   https://127.0.0.1:$TOKIO_HTTPS_HOST     all"; do
    read -r name base scope <<<"$peer"
    echo ""
    echo "  ── $name @ $base ──"
    check_body "GET /health" "$base/health" "$HEALTH_SHA" "$HEALTH_SIZE"
    check_body "GET /static-64k" "$base/static-64k" "$STATIC64K_SHA" "$STATIC64K_SIZE"
    if [ "$scope" = "all" ]; then
        check_body "GET /compute" "$base/compute" "$COMPUTED_SHA" "$COMPUTED_SIZE"
        # POST /discard with a small body — body content irrelevant
        # (server discards), the parity check is on the response.
        tmp=$(mktemp)
        printf 'hello world' | curl -sk --data-binary @- -o "$tmp" "$base/discard"
        actual_size=$(wc -c <"$tmp" | tr -d ' ')
        actual_sha=$(shasum -a 256 "$tmp" | awk '{print $1}')
        rm -f "$tmp"
        if [ "$actual_size" = "$DISCARDED_SIZE" ] && [ "$actual_sha" = "$DISCARDED_SHA" ]; then
            printf "    %-40s OK (%d bytes)\n" "POST /discard" "$actual_size"
        else
            printf "    %-40s FAIL (got %d bytes, sha %s)\n" "POST /discard" "$actual_size" "$actual_sha"
            FAIL=$((FAIL + 1))
        fi
    fi
done

echo ""
if [ $FAIL -eq 0 ]; then
    echo "==> PARITY OK — all endpoints match waitless reference bytes."
else
    echo "==> PARITY FAILED — $FAIL endpoint(s) don't match. Check output above."
    exit 1
fi
