#!/usr/bin/env bash
# bazel/rules/run_native.sh — Run the native POSIX binary (no VM).
#
# Runs from two contexts without caring which:
#   1. `bazel run //apps/webserver:webserver` — invoked directly by Bazel.
#   2. sh_test subprocess — the test includes :webserver in `data` and
#      spawns the launcher from its runfiles.
#
# In either case, this script sits next to the `<app>_native` binary in
# the runfiles tree (e.g. `apps/webserver/webserver` alongside
# `apps/webserver/webserver_native`), so the artefact is resolved via
# $0's own directory. No env = {} from sh_binary needed.
#
# Env:
#   UNIKERNEL_PORT     — HTTP listen port  (default 8080)
#   UNIKERNEL_TLS_PORT — HTTPS listen port (default 8443)
#   UNIKERNEL_UDP_PORT — UDP  listen port  (default 8007)
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
NATIVE="${SELF}_native"
[[ -x "$NATIVE" ]] || { echo "ERROR: native binary not found at $NATIVE" >&2; exit 1; }

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"
UDP_PORT="${UNIKERNEL_UDP_PORT:-8007}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"
echo "==> udp  ::${UDP_PORT} → local :7"

# uni/native.rs reads PORT / TLS_PORT / UDP_PORT at init — same env names
# as its config_port / config_tls_port / udp_bind overrides.
exec env \
    PORT="$PORT" \
    TLS_PORT="$TLS_PORT" \
    UDP_PORT="$UDP_PORT" \
    "$NATIVE"
