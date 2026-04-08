#!/usr/bin/env bash
# oracle.sh — Remote control for Oracle Cloud dev instance
#
# One-time setup:
#   1. Add to ~/.ssh/config:
#        Host oracle
#            HostName <instance-public-ip>
#            User ubuntu
#            IdentityFile ~/.ssh/id_ed25519
#   2. For start/stop: brew install oci-cli && oci setup config
#      Then export ORACLE_INSTANCE_OCID=ocid1.instance.oc1.<region>.<id>
#
# Usage: ./scripts/oracle.sh <command>
#
# Commands:
#   status    Show instance lifecycle state
#   start     Start the instance
#   stop      Stop the instance
#   ssh       Open an interactive SSH session
#   run       Build locally, push binary, run with KVM (http://localhost:PORT/)
#   test      Build locally, push binary, run HTTP+UDP tests with KVM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SSH_HOST="${ORACLE_SSH_HOST:-oracle}"
INSTANCE_OCID="${ORACLE_INSTANCE_OCID:-}"
MEMORY="${UNIKERNEL_MEMORY:-128}"
CPUS="${UNIKERNEL_CPUS:-1}"
HOST_PORT="${UNIKERNEL_PORT:-8080}"
TEST_PORT=19099  # internal port for automated tests (avoids conflicts)

cmd="${1:-help}"

_require_ocid() {
    if [ -z "$INSTANCE_OCID" ]; then
        echo "error: ORACLE_INSTANCE_OCID not set"
        echo "  export ORACLE_INSTANCE_OCID=ocid1.instance.oc1..."
        exit 1
    fi
}

_require_oci() {
    if ! command -v oci &>/dev/null; then
        echo "error: OCI CLI not installed"
        echo "  brew install oci-cli && oci setup config"
        exit 1
    fi
}

_build() {
    echo "==> Building webserver.img..."
    cd "$PROJECT_ROOT"
    bazel build //apps/webserver:webserver.img
}

_push() {
    local img="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.img"
    echo "==> Copying image to Oracle..."
    scp "$img" "$SSH_HOST:~/webserver.img"
}

case "$cmd" in

    status)
        _require_ocid; _require_oci
        oci compute instance get \
            --instance-id "$INSTANCE_OCID" \
            --query 'data."lifecycle-state"' --raw-output
        ;;

    start)
        _require_ocid; _require_oci
        echo "==> Starting instance..."
        oci compute instance action \
            --instance-id "$INSTANCE_OCID" --action START
        echo "    Waiting for RUNNING state..."
        oci compute instance get \
            --instance-id "$INSTANCE_OCID" \
            --wait-for-state RUNNING \
            --max-wait-seconds 120 \
            --query 'data."lifecycle-state"' --raw-output
        echo ""; echo "    Connect: ssh $SSH_HOST"
        ;;

    stop)
        _require_ocid; _require_oci
        echo "==> Stopping instance..."
        oci compute instance action \
            --instance-id "$INSTANCE_OCID" --action SOFTSTOP
        ;;

    ssh)
        exec ssh "$SSH_HOST"
        ;;

    run)
        _build; _push

        echo "==> Running on Oracle with KVM..."
        echo "    URL: http://localhost:${HOST_PORT}/"
        echo "    Serial console below. Press Ctrl-C to stop."
        echo ""
        # -L: tunnel Oracle's QEMU port-forward back to localhost (no firewall rules needed)
        # -t: PTY so Ctrl-C (0x03) is forwarded to the VM for graceful shutdown
        ssh -t -L "${HOST_PORT}:localhost:${HOST_PORT}" "$SSH_HOST" \
            "qemu-system-aarch64 \
                -machine virt -accel kvm -cpu host \
                -kernel ~/webserver.img \
                -m ${MEMORY} -smp ${CPUS} \
                -device virtio-net-device,netdev=net0 \
                -netdev user,id=net0,hostfwd=tcp::${HOST_PORT}-:80 \
                -chardev stdio,id=s0,signal=off -serial chardev:s0 \
                -display none -no-reboot"
        ;;

    test)
        _build; _push

        echo "==> Running tests on Oracle with KVM..."
        # Pass TEST_PORT as $1 via bash -s; use quoted heredoc so remote $vars are literal.
        ssh "$SSH_HOST" bash -s "$TEST_PORT" <<'REMOTE'
set -euo pipefail
PORT="$1"
UDP_PORT=$((PORT + 1))
FAILURES=0

VM_LOG=$(mktemp)
qemu-system-aarch64 \
    -machine virt -accel kvm -cpu host \
    -kernel ~/webserver.img -m 128 \
    -device virtio-net-device,netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80,hostfwd=udp::${UDP_PORT}-:7" \
    -serial "file:${VM_LOG}" -display none -no-reboot &
VM_PID=$!
trap "kill $VM_PID 2>/dev/null; wait $VM_PID 2>/dev/null; rm -f $VM_LOG" EXIT

echo "  Waiting for server (KVM)..."
for i in $(seq 1 60); do
    sleep 1
    if curl -sf --max-time 2 "http://localhost:${PORT}/" >/dev/null 2>&1; then
        echo "  Ready in ${i}s"; break
    fi
    if ! kill -0 "$VM_PID" 2>/dev/null; then
        echo "ERROR: QEMU exited early"; cat "$VM_LOG" >&2; exit 1
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: not ready after 60s"; cat "$VM_LOG" >&2; exit 1
    fi
done

check_http() {
    local desc="$1" url="$2" want_status="$3" want_body="${4:-}"
    local resp body status
    resp="$(curl -s -w $'\n%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$resp" | sed '$d')"
    status="$(echo "$resp" | tail -n1)"
    if [[ "$status" == "$want_status" ]] && { [[ -z "$want_body" ]] || echo "$body" | grep -q "$want_body"; }; then
        echo "  PASS: $desc"
    else
        echo "  FAIL: $desc (status=$status)"
        FAILURES=$((FAILURES + 1))
    fi
}

echo "==> HTTP tests..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"
check_http "GET /health"   "http://localhost:${PORT}/health" "200"
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404" "Not Found"

echo "==> UDP echo test..."
REPLY=$(python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'hello', ('127.0.0.1', $UDP_PORT))
try:
    data, _ = s.recvfrom(1024)
    sys.stdout.write(data.decode())
except socket.timeout:
    pass
" 2>/dev/null || true)
if [[ "$REPLY" == "hello" ]]; then
    echo "  PASS: UDP echo"
else
    echo "  FAIL: UDP echo (got '${REPLY:-<empty>}')"
    FAILURES=$((FAILURES + 1))
fi

echo ""
[[ $FAILURES -eq 0 ]] && echo "ALL TESTS PASSED" && exit 0
echo "$FAILURES TEST(S) FAILED"; tail -40 "$VM_LOG" >&2; exit 1
REMOTE
        ;;

    help|*)
        cat <<'USAGE'
Usage: ./scripts/oracle.sh <command>

Commands:
  status    Show instance lifecycle state
  start     Start the instance (requires OCI CLI + ORACLE_INSTANCE_OCID)
  stop      Stop the instance
  ssh       Open an interactive SSH session
  run       Build locally, push binary, run with KVM (port-forwarded to localhost)
  test      Build locally, push binary, run HTTP+UDP tests with KVM

Environment:
  ORACLE_SSH_HOST=oracle        SSH config alias (default: oracle)
  ORACLE_INSTANCE_OCID=ocid1... Instance OCID for start/stop
  UNIKERNEL_MEMORY=128          VM memory in MB
  UNIKERNEL_CPUS=1              vCPU count
  UNIKERNEL_PORT=8080           Local port forwarded to VM port 80 (run only)
USAGE
        ;;
esac
