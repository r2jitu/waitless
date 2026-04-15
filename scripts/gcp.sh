#!/usr/bin/env bash
# gcp.sh — Remote control for GCP dev instance
#
# One-time setup:
#   gcloud auth login
#   gcloud config set project unikernel-dev
#   gcloud config set compute/zone us-west1-a
#   Add to ~/.ssh/config:
#     Host gcp
#         HostName <instance-external-ip>
#         User <your-gcloud-username>
#         IdentityFile ~/.ssh/google_compute_engine
#
# Usage: ./scripts/gcp.sh <command>
#
# Commands:
#   status    Show instance status
#   start     Start the instance
#   stop      Stop the instance (no compute charge while stopped)
#   ip        Print the current external IP (changes on each start)
#   ssh       Open an interactive SSH session
#   run       Build locally, push binary, run with KVM (http://localhost:PORT/)
#   test      Build locally, push binary, run HTTP+UDP tests with KVM
#   serve     Build, push, launch KVM detached with public :80/:443 bindings
#   serve-stop  Kill the detached serve VM (leaves the GCP instance running)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GCP_PROJECT="${GCP_PROJECT:-unikernel-dev}"
GCP_ZONE="${GCP_ZONE:-us-west1-a}"
GCP_INSTANCE="${GCP_INSTANCE:-kvm-vm}"
SSH_HOST="${GCP_SSH_HOST:-gcp}"
MEMORY="${UNIKERNEL_MEMORY:-128}"
CPUS="${UNIKERNEL_CPUS:-1}"
HOST_PORT="${UNIKERNEL_PORT:-8080}"
TLS_HOST_PORT="${UNIKERNEL_TLS_PORT:-8443}"
TEST_PORT=19099

cmd="${1:-help}"

_gcloud() {
    gcloud compute instances "$@" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE"
}

_update_ssh_ip() {
    local ip
    ip=$(_gcloud describe "$GCP_INSTANCE" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
    if [ -z "$ip" ] || [ "$ip" = "None" ]; then
        echo "error: no external IP found" >&2
        return 1
    fi
    # Update the HostName in ~/.ssh/config
    sed -i.bak "/^Host ${SSH_HOST}$/,/^Host / s/HostName .*/HostName ${ip}/" ~/.ssh/config
    echo "$ip"
}

_build() {
    echo "==> Building webserver.elf..."
    cd "$PROJECT_ROOT"
    bazel build --config=x86_64-qemu //apps/webserver:webserver.elf
}

_push() {
    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    echo "==> Copying image to GCP..."
    cat "$elf" | ssh "$SSH_HOST" "cat > ~/webserver.elf"
}

case "$cmd" in

    status)
        _gcloud describe "$GCP_INSTANCE" \
            --format='table(name,status,networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)'
        ;;

    start)
        echo "==> Starting instance..."
        _gcloud start "$GCP_INSTANCE"
        echo "    Waiting for SSH..."
        sleep 5
        local_ip=$(_update_ssh_ip)
        # Drop any stale known_hosts entry for the new IP — GCE re-rolls
        # the external IP on every start so the old fingerprint is
        # almost always wrong for the new host at the same address.
        ssh-keygen -R "$local_ip" >/dev/null 2>&1 || true
        echo "    External IP: $local_ip (SSH config updated)"
        echo "    Connect: ssh $SSH_HOST"
        ;;

    stop)
        echo "==> Stopping instance..."
        _gcloud stop "$GCP_INSTANCE"
        ;;

    ip)
        _gcloud describe "$GCP_INSTANCE" \
            --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
        ;;

    ssh)
        exec ssh "$SSH_HOST"
        ;;

    run)
        _build; _push
        _update_ssh_ip > /dev/null 2>&1 || true

        # Launch QEMU detached on the remote with serial → /tmp/webserver.log
        # and hostfwd bound to 127.0.0.1 on the instance (only reachable
        # through the -L tunnels we open below). Running detached is what
        # lets Ctrl-C actually work: we tail the log through a cooked-mode
        # ssh (no -t), so a local SIGINT fires the EXIT trap, which kills
        # the remote VM via a side-channel ssh. The old interactive path
        # used `-chardev stdio,signal=off`, which silently drops the 0x03
        # byte somewhere in the SSH-PTY → remote-PTY → QEMU stdin chain.
        ssh "$SSH_HOST" "sudo pkill -f '[q]emu-system-x86_64.*webserver.elf' 2>/dev/null; true"
        ssh "$SSH_HOST" bash -s "$MEMORY" "$CPUS" "$HOST_PORT" "$TLS_HOST_PORT" <<'REMOTE'
set -euo pipefail
MEMORY="$1"; CPUS="$2"; HTTP_PORT="$3"; TLS_PORT="$4"

DEVICE="virtio-net-pci,netdev=net0"
NETDEV="user,id=net0,hostfwd=tcp:127.0.0.1:${HTTP_PORT}-:80,hostfwd=tcp:127.0.0.1:${TLS_PORT}-:443"
if [[ "$CPUS" -gt 1 ]]; then
    DEVICE="virtio-net-pci,netdev=net0,mq=on,vectors=$((2*CPUS+2))"
    NETDEV="${NETDEV},queues=${CPUS}"
fi

sudo rm -f /tmp/webserver.log /tmp/qemu.out
nohup sudo qemu-system-x86_64 \
    -accel kvm \
    -kernel "$HOME/webserver.elf" \
    -m "$MEMORY" -smp "$CPUS" \
    -cpu host \
    -device "$DEVICE" \
    -netdev "$NETDEV" \
    -serial file:/tmp/webserver.log \
    -display none -no-reboot \
    </dev/null >/tmp/qemu.out 2>&1 &
disown

for i in $(seq 1 60); do
    if curl -sf --max-time 2 "http://127.0.0.1:${HTTP_PORT}/health" >/dev/null 2>&1; then
        exit 0
    fi
    if ! pgrep -f "qemu-system-x86_64.*webserver.elf" >/dev/null; then
        echo "ERROR: qemu exited early" >&2
        tail -40 /tmp/qemu.out /tmp/webserver.log 2>/dev/null >&2 || true
        exit 1
    fi
    sleep 0.5
done
echo "ERROR: http not ready after 30s" >&2
tail -40 /tmp/webserver.log 2>/dev/null >&2 || true
exit 1
REMOTE

        _gcp_run_cleanup() {
            trap - EXIT INT TERM
            echo ""
            echo "==> Stopping remote VM..."
            ssh "$SSH_HOST" "sudo pkill -f '[q]emu-system-x86_64.*webserver.elf' 2>/dev/null; true" >/dev/null 2>&1 || true
        }
        trap '_gcp_run_cleanup' EXIT INT TERM

        echo "==> Running on GCP with KVM..."
        echo "    HTTP:  http://localhost:${HOST_PORT}/"
        echo "    HTTPS: https://localhost:${TLS_HOST_PORT}/  (self-signed — use curl -k)"
        echo "    Serial log below. Press Ctrl-C to stop."
        echo ""
        ssh \
            -L "${HOST_PORT}:localhost:${HOST_PORT}" \
            -L "${TLS_HOST_PORT}:localhost:${TLS_HOST_PORT}" \
            "$SSH_HOST" \
            "sudo tail -n +1 -F /tmp/webserver.log" || true
        ;;

    test)
        _build; _push

        _update_ssh_ip > /dev/null 2>&1 || true

        echo "==> Running tests on GCP with KVM..."
        ssh "$SSH_HOST" bash -s "$TEST_PORT" <<'REMOTE'
set -euo pipefail
PORT="$1"
UDP_PORT=$((PORT + 1))
FAILURES=0

VM_LOG=$(mktemp)
qemu-system-x86_64 \
    -accel kvm \
    -kernel ~/webserver.elf -m 128 \
    -cpu host \
    -device virtio-net-pci,netdev=net0 \
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

    serve)
        _build; _push

        ext_ip=$(_update_ssh_ip)

        echo "==> Launching detached KVM serve on GCP (public :80/:443)..."
        ssh "$SSH_HOST" bash -s "$MEMORY" "$CPUS" <<'REMOTE'
set -euo pipefail
MEMORY="$1"
CPUS="$2"

sudo pkill -f '[q]emu-system-x86_64.*webserver.elf' 2>/dev/null || true
sleep 0.5

DEVICE="virtio-net-pci,netdev=net0"
NETDEV="user,id=net0,hostfwd=tcp::80-:80,hostfwd=tcp::443-:443"
if [[ "$CPUS" -gt 1 ]]; then
    DEVICE="virtio-net-pci,netdev=net0,mq=on,vectors=$((2*CPUS+2))"
    NETDEV="user,id=net0,hostfwd=tcp::80-:80,hostfwd=tcp::443-:443,queues=${CPUS}"
fi

sudo rm -f /tmp/webserver.log /tmp/qemu.out
nohup sudo qemu-system-x86_64 \
    -accel kvm \
    -kernel "$HOME/webserver.elf" \
    -m "$MEMORY" -smp "$CPUS" \
    -cpu host \
    -device "$DEVICE" \
    -netdev "$NETDEV" \
    -serial file:/tmp/webserver.log \
    -display none -no-reboot \
    </dev/null >/tmp/qemu.out 2>&1 &
disown

echo "    Waiting for HTTP on :80..."
for i in $(seq 1 30); do
    if curl -sf --max-time 2 http://localhost/health >/dev/null 2>&1; then
        echo "    Ready in ${i}s"; exit 0
    fi
    if ! pgrep -f "qemu-system-x86_64.*webserver.elf" >/dev/null; then
        echo "ERROR: QEMU exited early" >&2
        tail -40 /tmp/qemu.out /tmp/webserver.log >&2 || true
        exit 1
    fi
    sleep 1
done
echo "ERROR: HTTP not ready after 30s" >&2
tail -40 /tmp/webserver.log >&2 || true
exit 1
REMOTE

        echo ""
        echo "==> Public endpoints:"
        echo "     HTTP:  http://${ext_ip}/"
        echo "     HTTPS: https://${ext_ip}/   (self-signed dev cert — use curl -k)"
        echo ""
        echo "    Serial log: ssh ${SSH_HOST} 'sudo tail -f /tmp/webserver.log'"
        echo "    Stop VM:    ./scripts/gcp.sh serve-stop"
        echo "    Stop inst:  ./scripts/gcp.sh stop"
        ;;

    serve-stop)
        echo "==> Stopping detached serve VM..."
        ssh "$SSH_HOST" 'sudo pkill -f '[q]emu-system-x86_64.*webserver.elf' || true'
        echo "    (GCP instance still running; use './scripts/gcp.sh stop' to halt it.)"
        ;;

    help|*)
        cat <<'USAGE'
Usage: ./scripts/gcp.sh <command>

Commands:
  status      Show instance status and external IP
  start       Start the instance
  stop        Stop the instance (no compute charge while stopped)
  ip          Print current external IP
  ssh         Open an interactive SSH session
  run         Build, push, run with KVM (SSH-tunnelled to localhost)
  test        Build, push, run HTTP+UDP tests with KVM
  serve       Build, push, launch detached KVM with public :80/:443 bindings
  serve-stop  Kill the detached serve VM (leaves the GCP instance running)

Environment:
  GCP_PROJECT=unikernel-dev    GCP project (default: unikernel-dev)
  GCP_ZONE=us-west1-a          GCP zone (default: us-west1-a)
  GCP_INSTANCE=kvm-vm          Instance name (default: kvm-vm)
  GCP_SSH_HOST=gcp             SSH config alias (default: gcp)
  UNIKERNEL_MEMORY=128         VM memory in MB
  UNIKERNEL_CPUS=1             vCPU count
  UNIKERNEL_PORT=8080          Local port forwarded to VM port 80 (run only)
  UNIKERNEL_TLS_PORT=8443      Local port forwarded to VM port 443 (run only)
USAGE
        ;;
esac
