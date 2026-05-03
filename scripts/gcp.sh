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
#   status   Show instance status and external IP
#   start    Start the instance
#   stop     Stop the instance (no compute charge while stopped)
#   ip       Print current external IP
#   ssh      Open an interactive SSH session
#   run      Build, push, run KVM with public :80/:443 + interactive serial
#   test     Build, push, run HTTP+UDP tests with KVM
#   serve    Build, push, run KVM detached with public :80/:443
#   kill     Kill the remote VM (leaves the GCP instance running)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GCP_PROJECT="${GCP_PROJECT:-unikernel-dev}"
GCP_ZONE="${GCP_ZONE:-us-west1-a}"
GCP_INSTANCE="${GCP_INSTANCE:-kvm-vm}"
SSH_HOST="${GCP_SSH_HOST:-gcp}"
MEMORY="${UNIKERNEL_MEMORY:-128}"
TEST_PORT=19099

# Resolve the guest vCPU count — `UNIKERNEL_CPUS` if set, else the
# remote host's `nproc`. Deferred into a function (rather than a
# top-level `$(...)` assignment) so `gcp.sh status`/`stop`/`ip` don't
# ssh to the instance just to populate a variable they never read —
# when the instance is TERMINATED that ssh blocks on TCP retries for
# ~75 s, which made every `gcp-bench.sh` invocation look hung right
# after the build step finished.
_cpus() {
    if [ -n "${UNIKERNEL_CPUS:-}" ]; then
        echo "$UNIKERNEL_CPUS"
    else
        ssh "$SSH_HOST" nproc 2>/dev/null || echo 1
    fi
}

# pkill/pgrep -f pattern for the running guest. The character-class
# trick (`[q]emu…`) is load-bearing: without it the literal regex
# appears in pkill's own argv, and the regex self-matches the caller
# process, so bash/ssh exits 255 mid-cleanup.
QEMU_PATTERN='[q]emu-system-x86_64.*webserver.elf'

cmd="${1:-help}"

_gcloud() {
    gcloud compute instances "$@" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE"
}

_ext_ip() {
    _gcloud describe "$GCP_INSTANCE" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
}

_update_ssh_ip() {
    local ip
    ip=$(_ext_ip)
    if [ -z "$ip" ] || [ "$ip" = "None" ]; then
        echo "error: no external IP found" >&2
        return 1
    fi
    # Portable in-place sed: GNU accepts `-i ''`, BSD requires `-i
    # <suffix>`, so we write a .bak and delete it afterwards to keep
    # ~/.ssh clean.
    sed -i.bak "/^Host ${SSH_HOST}$/,/^Host / s/HostName .*/HostName ${ip}/" ~/.ssh/config
    rm -f ~/.ssh/config.bak
    echo "$ip"
}

_kill_remote_vm() {
    # Remove any running guest AND wait for it to actually exit before
    # returning, so the next `run`/`serve` can re-bind :80/:443 without
    # racing a dying qemu. SIGTERM first (qemu catches it and shuts
    # down the machine cleanly), SIGKILL fallback after 3 s.
    ssh "$SSH_HOST" bash -s "$QEMU_PATTERN" <<'REMOTE' >/dev/null 2>&1 || true
set -u
PAT="$1"
pgrep -f "$PAT" >/dev/null 2>&1 || exit 0
sudo pkill -f "$PAT" 2>/dev/null || true
for _ in $(seq 1 30); do
    pgrep -f "$PAT" >/dev/null 2>&1 || exit 0
    sleep 0.1
done
sudo pkill -9 -f "$PAT" 2>/dev/null || true
for _ in $(seq 1 20); do
    pgrep -f "$PAT" >/dev/null 2>&1 || exit 0
    sleep 0.1
done
exit 1
REMOTE
}

# Print "Stopping existing remote VM..." and invoke _kill_remote_vm,
# but only when there's actually a guest running. Silent fast path
# when the instance is clean.
_replace_remote_vm() {
    if ssh "$SSH_HOST" "pgrep -f '$QEMU_PATTERN'" >/dev/null 2>&1; then
        echo "==> Stopping existing remote VM..."
        _kill_remote_vm
    fi
}

# Bring up a multi-queue tap0 + dnsmasq lease + iptables NAT so the
# guest is reachable at the public IP via DNAT and outbound from the
# guest is MASQUERADE'd. Idempotent — fast on subsequent runs.
#
# Why tap+vhost instead of `-netdev user`: SLIRP user-mode networking
# only has one host-side queue regardless of the device's mq=on, so
# the guest always negotiates max_virtqueue_pairs=1 and our virtio-net
# driver falls back to Tier 2 software distribution. tap+vhost-net
# gives us real per-core queue pairs, with one ksoftirqd-style worker
# thread per queue on the host side.
GUEST_MAC="52:54:00:12:34:56"
GUEST_IP="10.20.30.10"
TAP_NET_CIDR="10.20.30.0/24"
TAP_HOST_IP="10.20.30.1"
_setup_remote_tap_nat() {
    ssh "$SSH_HOST" sudo bash -s "$GUEST_IP" <<'NET'
set -e
GUEST_IP="$1"
USER_NAME="${SUDO_USER:-jitudas}"
PUB_IF=$(ip -o -4 route show default | awk '{print $5; exit}')

# tap0 multi-queue (matches scripts/bench/bench-tap-setup.sh layout
# so bench.zip and gcp.sh share the same interface and dnsmasq lease).
if ! ip link show tap0 >/dev/null 2>&1; then
    ip tuntap add dev tap0 mode tap multi_queue user "$USER_NAME"
    ip addr add 10.20.30.1/24 dev tap0
fi
ip link set tap0 up

# dnsmasq leases ${GUEST_IP} to the fixed guest MAC; restart only when
# stopped so we don't churn DHCP between back-to-back launches.
systemctl is-active --quiet dnsmasq || systemctl restart dnsmasq

# IP forwarding + NAT plumbing.
sysctl -wq net.ipv4.ip_forward=1

_add_nat() { iptables -t nat -C "$@" 2>/dev/null || iptables -t nat -A "$@"; }
_add_nat POSTROUTING -s 10.20.30.0/24 -o "$PUB_IF" -j MASQUERADE
for port in 80 443; do
    _add_nat PREROUTING -i "$PUB_IF" -p tcp --dport "$port" \
        -j DNAT --to-destination "${GUEST_IP}:${port}"
done
NET
}

_build() {
    echo "==> Building :webserver_qemu_x86_64..."
    cd "$PROJECT_ROOT"
    bazel build //apps/webserver:webserver_qemu_x86_64
}

_push() {
    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_qemu_x86_64.elf"
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
        ip=$(_update_ssh_ip)
        # Drop any stale known_hosts entries — GCE re-rolls the external
        # IP on every start so the old fingerprint is almost always wrong
        # for the new host. Wipe entries under BOTH the new IP and the
        # SSH alias (`gcp`); ssh records hostnames as listed in the SSH
        # config, so depending on prior connections either could be cached.
        ssh-keygen -R "$ip" >/dev/null 2>&1 || true
        ssh-keygen -R "$SSH_HOST" >/dev/null 2>&1 || true
        # First-touch trust: accept and pin the new host key on the next
        # connection, then close. Retry: SSH on the freshly-started
        # instance can still be unavailable after the initial 5 s sleep
        # (cloud-init / sshd boot lags), and a single failed connect
        # leaves nothing pinned, so the next user command sees
        # "Host key verification failed".
        for _ in $(seq 1 10); do
            if ssh -o StrictHostKeyChecking=accept-new \
                   -o ConnectTimeout=5 \
                   -o BatchMode=yes \
                   "$SSH_HOST" true >/dev/null 2>&1; then
                break
            fi
            sleep 2
        done
        echo "    External IP: $ip (SSH config updated)"
        echo "    Connect: ssh $SSH_HOST"
        ;;

    stop)
        echo "==> Stopping instance..."
        _gcloud stop "$GCP_INSTANCE"
        ;;

    ip)
        _ext_ip
        ;;

    ssh)
        exec ssh "$SSH_HOST"
        ;;

    run)
        if ! command -v socat >/dev/null 2>&1; then
            echo "error: 'socat' not found — install it first:" >&2
            case "$(uname -s)" in
                Darwin) echo "  brew install socat" >&2 ;;
                Linux)  echo "  sudo apt install socat   # Debian/Ubuntu" >&2
                        echo "  sudo dnf install socat   # Fedora/RHEL" >&2 ;;
            esac
            exit 1
        fi

        _build; _push
        ext_ip=$(_update_ssh_ip)
        _replace_remote_vm
        _setup_remote_tap_nat

        # tap+vhost-net replaces user-mode networking so the device
        # actually has per-queue host workers (real MQ; the guest
        # negotiates max_virtqueue_pairs from the device's config and
        # promotes to N pairs in activate_multi_queue()). The fixed
        # GUEST_MAC pins dnsmasq's lease to GUEST_IP so the kernel
        # always comes up at the same address, and iptables PREROUTING
        # DNAT (set up by _setup_remote_tap_nat) forwards external
        # :80/:443 there.
        #
        # The serial chardev is a unix-domain socket forwarded over SSH;
        # local socat drives the tty in raw mode. wait=on blocks qemu's
        # main loop at chardev init until the first client connects, so
        # local socat captures the very first boot line — the tradeoff
        # is we can't probe /health from the remote launcher (the guest
        # hasn't started yet); readiness is the user's eyeballs on the
        # interactive console.
        ssh "$SSH_HOST" bash -s "$QEMU_PATTERN" "$MEMORY" "$(_cpus)" "$GUEST_MAC" <<'REMOTE'
set -euo pipefail
QEMU_PATTERN="$1"; MEMORY="$2"; CPUS="$3"; GUEST_MAC="$4"

# Multi-queue tap requires queues>=2 (QEMU rejects queues=1 on a
# multi-queue tap, see bench.py KvmEnv comment). vectors=2N+2 covers
# one MSI-X for each RX, each TX, plus config + ctrl.
NQUEUES=$(( CPUS > 1 ? CPUS : 2 ))
NETDEV="tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=on,queues=${NQUEUES}"
DEVICE="virtio-net-pci,netdev=net0,mac=${GUEST_MAC},mq=on,vectors=$((2*NQUEUES+2))"

sudo rm -f /tmp/webserver.sock /tmp/qemu.out
nohup sudo qemu-system-x86_64 \
    -accel kvm \
    -kernel "$HOME/webserver.elf" \
    -m "$MEMORY" -smp "$CPUS" \
    -cpu host \
    -device "$DEVICE" \
    -netdev "$NETDEV" \
    -chardev socket,id=s0,path=/tmp/webserver.sock,server=on,wait=on \
    -serial chardev:s0 \
    -display none -no-reboot \
    </dev/null >/tmp/qemu.out 2>&1 &
disown

# Wait for the listener socket to appear (qemu's listen() happens
# before it blocks in accept()) and chmod it so the sshd-forwarding
# user — not root — can connect through.
for _ in $(seq 1 80); do
    if [[ -S /tmp/webserver.sock ]]; then
        sudo chmod 666 /tmp/webserver.sock
        exit 0
    fi
    if ! pgrep -f "$QEMU_PATTERN" >/dev/null; then
        echo "ERROR: qemu exited before socket appeared" >&2
        tail -40 /tmp/qemu.out 2>/dev/null >&2 || true
        exit 1
    fi
    sleep 0.1
done
echo "ERROR: serial socket not created after 8s" >&2
exit 1
REMOTE

        LOCAL_SOCK="/tmp/gcp-webserver-$$.sock"
        SSH_CTRL="/tmp/gcp-run-ctrl-$$"
        rm -f "$LOCAL_SOCK" "$SSH_CTRL"

        _gcp_run_cleanup() {
            trap - EXIT INT TERM
            echo ""
            # If the VM is still alive the user detached via Ctrl-] (or
            # something killed socat before the kernel shut down): kill
            # it explicitly. If the VM already exited on its own — the
            # Ctrl-C → ACPI S5 path — _kill_remote_vm is a no-op but we
            # still print a friendly message.
            if ssh "$SSH_HOST" "pgrep -f '$QEMU_PATTERN'" >/dev/null 2>&1; then
                echo "==> Stopping remote VM..."
                _kill_remote_vm
            else
                echo "==> VM exited."
            fi
            ssh -O exit -S "$SSH_CTRL" "$SSH_HOST" 2>/dev/null || true
            rm -f "$LOCAL_SOCK" "$SSH_CTRL"
        }
        trap '_gcp_run_cleanup' EXIT INT TERM

        # Background SSH ControlMaster with a single unix-socket tunnel
        # for the guest serial. HTTP/HTTPS aren't tunneled — they bind
        # publicly on the instance and are reachable at the external IP.
        ssh -fN \
            -o ControlMaster=yes \
            -o ControlPath="$SSH_CTRL" \
            -o ExitOnForwardFailure=yes \
            -L "${LOCAL_SOCK}:/tmp/webserver.sock" \
            "$SSH_HOST"

        for _ in $(seq 1 20); do
            [[ -S "$LOCAL_SOCK" ]] && break
            sleep 0.1
        done
        [[ -S "$LOCAL_SOCK" ]] || { echo "ERROR: local socket forward not established" >&2; exit 1; }

        echo "==> Running on GCP with KVM..."
        echo "    HTTP:   http://${ext_ip}/"
        echo "    HTTPS:  https://${ext_ip}/  (self-signed — curl -k)"
        echo "    Serial: interactive (Ctrl-C → VM graceful shutdown; Ctrl-] → detach)"
        echo ""
        # rawer = no ICANON/ECHO/ISIG/IEXTEN/OPOST etc — pure byte relay.
        # escape=0x1d = Ctrl-] disconnects socat without forwarding the byte.
        socat -,rawer,escape=0x1d UNIX-CONNECT:"$LOCAL_SOCK" || true
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
        _replace_remote_vm
        _setup_remote_tap_nat

        echo "==> Launching detached KVM on GCP (public :80/:443)..."
        ssh "$SSH_HOST" bash -s "$QEMU_PATTERN" "$MEMORY" "$(_cpus)" "$GUEST_MAC" "$GUEST_IP" <<'REMOTE'
set -euo pipefail
QEMU_PATTERN="$1"; MEMORY="$2"; CPUS="$3"; GUEST_MAC="$4"; GUEST_IP="$5"

NQUEUES=$(( CPUS > 1 ? CPUS : 2 ))
NETDEV="tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=on,queues=${NQUEUES}"
DEVICE="virtio-net-pci,netdev=net0,mac=${GUEST_MAC},mq=on,vectors=$((2*NQUEUES+2))"

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

echo "    Waiting for HTTP on guest ${GUEST_IP}:80..."
for i in $(seq 1 30); do
    if curl -sf --max-time 2 "http://${GUEST_IP}/health" >/dev/null 2>&1; then
        echo "    Ready in ${i}s"; exit 0
    fi
    if ! pgrep -f "$QEMU_PATTERN" >/dev/null; then
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
        echo "     HTTPS: https://${ext_ip}/   (self-signed dev cert — curl -k)"
        echo ""
        echo "    Serial log: ssh ${SSH_HOST} 'sudo tail -f /tmp/webserver.log'"
        echo "    Stop VM:    ./scripts/gcp.sh kill"
        echo "    Stop inst:  ./scripts/gcp.sh stop"
        ;;

    kill)
        echo "==> Stopping remote VM..."
        _kill_remote_vm
        echo "    (GCP instance still running; use './scripts/gcp.sh stop' to halt it.)"
        ;;

    help|*)
        cat <<'USAGE'
Usage: ./scripts/gcp.sh <command>

Commands:
  status   Show instance status and external IP
  start    Start the instance
  stop     Stop the instance (no compute charge while stopped)
  ip       Print current external IP
  ssh      Open an interactive SSH session
  run      Build, push, run KVM with public :80/:443 + interactive serial
  test     Build, push, run HTTP+UDP tests with KVM
  serve    Build, push, run KVM detached with public :80/:443
  kill     Kill the remote VM (leaves the GCP instance running)

Environment:
  GCP_PROJECT=unikernel-dev    GCP project
  GCP_ZONE=us-west1-a          GCP zone
  GCP_INSTANCE=kvm-vm          Instance name
  GCP_SSH_HOST=gcp             SSH config alias
  UNIKERNEL_MEMORY=128         VM memory in MB
  UNIKERNEL_CPUS=<nproc>        vCPU count (default: all host cores)
USAGE
        ;;
esac
