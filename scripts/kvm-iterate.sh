#!/usr/bin/env bash
# scripts/kvm-iterate.sh — Fast edit-build-bench loop on GCE kvm-vm.
#
# Same shape as local-iterate.sh but the unikernel runs under QEMU/KVM
# on the kvm-vm (Linux host, hardware-virt, virtio-net + vhost-net
# multi-queue) rather than HVF on the local Mac. Closer to the GCE
# production path:
#   - real Linux host TCP stack on the loadgen side
#   - virtio-net (vs HVF's userspace TCP proxy)
#   - KVM accel + multi-queue + vhost-net (vs HVF userspace)
#
# What this CAN'T reproduce vs full GCE deploy:
#   - gve-specific behaviour (this is virtio-net)
#   - Andromeda VPC-level packet routing
#
# What it CAN reproduce that HVF can't:
#   - real virtio RX/TX queue dynamics
#   - vhost-net cross-cpu scaling
#   - Linux host scheduling + ulimit pressure at high conn counts
#
# Iteration cycle: ~30s build + rsync + 10s QEMU boot + workload.
# Faster than full GCE deploy by ~3-5x; slower than HVF by ~3-5x.
#
# Usage:
#   ./kvm-iterate.sh                          # default: 1000 conns, 10s
#   ./kvm-iterate.sh --conns 4000 --duration 20
#   ./kvm-iterate.sh --conns 500 --workload health-tls --cpus 4
#
# Workloads: health, health-tls, static64k, static64k-tls

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

CONNS=1000
DURATION=10
WARMUP=2
WORKLOAD="health-tls"
THREADS=4
VCPUS=4
KVM_VM="${GCP_KVM_VM_NAME:-kvm-vm}"
KVM_ZONE="${GCP_KVM_VM_ZONE:-us-west1-c}"
DO_BUILD=1

while [ $# -gt 0 ]; do
    case "$1" in
    --conns) shift; CONNS="$1" ;;
    --duration) shift; DURATION="$1" ;;
    --warmup) shift; WARMUP="$1" ;;
    --workload) shift; WORKLOAD="$1" ;;
    --threads) shift; THREADS="$1" ;;
    --cpus) shift; VCPUS="$1" ;;
    --no-build) DO_BUILD=0 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# *//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

case "$WORKLOAD" in
health)        URL="http://10.20.30.10/health" ;;
health-tls)    URL="https://10.20.30.10/health" ;;
static64k)     URL="http://10.20.30.10/static-64k" ;;
static64k-tls) URL="https://10.20.30.10/static-64k" ;;
*) echo "unknown workload: $WORKLOAD" >&2; exit 1 ;;
esac

# 1. Build the unikernel ELF locally (cached, fast on re-build).
if [ $DO_BUILD -eq 1 ]; then
    echo "==> Building //apps/webserver:webserver_qemu_x86_64..." >&2
    bazel build //apps/webserver:webserver_qemu_x86_64 >/dev/null 2>&1
fi
ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_qemu_x86_64.elf"
[ -f "$ELF" ] || { echo "ELF missing: $ELF" >&2; exit 1; }

# 2. Ensure kvm-vm is up.
echo "==> Ensuring $KVM_VM running..." >&2
STATUS=$(gcloud compute instances describe "$KVM_VM" --zone="$KVM_ZONE" \
    --format='value(status)' 2>/dev/null || echo MISSING)
case "$STATUS" in
RUNNING) ;;
TERMINATED|STOPPED)
    gcloud compute instances start "$KVM_VM" --zone="$KVM_ZONE" >/dev/null
    until gcloud compute ssh "$KVM_VM" --zone="$KVM_ZONE" \
        --command='true' >/dev/null 2>&1; do sleep 2; done
    ;;
*) echo "kvm-vm in $STATUS, unexpected" >&2; exit 1 ;;
esac

# 3. Sync the ISO + tap-setup script via gcloud scp (handles auth /
#    IAP / per-project SSH keys properly; raw rsync over plain ssh
#    chokes on gcloud's wrapper).
echo "==> Syncing ELF + tap setup to $KVM_VM..." >&2
# Clean up the prior ELF first — sudo-launched qemu may have left it
# with restrictive perms, blocking our re-scp.
gcloud compute ssh "$KVM_VM" --zone="$KVM_ZONE" \
    --command='mkdir -p ~/kvm-iter && sudo rm -f ~/kvm-iter/webserver_qemu_x86_64.elf ~/kvm-iter/bench-tap-setup.sh' >/dev/null
gcloud compute scp --zone="$KVM_ZONE" \
    "$ELF" \
    "$SCRIPT_DIR/bench/bench-tap-setup.sh" \
    "$KVM_VM":kvm-iter/ >/dev/null

# 4. Run the test on kvm-vm — tap0 setup, QEMU launch, wrk drive,
#    /obs snapshot, teardown. All in one ssh round-trip.
#
# The remote script is sent verbatim via heredoc; CONNS/DURATION/etc.
# get interpolated by the local shell before sending. Inside the
# heredoc, `$VAR` refers to the value sent over.
#
# `OBS_DELTA_PY` interpolates the shared /obs-delta script body
# from scripts/bench/obs_delta.py — same body c3-bench-once.sh uses.
OBS_DELTA_PY="$(cat "$SCRIPT_DIR/bench/obs_delta.py")"
gcloud compute ssh "$KVM_VM" --zone="$KVM_ZONE" --command="bash -s" <<REMOTE
set -euo pipefail
cd ~/kvm-iter

# Bump file-descriptor limit for wrk at high conn counts. macOS /
# Debian default hard limit is often 65536; try high first then fall
# back. Verify after so the test fails loud if 1024 sticks.
ulimit -Sn 1048576 2>/dev/null || ulimit -Sn 65536 2>/dev/null || true
echo "ulimit -n = \$(ulimit -n)" >&2

# Host sysctls for high-conn loadgen (mirrors gcp-deploy-bench.sh's
# tuning). Without these, wrk above ~1K conns gets ephemeral port
# exhaustion or conntrack-table-full errors and the bench gets ~0 rps.
sudo sysctl -w \
    net.core.somaxconn=65535 \
    net.ipv4.tcp_max_syn_backlog=65535 \
    net.ipv4.ip_local_port_range='1024 65535' \
    net.ipv4.tcp_tw_reuse=1 \
    net.netfilter.nf_conntrack_max=524288 \
    fs.file-max=2097152 \
    >/dev/null 2>&1 || true

# Ensure tap0 + dnsmasq + NAT.
sudo ./bench-tap-setup.sh >/dev/null 2>&1 || true

# Kill any prior QEMU.
sudo pkill -9 qemu-system-x86_64 2>/dev/null || true
sleep 0.3

# Launch QEMU/KVM with the unikernel. Same shape as KvmEnv.start in
# scripts/bench/envs.py. -m 4096 needed for high-conn runs
# (~80 KB/conn, so 32K conns ≈ 2.5 GiB heap working set).
#
# With -m > 3 GiB, q35 spills RAM above 4 GiB and SeaBIOS places
# virtio-net's 64-bit modern BAR in its high MMIO window (observed
# at 0x3800_0000_0000 / 56 TiB on this kvm-vm). The boot stub's
# identity map covers only [0, 4 GiB), so the virtio-net driver
# would page-fault on first BAR access. bus::virtio::resolve_bar
# now calls mm::map_device_range to install a runtime 2 MiB
# identity mapping for any BAR at or above 4 GiB.
NQUEUES=\$(( $VCPUS > 2 ? $VCPUS : 2 ))
sudo qemu-system-x86_64 \
    -machine q35 -accel kvm -cpu host -m 4096 -smp $VCPUS \
    -nographic -serial file:/tmp/kvm-iter.log -no-reboot \
    -device "virtio-net-pci,mac=52:54:00:12:34:56,mq=on,vectors=\$((2*\$NQUEUES+2)),netdev=net0" \
    -netdev "tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=on,queues=\$NQUEUES" \
    -kernel webserver_qemu_x86_64.elf \
    >/tmp/kvm-iter.qemu.log 2>&1 &
QEMU_PID=\$!

# Wait for /health. ISO boot adds ~5s for Limine vs raw -kernel.
READY=0
for i in \$(seq 1 45); do
    if curl -fsSk --max-time 1 http://10.20.30.10/health >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done
if [ \$READY -eq 0 ]; then
    echo "FAILED — last serial:" >&2
    sudo tail -20 /tmp/kvm-iter.log >&2
    sudo kill \$QEMU_PID 2>/dev/null || true
    exit 1
fi

# Snapshot /obs pre.
curl -sk http://10.20.30.10/obs > /tmp/obs-pre.json

# Drive wrk.
echo "==> wrk -t$THREADS -c$CONNS -d${DURATION}s --latency $URL" >&2
wrk -t$THREADS -c$CONNS -d${DURATION}s --latency --timeout 10s "$URL" 2>&1 | \
    grep -E 'Requests/sec|^[[:space:]]+(50|99)%|Socket errors|Latency'

# Snapshot /obs post. Tolerant of unikernel being overloaded
# (which is exactly when we most want to see the counters); fall
# back to an empty object so the delta script doesn't crash.
curl -sk --max-time 15 http://10.20.30.10/obs > /tmp/obs-post.json 2>/dev/null \
    || echo '{}' > /tmp/obs-post.json

# Tear down.
sudo kill \$QEMU_PID 2>/dev/null || true
wait \$QEMU_PID 2>/dev/null || true

# /obs deltas.
echo "" >&2
echo "==> /obs deltas (post - pre):" >&2
python3 - /tmp/obs-pre.json /tmp/obs-post.json <<'PY'
$OBS_DELTA_PY
PY
REMOTE
