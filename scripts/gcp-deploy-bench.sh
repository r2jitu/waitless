#!/usr/bin/env bash
# gcp-deploy-bench.sh — Production-shape GCE bench: deploy the
# unikernel as a real GCE VM (`unikernel-webserver`, n2-highcpu-4
# w/ gVNIC) and drive the loadgen against it from a separate
# bench client (`kvm-vm`, n2-highcpu-8). Both VMs sit on the
# default VPC, so traffic crosses the GCE network on internal
# IPs.
#
# This complements `gcp-bench.sh` (which runs the unikernel
# *nested* inside QEMU/KVM on `kvm-vm`):
#
#   gcp-bench.sh         : kvm-vm runs both QEMU+unikernel and the
#                          loadgen → tests guest-side stack with
#                          minimal network overhead.
#   gcp-deploy-bench.sh  : unikernel runs as a real GCE VM (gVNIC
#                          driver, real Andromeda network path),
#                          loadgen on a separate VM → tests the
#                          production-shape datapath end-to-end.
#
# Default lifecycle: starts both VMs (deploys the unikernel image
# if needed), runs the workloads, stops both VMs. `--keep-running`
# leaves them up for iterative debug; `--no-redeploy` skips the
# image rebuild + upload and just re-uses whatever's currently
# deployed.
#
# Usage:
#   ./scripts/gcp-deploy-bench.sh                              # full deploy + bench
#   ./scripts/gcp-deploy-bench.sh --workload h3_health_max     # one workload
#   ./scripts/gcp-deploy-bench.sh --no-redeploy --keep-running # iterate locally
#   ./scripts/gcp-deploy-bench.sh --no-redeploy --par 64 --duration 5
#                                                              # raw loadgen call,
#                                                              # bypass bench harness
#
# Env overrides: same as deploy-gcloud.sh (UNIKERNEL_GCE_*) plus
#   GCP_KVM_VM_NAME (default: `kvm-vm`)
#   GCP_KVM_VM_ZONE (default: same as deploy zone)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

UNI_NAME="${UNIKERNEL_GCE_NAME:-unikernel-webserver}"
UNI_ZONE="${UNIKERNEL_GCE_ZONE:-us-west1-a}"

KVM_NAME="${GCP_KVM_VM_NAME:-kvm-vm}"
KVM_ZONE="${GCP_KVM_VM_ZONE:-$UNI_ZONE}"

# Default workload set, picked to give signal across both protocol
# stacks AND both small/large body shapes:
#
#   * `health_max`           — /health over plain HTTP. Pure
#                              throughput baseline (we hit 466K
#                              req/s on c3 here in 2026-05-09).
#   * `health_tls_max`       — /health over TLS-over-TCP. Same
#                              80 B body, exercises TLS record
#                              hot path (1 record per request).
#   * `h3_health_max`        — /health over QUIC. QUIC TX path
#                              equivalent of the above.
#   * `diagnostics_tls_max`  — /diagnostics (~9 KB HTML) over
#                              TLS-over-TCP. Required to make
#                              per-byte memcpy + CSUM-offload +
#                              TSO wins visible — the small-body
#                              workloads can't surface them
#                              above run-to-run noise.
#   * `h3_diagnostics_max`   — same multi-packet body but over
#                              QUIC, so cross-protocol perf on
#                              larger bodies is comparable.
DEFAULT_WORKLOADS="health_max,health_tls_max,h3_health_max,diagnostics_tls_max,h3_diagnostics_max"
DEFAULT_CORES="1,2,4"
DEFAULT_DURATION="10"

do_redeploy=1
do_stop=1
mode="harness"            # `harness` (bench.py) or `raw` (one loadgen call)
workloads=""
cores=""
duration=""
par=""
warmup="1"
endpoint="/health"

while [ $# -gt 0 ]; do
    case "$1" in
        --no-redeploy)   do_redeploy=0 ;;
        --keep-running)  do_stop=0 ;;
        --workload)      shift; workloads="$1" ;;
        --workload=*)    workloads="${1#--workload=}" ;;
        --cores)         shift; cores="$1" ;;
        --cores=*)       cores="${1#--cores=}" ;;
        --duration)      shift; duration="$1" ;;
        --duration=*)    duration="${1#--duration=}" ;;
        --par)           shift; mode="raw"; par="$1" ;;
        --par=*)         mode="raw"; par="${1#--par=}" ;;
        --warmup)        shift; warmup="$1" ;;
        --endpoint)      shift; endpoint="$1" ;;
        --endpoint=*)    endpoint="${1#--endpoint=}" ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# *//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

[ -n "$workloads" ] || workloads="$DEFAULT_WORKLOADS"
[ -n "$cores" ]     || cores="$DEFAULT_CORES"
[ -n "$duration" ]  || duration="$DEFAULT_DURATION"

# Resolve project for gcloud calls (same shape as deploy-gcloud.sh).
PROJECT="${UNIKERNEL_GCE_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
if [ -z "$PROJECT" ]; then
    echo "Error: no GCP project (set UNIKERNEL_GCE_PROJECT or 'gcloud config set project')" >&2
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────

# instance_status NAME ZONE
instance_status() {
    gcloud compute instances describe "$1" --zone="$2" --project="$PROJECT" \
        --format='value(status)' 2>/dev/null || echo "MISSING"
}

# instance_internal_ip NAME ZONE
instance_internal_ip() {
    gcloud compute instances describe "$1" --zone="$2" --project="$PROJECT" \
        --format='value(networkInterfaces[0].networkIP)' 2>/dev/null
}

# Start an instance (idempotent — no-op if already RUNNING). After
# returning, sshd may still be coming up — call `wait_for_ssh`
# before issuing scp/ssh.
start_if_stopped() {
    local name="$1" zone="$2"
    local s
    s="$(instance_status "$name" "$zone")"
    case "$s" in
        RUNNING) ;;
        TERMINATED|STOPPED)
            echo "==> Starting $name..."
            gcloud compute instances start "$name" --zone="$zone" \
                --project="$PROJECT" >/dev/null
            ;;
        STOPPING) wait_until_stopped "$name" "$zone"; start_if_stopped "$name" "$zone" ;;
        MISSING) echo "Error: $name not found in zone $zone" >&2; exit 1 ;;
        *)
            echo "==> $name in transient state $s — waiting..."
            until [ "$(instance_status "$name" "$zone")" = "RUNNING" ]; do
                sleep 3
            done
            ;;
    esac
}

# Wait for sshd to accept connections. `gcloud compute ssh` doesn't
# always handle the post-start window where the VM is RUNNING but
# sshd isn't ready yet; retry up to ~60 s with a no-op `true` before
# falling through. (Times out fast when ssh is broken — no point
# waiting forever for misconfig.)
wait_for_ssh() {
    local name="$1" zone="$2"
    local i=0
    while [ $i -lt 30 ]; do
        if gcloud compute ssh "$name" --zone="$zone" --project="$PROJECT" \
                --command='true' >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        i=$((i+1))
    done
    echo "Error: ssh to $name didn't come up within 60s" >&2
    return 1
}

# Wait for instance to reach STOPPED / TERMINATED.
wait_until_stopped() {
    local name="$1" zone="$2"
    until case "$(instance_status "$name" "$zone")" in
              STOPPED|TERMINATED|MISSING) true ;;
              *) false ;;
          esac; do
        sleep 3
    done
}

# Run command on kvm-vm via `gcloud compute ssh` (which handles
# IAP-tunnelled or external-IP routing, project-scoped keys, etc.
# More robust than a raw `ssh` against a host alias whose IP
# changes on every start).
kvm_ssh() {
    gcloud compute ssh "$KVM_NAME" --zone="$KVM_ZONE" \
        --project="$PROJECT" --command="$1"
}

kvm_scp() {
    gcloud compute scp --zone="$KVM_ZONE" --project="$PROJECT" "$@"
}

# ── Step 1: deploy the unikernel ──────────────────────────────────

if [ $do_redeploy -eq 1 ]; then
    echo "==> Deploying $UNI_NAME (rebuild + upload + image + VM)..."
    "$SCRIPT_DIR/deploy-gcloud.sh" deploy
else
    echo "==> --no-redeploy: skipping image rebuild; ensuring $UNI_NAME is running..."
    start_if_stopped "$UNI_NAME" "$UNI_ZONE"
fi

UNI_IP="$(instance_internal_ip "$UNI_NAME" "$UNI_ZONE")"
[ -n "$UNI_IP" ] || { echo "Error: couldn't read $UNI_NAME's internal IP" >&2; exit 1; }
echo "    $UNI_NAME internal IP: $UNI_IP"

# ── Step 2: ensure kvm-vm is running, sync the bench files ────────

start_if_stopped "$KVM_NAME" "$KVM_ZONE"
wait_for_ssh    "$KVM_NAME" "$KVM_ZONE"

# Sync only what changed: cli.py / workloads.py / envs.py + the
# loadgen sources. The bench harness's `--no-build` skips the
# loadgen recompile if the binary already exists; we drive that
# from the harness side (rsync the sources, then trigger build).
echo "==> Syncing bench harness + loadgen to $KVM_NAME..."
# Skip the heavy loadgen target/ directory (compiled artefacts).
SYNC_FILES=("$SCRIPT_DIR/bench.py" "$SCRIPT_DIR/bench")
TARBALL="/tmp/gcp-deploy-bench-sync.tar"
## macOS bsdtar archives `com.apple.provenance` Gatekeeper xattrs
## as PAX `LIBARCHIVE.xattr.*` headers, which GNU tar on the
## remote then warns about on every entry ("Ignoring unknown
## extended header keyword …"). `COPYFILE_DISABLE` only
## suppresses AppleDouble (`._foo`) resource forks, not xattrs —
## `--no-xattrs` is what actually drops the headers at create
## time. Belt-and-braces: keep both, since `COPYFILE_DISABLE` is
## still doing useful work for resource forks.
COPYFILE_DISABLE=1 tar --no-xattrs \
    --exclude='loadgen/target' \
    --exclude='loadgen/Cargo.lock' \
    --exclude='__pycache__' \
    -C "$SCRIPT_DIR" -cf "$TARBALL" \
    bench.py bench/
kvm_scp "$TARBALL" "$KVM_NAME:/tmp/" >/dev/null
kvm_ssh "mkdir -p ~/bench && tar -xf /tmp/$(basename "$TARBALL") -C ~/bench && rm /tmp/$(basename "$TARBALL")"

# Rebuild loadgen on kvm-vm (cheap if no source changes; cargo
# detects unchanged inputs and reuses the binary).
echo "==> Building loadgen on $KVM_NAME..."
kvm_ssh "cd ~/bench/bench/loadgen && PATH=\$HOME/.cargo/bin:\$PATH cargo build --release 2>&1 | tail -3"

# ── Step 3: run the bench ─────────────────────────────────────────

if [ "$mode" = "raw" ]; then
    # Direct loadgen call — bypass the harness for ad-hoc parallelism.
    echo "==> Running loadgen h3-health (par=$par, duration=${duration}s, warmup=${warmup}s)..."
    kvm_ssh "~/bench/bench/loadgen/target/release/loadgen h3-health \
        --host $UNI_IP --port 443 --endpoint $endpoint \
        --duration-secs $duration --warmup-secs $warmup --parallelism $par"
else
    # Drive the bench harness in `--env remote` mode against the
    # deployed unikernel. The harness's `RemoteEnv` honours
    # `--target IP` and the per-workload `parallelism_per_core`
    # scaling (mirroring how nested-KVM benches scale).
    echo "==> Running bench harness against $UNI_IP..."
    echo "    cores=$cores  duration=${duration}s  workloads=$workloads"
    kvm_ssh "cd ~/bench && python3 bench.py \
        --env remote --target $UNI_IP \
        --cores $cores --duration $duration --workload $workloads"
fi

# ── Step 4: tear down (unless --keep-running) ─────────────────────

if [ $do_stop -eq 1 ]; then
    echo "==> Stopping $UNI_NAME + $KVM_NAME..."
    gcloud compute instances stop "$UNI_NAME" "$KVM_NAME" \
        --zone="$UNI_ZONE" --project="$PROJECT" --async >/dev/null
    echo "    (stop dispatched async; check 'gcloud compute instances list' to confirm)"
else
    echo "==> --keep-running: leaving $UNI_NAME + $KVM_NAME up."
fi
