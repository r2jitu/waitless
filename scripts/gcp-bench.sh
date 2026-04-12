#!/usr/bin/env bash
# gcp-bench.sh — Run bench.py on the GCP KVM host.
#
# Both the unikernel VM and the workload generator run on the remote host
# (loopback between wrk and the guest) for lowest-overhead measurements.
#
# Usage:
#   ./scripts/gcp-bench.sh                           # 1,2,4,8 cores, all workloads
#   ./scripts/gcp-bench.sh --cores 1,4 --duration 10
#   ./scripts/gcp-bench.sh --workload compute_c8
#   ./scripts/gcp-bench.sh --no-build                # skip local rebuild
#
# Any args not consumed here are forwarded to bench.py verbatim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SSH_HOST="${GCP_SSH_HOST:-gcp}"
REMOTE_DIR="${GCP_REMOTE_DIR:-bench}"

# Default args; overridden by user-supplied flags.
DEFAULT_CORES="1,2,4,8"
DEFAULT_DURATION="10"

do_build=1
bench_args=()
have_cores=0
have_duration=0
for arg in "$@"; do
    case "$arg" in
        --no-build) do_build=0 ;;
        --cores|--cores=*) have_cores=1; bench_args+=("$arg") ;;
        --duration|--duration=*) have_duration=1; bench_args+=("$arg") ;;
        *) bench_args+=("$arg") ;;
    esac
done
[ $have_cores    -eq 0 ] && bench_args+=(--cores "$DEFAULT_CORES")
[ $have_duration -eq 0 ] && bench_args+=(--duration "$DEFAULT_DURATION")

# Always run the kvm env on the remote host.
bench_args+=(--env kvm --elf "\$HOME/$REMOTE_DIR/webserver.elf")

if [ $do_build -eq 1 ]; then
    echo "==> Building webserver.elf (x86_64-qemu)..."
    cd "$PROJECT_ROOT"
    bazel build --config=x86_64-qemu //apps/webserver:webserver.elf
fi

ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
if [ ! -f "$ELF" ]; then
    echo "error: $ELF not found; run without --no-build" >&2
    exit 1
fi

echo "==> Syncing files to $SSH_HOST:~/$REMOTE_DIR/..."
ssh "$SSH_HOST" "mkdir -p ~/$REMOTE_DIR"
# rsync preserves mtimes so subsequent runs skip unchanged files.
rsync -az --partial \
    "$ELF" \
    "$SCRIPT_DIR/bench.py" \
    "$SCRIPT_DIR/udp_bench.c" \
    "$SSH_HOST:$REMOTE_DIR/"

# Build udp_bench on the remote if missing or stale.
ssh "$SSH_HOST" "cd $REMOTE_DIR && \
    if [ ! -f udp_bench ] || [ udp_bench.c -nt udp_bench ]; then \
        cc -O2 -o udp_bench udp_bench.c -lpthread; \
    fi"

# Run bench.py on the remote. Use -tt so Ctrl-C here kills the remote process.
echo "==> Running bench.py on $SSH_HOST: ${bench_args[*]}"
echo ""
ssh -tt "$SSH_HOST" "cd $REMOTE_DIR && python3 bench.py ${bench_args[*]}"
