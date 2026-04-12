#!/usr/bin/env bash
# gcp-bench.sh — Run bench.py on the GCP KVM host.
#
# Both the unikernel VM (or native binary) and the workload generator
# run on the remote host (loopback only) for lowest-overhead measurements.
#
# Usage:
#   ./scripts/gcp-bench.sh                           # kvm + native, 1,2,4,8 cores
#   ./scripts/gcp-bench.sh --env kvm                 # kvm only
#   ./scripts/gcp-bench.sh --env native              # native Linux only
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
DEFAULT_ENV="kvm,native"

do_build=1
bench_args=()
have_cores=0
have_duration=0
env_arg=""
i=0
argv=("$@")
while [ $i -lt ${#argv[@]} ]; do
    arg="${argv[$i]}"
    case "$arg" in
        --no-build) do_build=0 ;;
        --cores|--cores=*) have_cores=1; bench_args+=("$arg") ;;
        --duration|--duration=*) have_duration=1; bench_args+=("$arg") ;;
        --env) i=$((i+1)); env_arg="${argv[$i]}" ;;
        --env=*) env_arg="${arg#--env=}" ;;
        *) bench_args+=("$arg") ;;
    esac
    i=$((i+1))
done
[ $have_cores    -eq 0 ] && bench_args+=(--cores "$DEFAULT_CORES")
[ $have_duration -eq 0 ] && bench_args+=(--duration "$DEFAULT_DURATION")
[ -z "$env_arg" ] && env_arg="$DEFAULT_ENV"
bench_args+=(--env "$env_arg")

# Decide which binaries we need based on the env list.
need_kvm=0
need_native=0
case ",$env_arg," in *,kvm,*)    need_kvm=1 ;; esac
case ",$env_arg," in *,native,*) need_native=1 ;; esac

if [ $need_kvm -eq 1 ]; then
    bench_args+=(--elf "\$HOME/$REMOTE_DIR/webserver.elf")
fi
if [ $need_native -eq 1 ]; then
    bench_args+=(--native-bin "\$HOME/$REMOTE_DIR/webserver_native")
fi

if [ $do_build -eq 1 ]; then
    cd "$PROJECT_ROOT"
    if [ $need_kvm -eq 1 ]; then
        echo "==> Building webserver.elf (x86_64-qemu)..."
        bazel build --config=x86_64-qemu //apps/webserver:webserver.elf
    fi
    if [ $need_native -eq 1 ]; then
        echo "==> Building webserver_native (x86_64-linux)..."
        bazel build --config=x86_64-linux //apps/webserver:webserver_native
    fi
fi

sync_files=("$SCRIPT_DIR/bench.py" "$SCRIPT_DIR/udp_bench.c"
            "$SCRIPT_DIR/bench-tap-setup.sh")
if [ $need_kvm -eq 1 ]; then
    ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    [ -f "$ELF" ] || { echo "error: $ELF not found; run without --no-build" >&2; exit 1; }
    sync_files+=("$ELF")
fi
if [ $need_native -eq 1 ]; then
    NBIN="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_native"
    [ -f "$NBIN" ] || { echo "error: $NBIN not found; run without --no-build" >&2; exit 1; }
    sync_files+=("$NBIN")
fi

echo "==> Syncing files to $SSH_HOST:~/$REMOTE_DIR/..."
ssh "$SSH_HOST" "mkdir -p ~/$REMOTE_DIR && chmod -R u+w ~/$REMOTE_DIR"
# rsync preserves mtimes so subsequent runs skip unchanged files.
rsync -az --partial "${sync_files[@]}" "$SSH_HOST:$REMOTE_DIR/"

# Build udp_bench on the remote if missing or stale, and force-recreate
# tap0 so vhost-net starts the bench with a clean slate (stale tap state
# from a prior run can break the very first udp_async test).
ssh "$SSH_HOST" "cd $REMOTE_DIR && \
    if [ ! -f udp_bench ] || [ udp_bench.c -nt udp_bench ]; then \
        cc -O2 -o udp_bench udp_bench.c -lpthread; \
    fi && \
    chmod +x bench-tap-setup.sh && \
    sudo ip link del tap0 2>/dev/null; \
    sudo ./bench-tap-setup.sh"

# Run bench.py on the remote.
#
# `-tt` allocates a PTY so Ctrl-C kills the remote process — but a PTY
# also makes ssh wait for an exit event before flushing. We force python
# to be unbuffered with `-u` and bench.py reconfigures stdout to line-
# buffered, so output streams in real time even when the caller pipes
# this script through `tee` or `tail`.
echo "==> Running bench.py on $SSH_HOST: ${bench_args[*]}"
echo ""
ssh -tt "$SSH_HOST" "cd $REMOTE_DIR && python3 -u bench.py ${bench_args[*]}"
