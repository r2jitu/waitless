#!/usr/bin/env bash
# gcp-bench.sh — Run bench.py on the GCP KVM host.
#
# Both the unikernel VM (or native binary) and the workload generator
# run on the remote host (loopback only) for lowest-overhead measurements.
#
# By default the script starts the instance if it's STOPPED, runs the
# bench, and stops it again at the end so minimum compute is billed.
# Use `--keep-running` to skip the post-run stop (handy for iterative
# debug sessions where you're about to run another bench).
#
# Default cores are 1,2,3 — the GCP host is 8 vCPUs, and the fair
# upper bound for a scaling comparison leaves room for wrk + per-
# queue vhost-net kthreads (each vCPU gets its own vhost kthread).
# 3 vCPUs + 3 vhost kthreads + wrk = ~7 busy threads, which fits
# comfortably. Pass `--cores 1,2,4,8` if you want to see the ceiling.
#
# Usage:
#   ./scripts/gcp-bench.sh                           # kvm + native, 1,2,4 cores
#   ./scripts/gcp-bench.sh --env kvm                 # kvm only
#   ./scripts/gcp-bench.sh --cores 1,4 --duration 10
#   ./scripts/gcp-bench.sh --workload get_tcp
#   ./scripts/gcp-bench.sh --no-build                # skip local rebuild
#   ./scripts/gcp-bench.sh --keep-running            # don't stop host after
#
# Any args not consumed here are forwarded to bench.py verbatim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SSH_HOST="${GCP_SSH_HOST:-gcp}"
REMOTE_DIR="${GCP_REMOTE_DIR:-bench}"

# Default args; overridden by user-supplied flags.
DEFAULT_CORES="1,2,3"
DEFAULT_DURATION="10"
DEFAULT_ENV="kvm,native"

do_build=1
do_stop=1
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
    --keep-running) do_stop=0 ;;
    --cores | --cores=*)
        have_cores=1
        bench_args+=("$arg")
        ;;
    --duration | --duration=*)
        have_duration=1
        bench_args+=("$arg")
        ;;
    --env)
        i=$((i + 1))
        env_arg="${argv[$i]}"
        ;;
    --env=*) env_arg="${arg#--env=}" ;;
    *) bench_args+=("$arg") ;;
    esac
    i=$((i + 1))
done
[ $have_cores -eq 0 ] && bench_args+=(--cores "$DEFAULT_CORES")
[ $have_duration -eq 0 ] && bench_args+=(--duration "$DEFAULT_DURATION")
[ -z "$env_arg" ] && env_arg="$DEFAULT_ENV"
bench_args+=(--env "$env_arg")

# Decide which binaries we need based on the env list.
need_kvm=0
need_native=0
case ",$env_arg," in *,kvm,*) need_kvm=1 ;; esac
case ",$env_arg," in *,native,*) need_native=1 ;; esac

if [ $need_kvm -eq 1 ]; then
    bench_args+=(--elf "\$HOME/$REMOTE_DIR/webserver_qemu_x86_64.elf")
fi
if [ $need_native -eq 1 ]; then
    # `:webserver_bin` is the underlying rust_binary;
    # `:webserver_native` is a launcher script that bakes BUILD-default
    # `WAITLESS_*` env vars. Bench sets every var explicitly, so the
    # launcher's defaults are no-ops — staging the raw binary skips
    # the launcher's runfile bookkeeping.
    bench_args+=(--native-bin "\$HOME/$REMOTE_DIR/webserver_bin")
fi

if [ $do_build -eq 1 ]; then
    cd "$PROJECT_ROOT"
    if [ $need_kvm -eq 1 ]; then
        echo "==> Building :webserver_qemu_x86_64..."
        bazel build //apps/webserver:webserver_qemu_x86_64
    fi
    if [ $need_native -eq 1 ]; then
        echo "==> Building :webserver_bin (x86_64-linux)..."
        bazel build --config=x86_64-linux //apps/webserver:webserver_bin
    fi
fi

# rsync the `scripts/bench/` package directory + the bench.py shim;
# the shim adds its own directory to sys.path so `from bench.cli
# import main` resolves to the sibling package. udp_bench.c and
# bench-tap-setup.sh ride along inside `bench/` and are located via
# `os.path.dirname(__file__)` — no bazel runfiles machinery.
sync_files=("$SCRIPT_DIR/bench.py" "$SCRIPT_DIR/bench")
if [ $need_kvm -eq 1 ]; then
    # `webserver.elf` is the host-default-platform build — on an
    # Apple-Silicon local that's aarch64 and QEMU on the GCP x86_64
    # host refuses it ("Error while loading elf kernel"). Ship the
    # explicit x86_64 variant and alias it to `webserver.elf` on the
    # remote so KvmEnv's `--elf` path resolves unchanged.
    ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_qemu_x86_64.elf"
    [ -f "$ELF" ] || {
        echo "error: $ELF not found; run without --no-build" >&2
        exit 1
    }
    sync_files+=("$ELF")
fi
if [ $need_native -eq 1 ]; then
    NBIN="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_bin"
    [ -f "$NBIN" ] || {
        echo "error: $NBIN not found; run without --no-build" >&2
        exit 1
    }
    sync_files+=("$NBIN")
fi

# Auto-start the instance if it's stopped, so the user doesn't have to
# remember to spin it up manually. `gcp.sh start` also refreshes the
# SSH config HostName since GCE re-rolls the external IP.
instance_status=$("$SCRIPT_DIR/gcp.sh" status 2>/dev/null | awk 'NR>1 {print $2}' || true)
if [ "$instance_status" = "TERMINATED" ] || [ "$instance_status" = "STOPPED" ]; then
    echo "==> Instance is $instance_status — starting..."
    "$SCRIPT_DIR/gcp.sh" start >/dev/null
    # Wait until SSH comes up (up to 60s). accept-new auto-adds the
    # fresh host key for the rolled-over external IP.
    for _try in $(seq 1 60); do
        if ssh -o ConnectTimeout=3 -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new \
            "$SSH_HOST" true 2>/dev/null; then
            break
        fi
        sleep 1
    done
fi

# Stop the instance on exit (including Ctrl-C), unless `--keep-running`.
if [ $do_stop -eq 1 ]; then
    trap '"$SCRIPT_DIR/gcp.sh" stop >/dev/null 2>&1 || true' EXIT
fi

echo "==> Syncing files to $SSH_HOST:~/$REMOTE_DIR/..."
ssh "$SSH_HOST" "mkdir -p ~/$REMOTE_DIR && chmod -R u+w ~/$REMOTE_DIR"
# rsync preserves mtimes so subsequent runs skip unchanged files.
# `-L` dereferences symlinks on the source side — `bazel-bin/...`
# entries are symlinks into the bazel cache, so a plain `-a` copy
# would send a broken link to the remote.
#
# `--exclude target/` avoids syncing the loadgen crate's locally-
# built macOS-arm64 binary; cargo on the GCP host rebuilds it for
# x86_64-linux on first bench run (~30s, then cached).
rsync -azL --partial --exclude 'target/' \
    "${sync_files[@]}" "$SSH_HOST:$REMOTE_DIR/"

# Run bench.py on the remote.
#
# bench.py is a 3-line shim that imports bench.cli; sys.path[0] is
# its own dir (~/bench) so the sibling `bench/` package resolves.
# KvmEnv.build() does tap0 + NAT setup by invoking the colocated
# bench-tap-setup.sh, and the workloads module compiles udp_bench
# on first UDP test. No pre-steps needed here.
#
# `-tt` allocates a PTY so Ctrl-C kills the remote process — but a PTY
# also makes ssh wait for an exit event before flushing. We force python
# to be unbuffered with `-u` and cli.main() reconfigures stdout to
# line-buffered, so output streams in real time even when the caller
# pipes this script through `tee` or `tail`.
echo "==> Running bench.py on $SSH_HOST: ${bench_args[*]}"
echo ""
ssh -tt "$SSH_HOST" "cd $REMOTE_DIR && python3 -u bench.py ${bench_args[*]}"
