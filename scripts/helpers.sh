#!/usr/bin/env bash
# scripts/helpers.sh — Shared helpers for run, test, and bench scripts.
#
# Source this file; do not execute it directly.
#   source "$(dirname "$0")/helpers.sh"                     (from scripts/)
#   source "$BUILD_WORKSPACE_DIRECTORY/scripts/helpers.sh"  (from bazel run)
#   source "${RUNFILES}/_main/scripts/helpers.sh"           (from bazel test)

# ── QEMU configuration ──────────────────────────────────────────────────────
# Detect QEMU binary, machine args, and virtio device type from an ELF.
#
# Usage: detect_qemu "$ELF"
# Sets:  QEMU_BIN  QEMU_MACHINE  VIRTIO_DEV  KERNEL_ARG
detect_qemu() {
    local elf="$1"
    local info
    info="$(file "$elf" 2>/dev/null || echo "")"

    if echo "$info" | grep -q "ARM aarch64"; then
        QEMU_BIN="qemu-system-aarch64"
        QEMU_MACHINE=(-machine virt -cpu max)
        VIRTIO_DEV="virtio-net-device"
        # aarch64 QEMU needs raw .img, not ELF
        KERNEL_ARG="${elf%.elf}.img"
        [[ -f "$KERNEL_ARG" ]] || { echo "error: .img not found: $KERNEL_ARG" >&2; return 1; }
    else
        QEMU_BIN="qemu-system-x86_64"
        VIRTIO_DEV="virtio-net-pci"
        KERNEL_ARG="$elf"
        # CPU model choice:
        #
        #   - Accelerated (KVM/HVF):  -cpu host  pass-through so the
        #     guest sees the real host's feature set. On any modern
        #     GCP / Apple Silicon x86 host that includes AVX/AVX2,
        #     which our p256 + chacha20poly1305 builds rely on.
        #
        #   - TCG emulation:  -cpu max  enables every feature TCG
        #     can simulate, including AVX. `-cpu qemu64` (the QEMU
        #     default) is pre-AVX and makes the compiled crypto
        #     crates crash with #UD the first time they emit a
        #     VMOVDQU — we learned this the hard way when TLS init
        #     started doing a d*G scalar mult at boot time.
        #
        # HVF on Apple Silicon arm64 never accelerates x86 guests,
        # so that branch only ever activates on an x86_64 macOS host
        # (which in practice doesn't exist anymore — every current
        # Mac is aarch64).
        if [[ "$(uname -m)" = "x86_64" ]]; then
            if [[ "$(uname -s)" = "Darwin" ]] && sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
                QEMU_MACHINE=(-cpu host -accel hvf)
            elif [[ "$(uname -s)" = "Linux" ]] && [[ -r /dev/kvm ]]; then
                QEMU_MACHINE=(-cpu host -accel kvm)
            else
                QEMU_MACHINE=(-cpu max)
            fi
        else
            QEMU_MACHINE=(-cpu max)
        fi
    fi
}

# ── VM lifecycle ─────────────────────────────────────────────────────────────
# Kill background VM and remove log file.
# Usage: trap cleanup_vm EXIT
cleanup_vm() {
    if [[ -n "${VM_PID:-}" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    [[ -n "${VM_LOG:-}" ]] && rm -f "$VM_LOG" || true
}

# Start QEMU in background.
# Usage: start_qemu PORT [LOG] [EXTRA_QEMU_ARGS...]
#   LOG: log file path; omit or pass "" to create a tempfile (sets VM_LOG).
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu or manually).
# Sets: VM_PID; sets VM_LOG if LOG is empty.
start_qemu() {
    local port="$1" log="${2:-}"; shift 2
    if [[ -z "$log" ]]; then
        VM_LOG="$(mktemp /tmp/unikernel_test_XXXXXXXX)"
        log="$VM_LOG"
    fi
    local cpus="${UNIKERNEL_CPUS:-1}"
    local dev_extra=""
    # Enable VirtIO multi-queue for PCI devices with multiple vCPUs.
    # MMIO devices (virtio-net-device) don't support mq parameter.
    # user-mode netdev doesn't support queues= parameter.
    if [[ "$cpus" -gt 1 ]] && [[ "$VIRTIO_DEV" == *"-pci"* ]]; then
        local vectors=$(( 2 * cpus + 2 ))
        dev_extra=",mq=on,vectors=$vectors"
    fi
    "$QEMU_BIN" \
        "$@" \
        -m 128 -smp "$cpus" -nographic \
        -serial "file:${log}" \
        -no-reboot \
        -device "${VIRTIO_DEV}${dev_extra}",netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${port}-:80,hostfwd=udp::$((port+1))-:7" \
        &>/dev/null &
    VM_PID=$!
}

# Exec QEMU interactively (for `bazel run` targets).
# Usage: run_qemu PORT TLS_PORT MEMORY [EXTRA_QEMU_ARGS...]
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu or manually).
run_qemu() {
    local port="$1" tls_port="$2" memory="$3"; shift 3
    exec "$QEMU_BIN" \
        "$@" \
        -m "$memory" -smp 1 \
        -display none -monitor none \
        -chardev stdio,id=s0,signal=off -serial chardev:s0 \
        -no-reboot \
        -device "${VIRTIO_DEV}",netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${port}-:80,hostfwd=tcp::${tls_port}-:443"
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
# Wait for an HTTP endpoint to respond.
# Usage: wait_http PORT [TIMEOUT] [PID] [HOST] [ENDPOINT]
wait_http() {
    local port=$1 timeout=${2:-60} pid=${3:-""} host=${4:-"127.0.0.1"} endpoint=${5:-"/"}
    local elapsed=0
    while ! curl -sf --max-time 3 "http://${host}:${port}${endpoint}" >/dev/null 2>&1; do
        if [[ $elapsed -ge $timeout ]]; then return 1; fi
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then return 1; fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 0
}

# Test an HTTP endpoint.  Returns 0 on pass, 1 on fail.
# Usage: check_http DESC URL WANT_STATUS [WANT_BODY]
check_http() {
    local desc="$1" url="$2" want_status="$3" want_body="${4:-}"
    local resp body status ok=1
    resp="$(curl -s -w $'\n%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$resp" | sed '$d')"
    status="$(echo "$resp" | tail -n1)"
    [[ "$status" == "$want_status" ]] || ok=0
    [[ -z "$want_body" ]] || echo "$body" | grep -q "$want_body" || ok=0
    if [[ $ok -eq 1 ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc (status=$status)"
        return 1
    fi
}

# ── HTTPS helpers ────────────────────────────────────────────────────────────
# The hand-rolled TLS 1.3 server uses an ECDSA P-256 dev cert +
# TLS_CHACHA20_POLY1305_SHA256, both of which every TLS 1.3 client
# supports — including macOS's bundled LibreSSL 3.x. All HTTPS helpers
# below assume the caller has set:
#   OPENSSL     — path to openssl binary (set by find_openssl)
#   VM_HOST     — default 127.0.0.1
#   VM_PORT     — port the server is listening on
#   DEV_CERT    — path to dev_cert.pem (for `-CAfile`)
#   VM_SNI      — SNI / Host: header (default unikernel.local)

# Find any TLS-1.3-capable openssl binary. We prefer Homebrew OpenSSL 3
# when present because its `-groups` / `-sigalgs` flags are handy for
# debugging handshakes, but macOS system LibreSSL also works. Sets
# OPENSSL on success and returns 0; returns 1 if nothing is found
# (caller can `exit 0` with a SKIP message in that case).
find_openssl() {
    local candidate ver
    for candidate in \
            /opt/homebrew/bin/openssl \
            /opt/homebrew/opt/openssl@3/bin/openssl \
            /usr/local/bin/openssl \
            /usr/local/opt/openssl@3/bin/openssl \
            /usr/bin/openssl \
            openssl; do
        if command -v "$candidate" &>/dev/null; then
            ver="$("$candidate" version 2>&1 || true)"
            # Accept OpenSSL 1.1.1+ / OpenSSL 3.x / LibreSSL 3.x.
            if [[ "$ver" == OpenSSL\ 3.* ]] \
                    || [[ "$ver" == OpenSSL\ 1.1.1* ]] \
                    || [[ "$ver" == LibreSSL\ 3.* ]]; then
                OPENSSL="$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# Bounded command runner. macOS has no GNU `timeout`; use perl (always
# present) to fork+exec the child under an alarm and escalate TERM→KILL
# on expiry. Exits 124 on timeout, otherwise the child's exit code.
# Usage: run_timeout SECONDS CMD [ARGS...]
run_timeout() {
    perl -e '
        my $t = shift;
        my $pid = fork // die "fork: $!";
        if ($pid == 0) { exec { $ARGV[0] } @ARGV or exit 127; }
        local $SIG{ALRM} = sub {
            kill TERM => $pid;
            select undef, undef, undef, 0.5;
            kill KILL => $pid;
        };
        alarm $t;
        waitpid $pid, 0;
        alarm 0;
        exit(($? & 127) ? 124 : ($? >> 8));
    ' "$@"
}

# Issue one HTTPS request, bounded by run_timeout. Prints the raw response
# (headers + body) to stdout, discards openssl stderr. Exit 124 if the
# handshake or response hangs (e.g. server wedged mid-connection), 0
# otherwise regardless of HTTP status — callers parse the status line.
#
# Usage: https_get PATH [TIMEOUT_S]
https_get() {
    local path="$1" timeout_s="${2:-5}"
    local host="${VM_HOST:-127.0.0.1}"
    local sni="${VM_SNI:-unikernel.local}"
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$path" "$sni" | \
        run_timeout "$timeout_s" \
            "$OPENSSL" s_client -connect "${host}:${VM_PORT}" -tls1_3 \
                -CAfile "$DEV_CERT" -servername "$sni" -quiet 2>/dev/null
}

# Poll until the server returns HTTP/1.1 200 on `path`. Bounded by
# `timeout` total seconds; if `pid` is non-empty, bails early when that
# PID dies. Returns 0 when the server answers 200, 1 on timeout.
#
# Usage: wait_https PATH TIMEOUT [PID]
wait_https() {
    local path="$1" timeout="$2" pid="${3:-}"
    local elapsed=0 status_line
    while :; do
        status_line="$(https_get "$path" 3 | head -1 | tr -d '\r' || true)"
        [[ "$status_line" == HTTP/1.1\ 200* ]] && return 0
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then return 1; fi
        if [[ $elapsed -ge $timeout ]]; then return 1; fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# Test an HTTPS endpoint. Returns 0 on pass, 1 on fail.
# Usage: check_https DESC PATH WANT_STATUS [WANT_BODY]
check_https() {
    local desc="$1" path="$2" want_status="$3" want_body="${4:-}"
    local resp status_line ok=1
    resp="$(https_get "$path" 10)"
    status_line="$(echo "$resp" | head -1 | tr -d '\r')"
    if [[ "$status_line" == "HTTP/1.1 $want_status"* ]]; then
        if [[ -n "$want_body" ]] && ! echo "$resp" | grep -q "$want_body"; then
            echo "  FAIL: $desc — missing '$want_body' in body"
            return 1
        fi
        echo "  PASS: $desc"
        return 0
    fi
    echo "  FAIL: $desc — got '$status_line', expected HTTP/1.1 $want_status"
    return 1
}

# Run a burst of N sequential HTTPS GETs against `path`; all must return
# HTTP/1.1 200. Regression guard for rapid-reconnect races in the guest
# TLS state machine and/or userspace TCP relay. Returns 0 on full pass,
# 1 on any failure.
#
# Usage: burst_https DESC PATH N
burst_https() {
    local desc="$1" path="$2" n="$3"
    local fails=0 status_line i
    echo "==> ${desc}: ${n} sequential HTTPS GETs to ${path}..."
    for i in $(seq 1 "$n"); do
        status_line="$(https_get "$path" 5 | head -1 | tr -d '\r' || true)"
        if [[ "$status_line" != "HTTP/1.1 200"* ]]; then
            fails=$((fails + 1))
            [[ $fails -le 3 ]] && echo "  req $i: got '${status_line}'"
        fi
    done
    if [[ $fails -eq 0 ]]; then
        echo "  PASS: burst (${n}/${n})"
        return 0
    fi
    echo "  FAIL: burst — ${fails}/${n} requests failed"
    return 1
}
