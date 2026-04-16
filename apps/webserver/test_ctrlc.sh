#!/usr/bin/env bash
# apps/webserver/test_ctrlc.sh — Boot the webserver via QEMU (aarch64) or the
# HVF runner, hammer it with traffic, then send a Ctrl-C byte on the guest
# serial and verify the VM exits within a reasonable deadline.
#
# This is a regression test for the IRQ-storm class of bugs where a virtio
# misconfiguration starves the event loop: the guest boots, but CPU is stuck
# in an interrupt storm so `check_shutdown` never runs. Symptom: Ctrl-C
# "hangs" instead of cleanly powering the VM off.
#
#   bazel test --config=hvf          //apps/webserver:test_ctrlc
#   bazel test --config=aarch64-qemu //apps/webserver:test_ctrlc

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

# Host must have python3 (installed by default on macOS and most Linux).
command -v python3 &>/dev/null || { echo "SKIP: python3 not found"; exit 0; }

# Pick a runner command. The Python harness runs it under a PTY so the
# `-chardev stdio,signal=off` / raw-mode-stdin paths expose their serial
# RX to the test.
CMD=()
BOOT_MARKER='[BOOT] Entering event loop'

case "${1:-auto}" in
    hvf|auto)
        if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] \
                && [[ -x "${RUNFILES}/_main/tools/hvf-runner/run-hvf" ]]; then
            IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
            [[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found"; exit 1; }
            CMD=(
                "${RUNFILES}/_main/tools/hvf-runner/run-hvf"
                "$IMG"
                -p "tcp:18200:80"
                -p "tcp:18201:443"
            )
        fi
        ;;
esac

if [[ ${#CMD[@]} -eq 0 ]]; then
    # Fall through to QEMU. Reuse detect_qemu for machine args.
    ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"
    if [[ ! -f "$ELF" ]]; then
        echo "SKIP: no runner available (hvf-runner absent, webserver.elf missing)"
        exit 0
    fi
    detect_qemu "$ELF"
    command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }
    CMD=(
        "$QEMU_BIN"
        "${QEMU_MACHINE[@]}"
        -m 128 -smp 1
        -display none -monitor none
        -chardev stdio,id=s0,signal=off -serial chardev:s0
        -no-reboot
        -device "${VIRTIO_DEV},netdev=net0"
        -netdev "user,id=net0,hostfwd=tcp::18200-:80,hostfwd=tcp::18201-:443"
        -kernel "$KERNEL_ARG"
    )
fi

echo "==> Boot + Ctrl-C test:  ${CMD[*]}"

python3 - "${CMD[@]}" <<'PY'
import os, pty, select, signal, sys, time

argv = sys.argv[1:]
boot_marker = b'[BOOT] Entering event loop'

pid, fd = pty.fork()
if pid == 0:
    # Child: run the VM under the PTY.
    os.execvp(argv[0], argv)

def drain(fd, timeout=0.1):
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return b''
    try:
        return os.read(fd, 4096)
    except OSError:
        return b''

# 1. Wait up to 15s for the boot marker.
buf = b''
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    chunk = drain(fd, 0.2)
    if chunk:
        buf += chunk
        if boot_marker in buf:
            break
else:
    print("FAIL: VM didn't reach boot marker within 15s")
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    sys.exit(1)

print(f"    booted ({len(buf)} bytes output)")

# 2. Hammer the HTTP port so the event loop is actively serving when we
#    send Ctrl-C. If the shutdown path hangs only under load, this will
#    expose it.
import subprocess, threading
stop = [False]
def hammer():
    while not stop[0]:
        subprocess.run(
            ['curl', '-s', '--max-time', '1', 'http://127.0.0.1:18200/health'],
            capture_output=True,
        )
workers = [threading.Thread(target=hammer, daemon=True) for _ in range(3)]
for w in workers: w.start()
time.sleep(2)   # let traffic flow

# 3. Send Ctrl-C on the guest serial and wait for graceful exit.
print("    sending ^C …")
t0 = time.monotonic()
os.write(fd, b'\x03')

exited = False
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    drain(fd, 0.1)   # keep the PTY buffer flowing
    r, _ = os.waitpid(pid, os.WNOHANG)
    if r == pid:
        exited = True
        break

stop[0] = True
elapsed = time.monotonic() - t0

if exited:
    print(f"    exited {elapsed:.2f}s after ^C — OK")
    sys.exit(0)

print(f"FAIL: VM still running 8s after ^C (hung)")
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
sys.exit(1)
PY
