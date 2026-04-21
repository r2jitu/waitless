"""scripts/test_helpers.py — Shared utilities for Python integration tests.

Replaces the bash-side `scripts/helpers.sh` for test targets. Each app's
test.py imports from here to get:

  * Runfiles discovery (`runfiles_root()`).
  * QEMU runner detection (`detect_qemu()`).
  * Launcher spawning — backgrounded (for probes) or PTY-driven (for
    Ctrl-C / log-based tests).
  * HTTP / HTTPS / UDP probe helpers.

The bash `helpers.sh` sticks around for `bazel/rules/run_*.sh` interactive
launchers — those stay bash-native so `bazel run` keeps working without a
Python round-trip.
"""

from __future__ import annotations

import http.client
import os
import pty
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ── Runfiles ────────────────────────────────────────────────────────────────

def runfiles_root() -> Path:
    """Locate `_main/` in the current test's runfiles tree."""
    rf = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if rf:
        return Path(rf) / "_main"
    return Path(f"{sys.argv[0]}.runfiles") / "_main"


# ── QEMU runner detection ───────────────────────────────────────────────────

@dataclass
class QemuConfig:
    binary: str
    machine: list[str]
    virtio_dev: str
    kernel_arg: str  # Path to .elf (x86) or .img (aarch64) for `-kernel`.


def detect_qemu(elf_path: Path, img_path: Optional[Path] = None) -> Optional[QemuConfig]:
    """Pick the right qemu-system-* + machine args for an ELF.

    Returns None if the matching qemu binary isn't on $PATH — caller
    should SKIP the test.

    `img_path` is the raw binary consumed by aarch64 QEMU via
    `-kernel` (the ELF is PIE, QEMU can't load it). Optional for
    backwards compatibility; defaults to `elf_path.with_suffix(".img")`.
    Variant-launcher callers pass both paths explicitly so the test
    harness doesn't have to mirror the runner script's co-located-
    file convention.
    """
    info = _file_magic(elf_path)
    host_arch = os.uname().machine
    host_os = os.uname().sysname

    if "ARM aarch64" in info:
        binary = "qemu-system-aarch64"
        machine = ["-machine", "virt", "-cpu", "max"]
        virtio_dev = "virtio-net-device"
        kernel_arg = str(img_path if img_path else elf_path.with_suffix(".img"))
        if not Path(kernel_arg).exists():
            raise FileNotFoundError(f".img not found: {kernel_arg}")
    else:
        binary = "qemu-system-x86_64"
        virtio_dev = "virtio-net-pci"
        kernel_arg = str(elf_path)
        # -cpu host under HVF/KVM, -cpu max under TCG; see the old bash
        # detect_qemu for rationale around AVX + qemu64.
        if host_arch == "x86_64":
            if host_os == "Darwin" and _mac_has_hvf():
                machine = ["-cpu", "host", "-accel", "hvf"]
            elif host_os == "Linux" and os.access("/dev/kvm", os.R_OK):
                machine = ["-cpu", "host", "-accel", "kvm"]
            else:
                machine = ["-cpu", "max"]
        else:
            machine = ["-cpu", "max"]

    if not shutil.which(binary):
        return None

    return QemuConfig(
        binary=binary,
        machine=machine,
        virtio_dev=virtio_dev,
        kernel_arg=kernel_arg,
    )


def _file_magic(path: Path) -> str:
    try:
        return subprocess.check_output(["file", "-b", str(path)], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def _mac_has_hvf() -> bool:
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "kern.hv_support"], text=True
        ).strip()
        return out == "1"
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# ── QEMU args builder ───────────────────────────────────────────────────────

def qemu_net_args(
    *, http_port: int, tls_port: int, udp_port: int,
    virtio_dev: str, cpus: int = 1,
) -> list[str]:
    """Canonical port-forward `-device ... -netdev ...` pair.

    Same layout as scripts/helpers.sh::_qemu_net_args — HTTP on :80,
    HTTPS on :443, UDP echo on :7.
    """
    dev_extra = ""
    netdev_extra = ""
    if cpus > 1 and "-pci" in virtio_dev:
        # MMIO devices (virtio-net-device) don't support mq / vectors;
        # user-mode netdev's queues= only pairs with PCI multi-queue.
        vectors = 2 * cpus + 2
        dev_extra = f",mq=on,vectors={vectors},queues={cpus}"
        netdev_extra = f",queues={cpus}"
    forwards = (
        f"hostfwd=tcp::{http_port}-:80"
        f",hostfwd=tcp::{tls_port}-:443"
        f",hostfwd=udp::{udp_port}-:7"
    )
    return [
        "-device", f"{virtio_dev}{dev_extra},netdev=net0",
        "-netdev", f"user,id=net0,{forwards}{netdev_extra}",
    ]


# ── Launcher lifecycle ──────────────────────────────────────────────────────

@dataclass
class Launcher:
    proc: subprocess.Popen[bytes]
    log_path: Path

    def alive(self) -> bool:
        return self.proc.poll() is None

    def terminate(self, *, grace: float = 2.0) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and self.proc.poll() is None:
            time.sleep(0.1)
        if self.proc.poll() is None:
            try:
                self.proc.kill()
            except ProcessLookupError:
                pass
        try:
            self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    def cleanup(self) -> None:
        self.terminate()
        try:
            self.log_path.unlink(missing_ok=True)
        except OSError:
            pass


def spawn_backgrounded(
    launcher_path: Path,
    *,
    env: Optional[dict[str, str]] = None,
    log_prefix: str = "unikernel_test",
) -> Launcher:
    """Run an executable in the background, stdout+stderr to a temp log."""
    fd, log_path_str = tempfile.mkstemp(prefix=f"{log_prefix}_", suffix=".log")
    os.close(fd)
    log_path = Path(log_path_str)
    full_env = os.environ | (env or {})
    with open(log_path, "wb") as log_fd:
        proc = subprocess.Popen(
            [str(launcher_path)],
            env=full_env,
            stdout=log_fd, stderr=log_fd,
            stdin=subprocess.DEVNULL,
        )
    return Launcher(proc=proc, log_path=log_path)


# ── Direct QEMU spawn (for serial-log tests: test_smp, test_percpu, etc.) ───

def spawn_qemu(
    elf_path: Path,
    *,
    img_path: Optional[Path] = None,
    cpus: int = 1,
    memory_mb: int = 128,
    extra_args: Optional[list[str]] = None,
    log_prefix: str = "unikernel_qemu",
) -> Optional[Launcher]:
    """Boot `elf_path` under QEMU in the background (no network forwards).

    For tests whose only output channel is the serial log — SMP boot
    checks, per-core state tests, TLS primitive smoke tests. `img_path`
    is the raw-binary companion to `elf_path` used by aarch64 QEMU;
    passed through to `detect_qemu`. Returns None if the matching
    qemu-system-* isn't on $PATH (caller SKIPs).
    """
    qemu = detect_qemu(elf_path, img_path)
    if qemu is None:
        return None

    fd, log_path_str = tempfile.mkstemp(prefix=f"{log_prefix}_", suffix=".log")
    os.close(fd)
    log_path = Path(log_path_str)
    argv = [
        qemu.binary,
        *qemu.machine,
        "-m", str(memory_mb), "-smp", str(cpus), "-nographic",
        "-serial", f"file:{log_path}",
        "-no-reboot",
        "-device", f"{qemu.virtio_dev},netdev=net0",
        "-netdev", "user,id=net0",
        *(extra_args or []),
        "-kernel", qemu.kernel_arg,
    ]
    proc = subprocess.Popen(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )
    return Launcher(proc=proc, log_path=log_path)


def wait_for_marker(launcher: Launcher, marker: str, *, timeout: float) -> bool:
    """Poll `launcher.log_path` until `marker` appears or the VM exits."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if launcher.log_path.is_file():
                with open(launcher.log_path, "rb") as fh:
                    if marker.encode() in fh.read():
                        return True
        except OSError:
            pass
        if not launcher.alive():
            break
        time.sleep(0.25)
    return False


# ── PTY launcher (for stdin-sensitive tests: Ctrl-C, log-based) ─────────────

class PtyLauncher:
    """Launch a program under a pseudo-terminal.

    Parent can read the guest's output via `drain()` and write bytes to
    the guest serial via `write()`.
    """

    def __init__(self, launcher_path: Path, env: Optional[dict[str, str]] = None):
        full_env = os.environ | (env or {})
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.update(full_env)
            os.execv(str(launcher_path), [str(launcher_path)])
        self.pid = pid
        self.fd = fd
        self._buffer = bytearray()

    def drain(self, timeout: float = 0.1) -> bytes:
        try:
            r, _, _ = select.select([self.fd], [], [], timeout)
        except Exception:
            return b""
        if not r:
            return b""
        try:
            chunk = os.read(self.fd, 4096)
            self._buffer += chunk
            return chunk
        except OSError:
            return b""

    @property
    def buffer(self) -> bytes:
        return bytes(self._buffer)

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def wait_for(self, marker: bytes, *, timeout: float) -> bool:
        """Drain output until `marker` is seen or `timeout` elapses."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.drain(0.2)
            if marker in self._buffer:
                return True
        return False

    def poll(self) -> Optional[int]:
        """Reap the child if it's exited; return exit code or None."""
        try:
            r, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return 0
        if r == self.pid:
            return os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
        return None

    def wait_exit(self, *, timeout: float) -> bool:
        """Return True if the child exits within `timeout` seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.drain(0.1)
            if self.poll() is not None:
                return True
        return False

    def kill(self) -> None:
        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


# ── Probes ──────────────────────────────────────────────────────────────────

def http_get(
    path: str, *, host: str = "127.0.0.1", port: int, timeout: float = 3.0,
) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def https_get(
    path: str, *, host: str = "127.0.0.1", port: int,
    ca_file: Optional[Path] = None, sni: str = "unikernel.local",
    timeout: float = 5.0,
) -> tuple[int, bytes]:
    if ca_file is not None:
        ctx = ssl.create_default_context(cafile=str(ca_file))
    else:
        ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": sni})
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def udp_echo(
    payload: bytes = b"hello", *, host: str = "127.0.0.1",
    port: int, timeout: float = 2.0,
) -> Optional[bytes]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(1024)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def wait_http_ready(port: int, *, timeout: float, host: str = "127.0.0.1",
                    path: str = "/health") -> bool:
    """Poll `http://host:port{path}` until it answers 200 or `timeout` hits."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s, _ = http_get(path, host=host, port=port, timeout=1.0)
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False
