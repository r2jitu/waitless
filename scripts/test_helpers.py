"""scripts/test_helpers.py — Shared utilities for Python integration tests.

Each app's test.py imports from here to get:

  * Runfiles discovery (`runfiles_root()`).
  * Launcher spawning — backgrounded (for probes) or PTY-driven (for
    Ctrl-C / log-based tests).
  * HTTP / HTTPS / UDP probe helpers.

Tests invoke the app's per-variant launcher target directly (from
`//bazel/rules:variants.bzl`), so the previous in-Python QEMU-arg
builder / detector is gone — the launcher owns all runner-specific
invocation.
"""

from __future__ import annotations

import http.client
import os
import pty
import select
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
