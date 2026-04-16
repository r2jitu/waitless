#!/usr/bin/env python3
"""apps/webserver/test.py — end-to-end test for the webserver app.

Runner-agnostic: depends on :webserver (the unikernel_binary launcher)
as a data dep and spawns it as a subprocess. One test file covers every
runner config (hvf / aarch64-qemu / x86_64-iso / native) because the
launcher hides the per-runner specifics.

Laid out as unittest TestCases so we get per-check PASS/FAIL lines and
proper assertion diffs instead of a bespoke bash tally:

    WebserverServiceTest    — boot once, probe HTTP / HTTPS / UDP while
                               the server stays up.
    WebserverShutdownTest   — separate boot under a PTY, hammer HTTP,
                               send Ctrl-C, assert the VM exits within
                               8 s (event-loop-starvation regression
                               guard, see commit 38abf2d).

Run under sh_test (no rules_python dep). The outer test.sh is a 3-line
exec of this file. Switching to py_test proper is a MODULE.bazel change
away — the Python itself is already framework-ready.
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
import threading
import time
import unittest
from pathlib import Path


# ── Runfiles + constants ─────────────────────────────────────────────────────

def _runfiles_root() -> Path:
    rf = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if rf:
        return Path(rf) / "_main"
    return Path(f"{sys.argv[0]}.runfiles") / "_main"


ROOT = _runfiles_root()
LAUNCHER = ROOT / "apps" / "webserver" / "webserver"
DEV_CERT = ROOT / "apps" / "webserver" / "dev_certs" / "dev_cert.pem"
# Works for both unikernel boot (`[BOOT] Entering event loop on core 0.`)
# and native POSIX (`Entering event loop.` from uni::main before
# server.run()).
BOOT_MARKER = b"Entering event loop"

PORT = int(os.environ.get("TEST_PORT", 18080))
TLS_PORT = int(os.environ.get("TEST_TLS_PORT", 18443))
UDP_PORT = int(os.environ.get("TEST_UDP_PORT", 18007))

if not (LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)):
    sys.exit(f"ERROR: launcher missing / not executable: {LAUNCHER}")


# ── Probe helpers ────────────────────────────────────────────────────────────

def http_get(path: str, *, port: int = PORT, timeout: float = 3.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def https_get(path: str, *, port: int = TLS_PORT, timeout: float = 5.0) -> tuple[int, bytes]:
    # Self-signed dev cert → pin it as the CA bundle.
    ctx = ssl.create_default_context(cafile=str(DEV_CERT))
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": "unikernel.local"})
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def udp_echo(payload: bytes = b"hello", *, port: int = UDP_PORT,
             timeout: float = 2.0) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, ("127.0.0.1", port))
        data, _ = s.recvfrom(1024)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


# ── Launcher lifecycle ───────────────────────────────────────────────────────

def spawn_backgrounded(port: int, tls_port: int, udp_port: int) -> tuple[subprocess.Popen[bytes], str]:
    log_path = f"/tmp/webserver_test_{os.getpid()}_{port}.log"
    env = os.environ | {
        "UNIKERNEL_PORT": str(port),
        "UNIKERNEL_TLS_PORT": str(tls_port),
        "UNIKERNEL_UDP_PORT": str(udp_port),
    }
    # Open with `with` to keep the handle locally; subprocess inherits
    # the fd into the child and closes our end on exit.
    with open(log_path, "wb") as log_fd:
        p = subprocess.Popen(
            [str(LAUNCHER)], env=env, stdout=log_fd, stderr=log_fd,
            stdin=subprocess.DEVNULL,
        )
    return p, log_path


def terminate(p: subprocess.Popen, *, grace: float = 2.0) -> None:
    if p.poll() is not None:
        return
    try:
        p.terminate()
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and p.poll() is None:
        time.sleep(0.1)
    if p.poll() is None:
        try:
            p.kill()
        except ProcessLookupError:
            pass
    p.wait(timeout=1.0)


def wait_http_ready(port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s, _ = http_get("/health", port=port, timeout=1.0)
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ── Phase 1: long-lived launcher + service probes ────────────────────────────

class WebserverServiceTest(unittest.TestCase):
    launcher: subprocess.Popen[bytes]
    log_path: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher, cls.log_path = spawn_backgrounded(PORT, TLS_PORT, UDP_PORT)
        if not wait_http_ready(PORT, timeout=20.0):
            # Dump the launcher log into the test output so CI can see it.
            try:
                with open(cls.log_path, "rb") as fh:
                    sys.stderr.buffer.write(fh.read())
            except OSError:
                pass
            terminate(cls.launcher)
            raise RuntimeError(f"HTTP not ready on :{PORT} after 20s")

    @classmethod
    def tearDownClass(cls) -> None:
        terminate(cls.launcher)
        try:
            os.unlink(cls.log_path)
        except OSError:
            pass

    # ── HTTP ─────────────────────────────────────────────────────
    def test_http_root(self) -> None:
        status, _ = http_get("/")
        self.assertEqual(status, 200)

    def test_http_health(self) -> None:
        status, _ = http_get("/health")
        self.assertEqual(status, 200)

    def test_http_notfound(self) -> None:
        status, body = http_get("/xyz")
        self.assertEqual(status, 404)
        self.assertIn(b"Not Found", body)

    # ── HTTPS ────────────────────────────────────────────────────
    def test_https_root(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, _ = https_get("/")
        self.assertEqual(status, 200)

    def test_https_health(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, body = https_get("/health")
        self.assertEqual(status, 200)
        self.assertIn(b"status", body)

    def test_https_notfound(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, body = https_get("/xyz")
        self.assertEqual(status, 404)
        self.assertIn(b"Not Found", body)

    def test_https_burst_30(self) -> None:
        """30 back-to-back HTTPS GETs with 0 failures.

        Regression guard for commits 52e3a62 (hvf-runner CLOSE_WAIT
        fd-leak on host-side FIN) and 03bf02f (tls_server.advance()
        didn't loop, stranding app_data records alongside
        ClientChangeCipherSpec+Finished). Pre-fix this loop produced
        ~20% empty responses, so 30 iters lights up a regression
        deterministically (<1% fluke probability).
        """
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        n = 30
        failures = []
        for i in range(n):
            try:
                status, _ = https_get("/health")
                if status != 200:
                    failures.append(f"#{i}: status={status}")
            except Exception as e:
                failures.append(f"#{i}: {e!r}")
        self.assertFalse(failures, f"{len(failures)}/{n} failed: {failures[:5]}")

    # ── UDP ──────────────────────────────────────────────────────
    def test_udp_echo(self) -> None:
        self.assertEqual(udp_echo(), b"hello")


# ── Phase 2: Ctrl-C regression under PTY ─────────────────────────────────────

class WebserverShutdownTest(unittest.TestCase):
    """Verify a Ctrl-C byte on the guest serial shuts the VM down promptly.

    Catches event-loop starvation: the kernel boots (HTTP works in phase
    1) but `check_shutdown` never runs because CPU is monopolised —
    e.g. the virtio-mmio IRQ storm that 38abf2d fixed. QEMU -chardev
    stdio / HVF raw-mode stdin / native POSIX SIGINT all funnel into
    the same 0x03 → PSCI/ACPI shutdown path in the guest.
    """

    def test_ctrlc_exits_within_8s(self) -> None:
        # Separate port range so phase-1 teardown races don't matter.
        port, tls_port, udp_port = PORT + 100, TLS_PORT + 100, UDP_PORT + 100

        env = os.environ | {
            "UNIKERNEL_PORT": str(port),
            "UNIKERNEL_TLS_PORT": str(tls_port),
            "UNIKERNEL_UDP_PORT": str(udp_port),
        }
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.update(env)
            os.execv(str(LAUNCHER), [str(LAUNCHER)])

        def drain(timeout: float = 0.1) -> bytes:
            try:
                r, _, _ = select.select([fd], [], [], timeout)
            except Exception:
                return b""
            if not r:
                return b""
            try:
                return os.read(fd, 4096)
            except OSError:
                return b""

        booted = False
        stop_hammer = [False]
        try:
            buf = b""
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                buf += drain(0.2)
                if BOOT_MARKER in buf:
                    booted = True
                    break
            self.assertTrue(booted, f"didn't reach boot marker within 15s (got {len(buf)} bytes)")

            # Hammer HTTP so the event loop is actively serving when ^C fires.
            def hammer() -> None:
                while not stop_hammer[0]:
                    subprocess.run(
                        ["curl", "-s", "--max-time", "1",
                         f"http://127.0.0.1:{port}/health"],
                        capture_output=True,
                    )

            workers = [threading.Thread(target=hammer, daemon=True) for _ in range(3)]
            for w in workers:
                w.start()
            time.sleep(2)

            t0 = time.monotonic()
            os.write(fd, b"\x03")
            exited = False
            for _ in range(80):  # 80 × 0.1s = 8s budget
                drain(0.1)
                r, _ = os.waitpid(pid, os.WNOHANG)
                if r == pid:
                    exited = True
                    break
            stop_hammer[0] = True
            elapsed = time.monotonic() - t0
            self.assertTrue(exited, f"VM still running {elapsed:.1f}s after ^C — hung")
            print(f"    (exited {elapsed:.2f}s after ^C)", flush=True)
        finally:
            stop_hammer[0] = True
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


if __name__ == "__main__":
    # Force per-test verbosity so bazel test output shows each check.
    unittest.main(verbosity=2)
