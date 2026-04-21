#!/usr/bin/env python3
"""apps/webserver/test.py — end-to-end test for the webserver app.

Runner-agnostic: depends on :webserver (the unikernel_binary launcher)
as a data dep and spawns it as a subprocess. One test file covers every
runner config (hvf / aarch64-qemu / x86_64-iso / native) because the
launcher hides the per-runner specifics.

    WebserverServiceTest    — boot once, probe HTTP / HTTPS / UDP while
                               the server stays up.
    WebserverShutdownTest   — separate boot under a PTY, hammer HTTP,
                               send Ctrl-C, assert the VM exits within
                               8 s (event-loop-starvation regression
                               guard, see commit 38abf2d).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest

from scripts.test_helpers import (
    PtyLauncher,
    http_get,
    https_get,
    runfiles_root,
    spawn_backgrounded,
    udp_echo,
    wait_http_ready,
)


ROOT = runfiles_root()
# Each per-variant py_test passes `env = {"LAUNCHER_NAME": "webserver_<variant>"}`;
# test.py resolves that runfile relative to its own package. No fallback:
# an unset env var is a BUILD bug, not a runtime-selectable default.
LAUNCHER_NAME = os.environ["LAUNCHER_NAME"]
LAUNCHER = ROOT / "apps" / "webserver" / LAUNCHER_NAME
DEV_CERT = ROOT / "apps" / "webserver" / "dev_certs" / "dev_cert.pem"
# Matches both unikernel boot (`[BOOT] Entering event loop on core 0.`)
# and native POSIX (`Entering event loop.` from the app's boot()
# function before server.run()).
BOOT_MARKER = b"Entering event loop"

PORT = int(os.environ.get("TEST_PORT", 18080))
TLS_PORT = int(os.environ.get("TEST_TLS_PORT", 18443))
UDP_PORT = int(os.environ.get("TEST_UDP_PORT", 18007))

if not (LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)):
    sys.exit(f"ERROR: launcher missing / not executable: {LAUNCHER}")


class WebserverServiceTest(unittest.TestCase):
    """Boot once, probe the HTTP / HTTPS / UDP paths while the server stays up."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = spawn_backgrounded(
            LAUNCHER,
            env={
                "UNIKERNEL_PORT": str(PORT),
                "UNIKERNEL_TLS_PORT": str(TLS_PORT),
                "UNIKERNEL_UDP_PORT": str(UDP_PORT),
            },
            log_prefix="webserver_svc",
        )
        if not wait_http_ready(PORT, timeout=20.0):
            try:
                sys.stderr.buffer.write(cls.launcher.log_path.read_bytes())
            except OSError:
                pass
            cls.launcher.terminate()
            raise RuntimeError(f"HTTP not ready on :{PORT} after 20s")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.launcher.cleanup()

    # ── HTTP ─────────────────────────────────────────────────────
    def test_http_root(self) -> None:
        status, _ = http_get("/", port=PORT)
        self.assertEqual(status, 200)

    def test_http_health(self) -> None:
        status, _ = http_get("/health", port=PORT)
        self.assertEqual(status, 200)

    def test_http_notfound(self) -> None:
        status, body = http_get("/xyz", port=PORT)
        self.assertEqual(status, 404)
        self.assertIn(b"Not Found", body)

    # ── HTTPS ────────────────────────────────────────────────────
    def test_https_root(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, _ = https_get("/", port=TLS_PORT, ca_file=DEV_CERT)
        self.assertEqual(status, 200)

    def test_https_health(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, body = https_get("/health", port=TLS_PORT, ca_file=DEV_CERT)
        self.assertEqual(status, 200)
        self.assertIn(b"status", body)

    def test_https_notfound(self) -> None:
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, body = https_get("/xyz", port=TLS_PORT, ca_file=DEV_CERT)
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
                status, _ = https_get("/health", port=TLS_PORT, ca_file=DEV_CERT)
                if status != 200:
                    failures.append(f"#{i}: status={status}")
            except Exception as e:
                failures.append(f"#{i}: {e!r}")
        self.assertFalse(failures, f"{len(failures)}/{n} failed: {failures[:5]}")

    # ── UDP ──────────────────────────────────────────────────────
    def test_udp_echo(self) -> None:
        self.assertEqual(udp_echo(port=UDP_PORT), b"hello")

    # ── Phase 0: boot_info surfaces through the serial log ───────
    def test_boot_info_logged(self) -> None:
        """Webserver's startup log must contain a BOOT_INFO line sourced
        from `uni::boot_info()`. This is the Phase 0 integration check
        for the init-redesign plan — it confirms `boot_info()` is wired
        up on whichever runner this test happens to be executing under
        (hvf / qemu / iso / native)."""
        log = self.launcher.log_path.read_bytes()
        self.assertIn(b"BOOT_INFO ram=", log,
                      f"BOOT_INFO line missing from serial log (length={len(log)})")
        self.assertIn(b"cpus=", log)


class WebserverShutdownTest(unittest.TestCase):
    """Verify a Ctrl-C byte on the guest serial shuts the VM down promptly.

    Catches event-loop starvation: the kernel boots (HTTP works in
    WebserverServiceTest) but `check_shutdown` never runs because CPU
    is monopolised — e.g. the virtio-mmio IRQ storm that 38abf2d fixed.
    QEMU -chardev stdio / HVF raw-mode stdin / native POSIX SIGINT all
    funnel into the same 0x03 → PSCI/ACPI shutdown path in the guest.
    """

    def test_ctrlc_exits_within_8s(self) -> None:
        port, tls_port, udp_port = PORT + 100, TLS_PORT + 100, UDP_PORT + 100
        pty_launcher = PtyLauncher(
            LAUNCHER,
            env={
                "UNIKERNEL_PORT": str(port),
                "UNIKERNEL_TLS_PORT": str(tls_port),
                "UNIKERNEL_UDP_PORT": str(udp_port),
            },
        )
        stop_hammer = [False]
        try:
            self.assertTrue(
                pty_launcher.wait_for(BOOT_MARKER, timeout=15.0),
                f"didn't see {BOOT_MARKER!r} within 15s "
                f"(got {len(pty_launcher.buffer)} bytes)",
            )

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
            pty_launcher.write(b"\x03")
            exited = pty_launcher.wait_exit(timeout=8.0)
            stop_hammer[0] = True
            elapsed = time.monotonic() - t0
            self.assertTrue(exited, f"VM still running {elapsed:.1f}s after ^C — hung")
            print(f"    (exited {elapsed:.2f}s after ^C)", flush=True)
        finally:
            stop_hammer[0] = True
            pty_launcher.kill()


if __name__ == "__main__":
    unittest.main(verbosity=2)
