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
import socket
import subprocess
import sys
import threading
import time
import unittest

from scripts.test_helpers import (
    PtyLauncher,
    h3_get,
    http_get,
    https_get,
    https_session_resume_check,
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
# Stable end-of-init marker emitted by `#[uni::init]` after the
# user's body returns. Same line on every runner (HVF / QEMU / native).
BOOT_MARKER = b"ready"

PORT = int(os.environ.get("TEST_PORT", 18080))
TLS_PORT = int(os.environ.get("TEST_TLS_PORT", 18443))
UDP_PORT = int(os.environ.get("TEST_UDP_PORT", 18007))
TCP_ECHO_PORT = int(os.environ.get("TEST_TCP_ECHO_PORT", 18009))


def _launcher_env(port: int, tls_port: int, udp_port: int, tcp_echo_port: int) -> dict[str, str]:
    """Env vars spanning every launcher variant.

    Name convention is `UNIKERNEL_<PROTO>_<GUEST>` — derived from
    the guest-side port the app binds, matching `port_fwd()` in
    BUILD and `variants.bzl`'s launcher templates. VM launchers
    (hvf / qemu_*) and the native binary (`uni::native::
    read_port_env`) both read this name, so the caller can stay
    ignorant of which variant LAUNCHER points at.
    """
    return {
        "UNIKERNEL_TCP_80": str(port),
        "UNIKERNEL_TCP_443": str(tls_port),
        "UNIKERNEL_UDP_7": str(udp_port),
        "UNIKERNEL_TCP_9": str(tcp_echo_port),
    }

if not (LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)):
    sys.exit(f"ERROR: launcher missing / not executable: {LAUNCHER}")


class WebserverServiceTest(unittest.TestCase):
    """Boot once, probe the HTTP / HTTPS / UDP paths while the server stays up."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = spawn_backgrounded(
            LAUNCHER,
            env=_launcher_env(PORT, TLS_PORT, UDP_PORT, TCP_ECHO_PORT),
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

    def test_https_session_resumption(self) -> None:
        """Verify TLS 1.3 session resumption end-to-end.

        Connection 1 is a fresh handshake — the server emits a
        NewSessionTicket post-handshake. Connection 2 presents that
        ticket via the `pre_shared_key` extension; the server matches
        it, verifies the binder, and sends a ServerHello with
        `selected_identity` while skipping the Certificate +
        CertificateVerify flight. Python's `ssl.SSLSocket.session_reused`
        flips to True iff that path completed successfully.

        Regression guard for the resumption sprint: a refactor that
        breaks ticket sealing, binder verification, or the
        skip-Cert/CV branch will surface here as
        `second_was_resumed=False` even when the TCP/TLS handshake
        otherwise succeeds.
        """
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        first_was_fresh, second_was_resumed = https_session_resume_check(
            port=TLS_PORT, ca_file=DEV_CERT,
        )
        self.assertTrue(first_was_fresh,
                        "first handshake should be fresh (no cached session)")
        self.assertTrue(second_was_resumed,
                        "second handshake should reuse the ticket from #1")

    # ── HTTP/3 over QUIC ─────────────────────────────────────────
    def test_h3_health(self) -> None:
        """End-to-end HTTP/3 GET against the same handler that
        serves HTTPS/1.1 — exercises the full stack
        `uni-quic` (QUIC v1 transport) → `uni-http3` (H3 frames +
        QPACK static-only) → `uni-http` Request/Response.
        Skips if `aioquic` isn't available locally.
        """
        status, body = h3_get("/health", port=TLS_PORT)
        self.assertEqual(status, 200)
        self.assertIn(b"status", body)

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

    # ── Async TCP reactor end-to-end (uni::runtime::TcpListener) ──
    def test_tcp_echo(self) -> None:
        """Validates `uni::runtime::TcpListener::bind(9)?.run(...)` —
        bare-metal + native both exercise the full reactor path:
        accept future wakes on new connection, handler runs on owning
        worker, recv/send round-trip succeeds."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        try:
            s.connect(("127.0.0.1", TCP_ECHO_PORT))
            s.sendall(b"ping")
            data = s.recv(32)
            self.assertEqual(data, b"ping")
        finally:
            s.close()

    # ── boot_info surfaces through the serial log ───────────────
    def test_boot_info_logged(self) -> None:
        """Webserver's startup log must contain an `app: ram=...` line
        sourced from `uni::boot_info()` — the user-facing API check
        that the boot snapshot makes it through the runfiles bundle on
        whichever runner this test happens to be running under
        (hvf / qemu / iso / native). Kernel-side hardware info appears
        on separate `cpu:` / `mem:` / `nic:` lines from boot/entry.rs;
        this assertion specifically guards the *app-visible* surface.
        """
        log = self.launcher.log_path.read_bytes()
        self.assertIn(b"app: ram=", log,
                      f"app boot_info line missing from serial log (length={len(log)})")
        self.assertIn(b"cpus=", log)


class WebserverShutdownTest(unittest.TestCase):
    """Verify a Ctrl-C byte on the guest serial shuts the VM down promptly.

    Catches event-loop starvation: the kernel boots (HTTP works in
    WebserverServiceTest) but `check_shutdown` never runs because CPU
    is monopolised — e.g. the virtio-mmio IRQ storm that 38abf2d fixed.
    QEMU -chardev stdio / HVF raw-mode stdin / native POSIX SIGINT all
    funnel into the same 0x03 → PSCI/ACPI shutdown path in the guest.
    """

    def _run_shutdown_scenario(self, *, port_offset: int, hammer: bool):
        """Boot, optionally hammer HTTP, send ^C, wait for VM exit. Returns
        the captured serial buffer for further assertions."""
        port = PORT + port_offset
        tls_port = TLS_PORT + port_offset
        udp_port = UDP_PORT + port_offset
        tcp_echo_port = TCP_ECHO_PORT + port_offset
        pty_launcher = PtyLauncher(
            LAUNCHER,
            env=_launcher_env(port, tls_port, udp_port, tcp_echo_port),
        )
        stop_hammer = [False]
        try:
            self.assertTrue(
                pty_launcher.wait_for(BOOT_MARKER, timeout=15.0),
                f"didn't see {BOOT_MARKER!r} within 15s "
                f"(got {len(pty_launcher.buffer)} bytes)",
            )

            if hammer:
                def _hammer() -> None:
                    while not stop_hammer[0]:
                        subprocess.run(
                            ["curl", "-s", "--max-time", "1",
                             f"http://127.0.0.1:{port}/health"],
                            capture_output=True,
                        )
                workers = [threading.Thread(target=_hammer, daemon=True) for _ in range(3)]
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
            return pty_launcher.buffer
        finally:
            stop_hammer[0] = True
            pty_launcher.kill()

    def test_ctrlc_exits_within_8s(self) -> None:
        """Active-traffic ^C shutdown leaves no allocations behind too.
        Listener drop sets the abort flag on per-worker conn-handler
        tasks, then `shutdown_and_drop` calls `drain_all_arenas` which
        force-drops every live `Box<dyn Future>` across every arena —
        APs have left the eventloop by then so it's race-free."""
        buf = self._run_shutdown_scenario(port_offset=100, hammer=True)
        leak_line = next(
            (line for line in buf.splitlines() if b"HEAP_LEAK_CHECK" in line),
            None,
        )
        self.assertIsNotNone(
            leak_line, "no HEAP_LEAK_CHECK line in serial log",
        )
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK", leak_line,
            "active-traffic shutdown leaked memory — "
            "drain_all_arenas didn't reclaim in-flight task storage",
        )

    def test_clean_shutdown_no_leak(self) -> None:
        """Idle ^C shutdown leaves no allocations behind. `shutdown_and_drop`
        snapshots `talc::heap_stats` at `set_ready` and again after dropping
        every retained listener; absence of in-flight conn tasks means the
        post-shutdown delta should be zero (or negative — the boot task
        itself drains). A `LEAK` verdict here means listener teardown
        regressed."""
        buf = self._run_shutdown_scenario(port_offset=200, hammer=False)
        leak_line = next(
            (line for line in buf.splitlines() if b"HEAP_LEAK_CHECK" in line),
            None,
        )
        self.assertIsNotNone(
            leak_line,
            "no HEAP_LEAK_CHECK line in serial log — shutdown_and_drop didn't run?",
        )
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK", leak_line,
            "idle-shutdown leaked memory — listener teardown regressed",
        )

    def test_open_conn_resets_promptly_on_shutdown(self) -> None:
        """Hold a TCP connection open across shutdown and assert the
        peer observes the close within a second.

        Pre-fix: `arch::shutdown()` powered off mid-flight without
        touching open conns, so the host's TCP stack sat on a
        half-open connection until keepalive eventually killed it
        (minutes). Post-fix: `shutdown_and_drop` walks every per-core
        TCP pool and emits one RST per active conn before
        PSCI SYSTEM_OFF; the host's `recv` returns within a few ms,
        either with `0` (graceful close — native, where the kernel
        FINs every fd at process exit) or `ConnectionResetError`
        (unikernel bare-metal RST sweep).
        """
        port = PORT + 300
        tls_port = TLS_PORT + 300
        udp_port = UDP_PORT + 300
        tcp_echo_port = TCP_ECHO_PORT + 300
        pty_launcher = PtyLauncher(
            LAUNCHER,
            env=_launcher_env(port, tls_port, udp_port, tcp_echo_port),
        )
        try:
            self.assertTrue(
                pty_launcher.wait_for(BOOT_MARKER, timeout=15.0),
                f"didn't see {BOOT_MARKER!r} within 15s",
            )
            # Boot marker fires before the HTTP listener fully accepts
            # conns; poll /health until it answers.
            self.assertTrue(
                wait_http_ready(port, timeout=10.0),
                f"HTTP not ready on :{port} after 10s",
            )

            # Open a long-lived TCP connection; verify it works.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(("127.0.0.1", port))
            s.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            resp = s.recv(4096)
            self.assertIn(b"200", resp[:32], f"sanity GET failed: {resp[:80]!r}")

            # Trigger shutdown. A background thread keeps the pty
            # drained — the unikernel's eventloop prints its
            # post-loop diagnostic before invoking
            # `shutdown_and_drop`, and a full pty buffer would
            # block those writes (preventing the RST sweep).
            stop_drain = [False]
            def _drain_loop() -> None:
                while not stop_drain[0]:
                    pty_launcher.drain(0.05)
            drainer = threading.Thread(target=_drain_loop, daemon=True)
            drainer.start()

            pty_launcher.write(b"\x03")

            # Block on recv with a 3 s timeout. Keepalive death would
            # take minutes; a healthy RST/FIN sweep returns within ms.
            s.settimeout(3.0)
            t0 = time.monotonic()
            try:
                tail = s.recv(4096)
                # `0` bytes = peer FINed cleanly (native).
                self.assertEqual(
                    tail, b"",
                    f"unexpected post-shutdown payload: {tail[:80]!r}",
                )
                close_kind = "FIN"
            except ConnectionResetError:
                close_kind = "RST"
            finally:
                stop_drain[0] = True
                drainer.join(timeout=1.0)
            elapsed = time.monotonic() - t0
            print(f"    (peer observed {close_kind} in {elapsed*1000:.0f} ms)",
                  flush=True)
            self.assertLess(
                elapsed, 2.0,
                f"close took {elapsed:.1f}s — keepalive-timeout shape, "
                "shutdown isn't closing conns",
            )
            s.close()

            # And the VM itself should still exit promptly.
            self.assertTrue(
                pty_launcher.wait_exit(timeout=8.0),
                "VM still running 8 s after ^C",
            )
        finally:
            pty_launcher.kill()


if __name__ == "__main__":
    unittest.main(verbosity=2)
