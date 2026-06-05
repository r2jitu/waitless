#!/usr/bin/env python3
"""apps/webserver/test.py — end-to-end test for the webserver app.

Runner-agnostic: depends on :webserver (the waitless_binary launcher)
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
import ssl
import subprocess
import sys
import threading
import time
import unittest

from scripts.test_helpers import (
    PtyLauncher,
    h3_get,
    h3_post,
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
# Stable end-of-init marker emitted by `#[waitless::init]` after the
# user's body returns. Same line on every runner (HVF / QEMU / native).
BOOT_MARKER = b"ready"

PORT = int(os.environ.get("TEST_PORT", 18080))
TLS_PORT = int(os.environ.get("TEST_TLS_PORT", 18443))
UDP_PORT = int(os.environ.get("TEST_UDP_PORT", 18007))
TCP_ECHO_PORT = int(os.environ.get("TEST_TCP_ECHO_PORT", 18009))


def _launcher_env(
    port: int, tls_port: int, udp_port: int, tcp_echo_port: int
) -> dict[str, str]:
    """Env vars spanning every launcher variant.

    Name convention is `WAITLESS_<PROTO>_<GUEST>` — derived from
    the guest-side port the app binds, matching `port_fwd()` in
    BUILD and `variants.bzl`'s launcher templates. VM launchers
    (hvf / qemu_*) and the native binary (`waitless::native::
    read_port_env`) both read this name, so the caller can stay
    ignorant of which variant LAUNCHER points at.
    """
    return {
        "WAITLESS_TCP_80": str(port),
        "WAITLESS_TCP_443": str(tls_port),
        # H3 listens on UDP/443 inside the guest; the launcher maps it
        # to the same host port as HTTPS so a single port number
        # addresses both. Omitting this would leave H3 at its
        # BUILD-default host port (8443) while HTTPS moves to
        # `tls_port` — the resulting Alt-Svc advertisement would still
        # be `h3=":<host_header_port>"` (correct per request), but
        # `test_h3_health` connects directly to `tls_port` over UDP and
        # would silently fail.
        "WAITLESS_UDP_443": str(tls_port),
        "WAITLESS_UDP_7": str(udp_port),
        "WAITLESS_TCP_9": str(tcp_echo_port),
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
    # The HTML pages all flow through `shell_body` in main.rs, which
    # builds a 9-part `Body` chain (mostly borrowed-static slices,
    # plus a couple of owned per-request chunks). That hits a code
    # path the small static endpoints (/health, JSON dumps) don't:
    # `ResponseBody::Chain` → one `stream.send(part)` per chunk →
    # multiple TLS records per response. Asserting on the body
    # boundaries (`<!DOCTYPE html>` head, `</html>` tail, byte size,
    # nav-bar active-class flip) lights up corruption that a
    # status-only check would miss — a chunk dropped, a record
    # mis-encrypted, or a content-length disagreement would all
    # surface here as a body-size or boundary mismatch.
    SHELL_PAGES: tuple[tuple[str, str, str], ...] = (
        ("/", "Home", '/" class="active"'),
        ("/architecture", "Architecture", '/architecture" class="active"'),
        ("/network", "Network", '/network" class="active"'),
        ("/tls", "TLS", '/tls" class="active"'),
        ("/quic", "QUIC", '/quic" class="active"'),
        ("/diagnostics", "Diagnostics", '/diagnostics" class="active"'),
    )

    def _assert_full_html(self, body: bytes, title: str, active_marker: str) -> None:
        self.assertTrue(
            body.startswith(b"<!DOCTYPE html>"),
            f"body doesn't start with doctype: {body[:40]!r}",
        )
        self.assertTrue(
            body.rstrip().endswith(b"</html>"),
            f"body doesn't end with </html>: ...{body[-60:]!r}",
        )
        self.assertIn(
            f"<title>{title} — Waitless</title>".encode(),
            body,
            f"title missing for {title!r}",
        )
        self.assertIn(
            active_marker.encode(),
            body,
            f"active nav marker missing for {active_marker!r}",
        )
        # Sanity floor: shell + nav + STYLES + page body is always
        # ≥ 5 KiB. A truncated multi-part body (chunk dropped mid-
        # response) typically lands well below this.
        self.assertGreater(len(body), 5000, f"body suspiciously small ({len(body)} B)")

    def test_https_root(self) -> None:
        """Full-body verification of /. Exercises the 9-part shell
        Body → ResponseBody::Chain → multi-record TLS path. Pre-
        coverage was status-only and would have missed mid-stream
        truncation."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        status, body = https_get("/", port=TLS_PORT, ca_file=DEV_CERT)
        self.assertEqual(status, 200)
        self._assert_full_html(body, "Home", '/" class="active"')

    def test_https_all_shell_pages(self) -> None:
        """Walk every page that goes through `shell_body`. Each
        renders 5 KiB-9 KiB across 9+ Body parts, sending a
        different chunk-size mix through `TlsStream::send` →
        PLAINTEXT_CHUNK splitting. A regression that broke any one
        page's framing (off-by-one Content-Length, wrong chunk
        order, dropped trailing static) shows up here."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        for path, title, active in self.SHELL_PAGES:
            with self.subTest(path=path):
                status, body = https_get(path, port=TLS_PORT, ca_file=DEV_CERT)
                self.assertEqual(status, 200)
                self._assert_full_html(body, title, active)

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

    def _alpn_select(self, offered: list[str]) -> str | None:
        """Run a TLS handshake offering `offered` and return the
        protocol the server selected via ALPN (or None)."""
        ctx = ssl.create_default_context(cafile=str(DEV_CERT))
        ctx.set_alpn_protocols(offered)
        sock = socket.create_connection(("127.0.0.1", TLS_PORT), timeout=5.0)
        try:
            with ctx.wrap_socket(sock, server_hostname="waitless.local") as ssock:
                return ssock.selected_alpn_protocol()
        finally:
            sock.close()

    def test_https_alpn_prefers_h2(self) -> None:
        """A ClientHello offering `h2,http/1.1` must negotiate `h2`
        (server preference). The server echoes the selected name in
        EncryptedExtensions; modern Chrome rejects a missing-ALPN
        ServerHello with ERR_SSL_PROTOCOL_ERROR, so the echo must be
        present. Python's `ssl` does the negotiation but doesn't speak
        h2 itself — this checks the negotiated string only."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        self.assertEqual(
            self._alpn_select(["h2", "http/1.1"]),
            "h2",
            "server should prefer h2 when the client offers it",
        )

    def test_https_alpn_http11_fallback(self) -> None:
        """A client offering only `http/1.1` (no h2) must still get
        `http/1.1` — the fallback the golden path depends on must stay
        intact now that h2 is additive."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        self.assertEqual(
            self._alpn_select(["http/1.1"]),
            "http/1.1",
            "http/1.1-only clients must still negotiate http/1.1",
        )

    def test_h2_curl_get(self) -> None:
        """End-to-end HTTP/2: `curl --http2` negotiates h2 via ALPN and
        gets a real response over the multiplexed connection. Exercises
        the full new stack — TLS ALPN dispatch → HPACK decode → frame
        codec → flow-controlled response framing → HPACK encode. Skips
        if the local curl lacks HTTP/2 support."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        try:
            ver = subprocess.run(
                ["curl", "-V"], capture_output=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("curl not available")
        if b"HTTP2" not in ver and b"http2" not in ver:
            self.skipTest("local curl lacks HTTP/2 support")
        # `--http2` over TLS uses ALPN; `-w` prints the negotiated
        # version curl actually used so we can assert on it.
        proc = subprocess.run(
            [
                "curl",
                "-s",
                "--http2",
                "--cacert",
                str(DEV_CERT),
                "--resolve",
                f"waitless.local:{TLS_PORT}:127.0.0.1",
                "-o",
                "-",
                "-w",
                "\n__HTTP_VERSION__:%{http_version}\n",
                f"https://waitless.local:{TLS_PORT}/health",
            ],
            capture_output=True,
            timeout=15,
        )
        out = proc.stdout
        self.assertIn(
            b"__HTTP_VERSION__:2",
            out,
            f"curl didn't use HTTP/2 (stderr={proc.stderr[:200]!r}, out={out[:200]!r})",
        )
        self.assertIn(b"status", out, f"missing /health body over h2: {out[:200]!r}")

    def test_h2_curl_multiplexed_pages(self) -> None:
        """Fetch several shell pages over a single h2 connection in one
        curl invocation (`--http2` + multiple URLs reuse the connection
        and multiplex the streams). Each must return a full HTML body —
        guards response framing / HPACK encode / interleaving across
        streams on the same connection."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        try:
            ver = subprocess.run(
                ["curl", "-V"], capture_output=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("curl not available")
        if b"HTTP2" not in ver and b"http2" not in ver:
            self.skipTest("local curl lacks HTTP/2 support")
        urls = [f"https://waitless.local:{TLS_PORT}{p}" for p, _, _ in self.SHELL_PAGES]
        proc = subprocess.run(
            [
                "curl",
                "-s",
                "--http2",
                "--cacert",
                str(DEV_CERT),
                "--resolve",
                f"waitless.local:{TLS_PORT}:127.0.0.1",
                "--parallel",
                "--parallel-immediate",
                *urls,
            ],
            capture_output=True,
            timeout=20,
        )
        out = proc.stdout
        n_doctype = out.count(b"<!DOCTYPE html>")
        n_close = out.count(b"</html>")
        self.assertEqual(
            n_doctype,
            len(urls),
            f"expected {len(urls)} full HTML pages over h2, got {n_doctype} "
            f"(stderr={proc.stderr[:200]!r})",
        )
        self.assertEqual(n_close, len(urls), "some h2 page bodies were truncated")

    def test_h2_upload_streams_with_flow_control(self) -> None:
        """POST a 512 KiB body over HTTP/2 to `/discard`.

        Exercises the streamed h2 request-body path end to end. The body
        is larger than BOTH the old whole-body buffer cap (256 KiB,
        beyond which the stream used to be reset) AND the 65535-byte h2
        stream flow-control window — so completing it requires the
        handler to run as its own task while the demux feeds DATA into
        the body channel and emits WINDOW_UPDATE credit as the handler
        drains. Before the streaming rework this size would have been
        rejected; without correct flow-control crediting it would stall.
        """
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        try:
            ver = subprocess.run(["curl", "-V"], capture_output=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("curl not available")
        if b"HTTP2" not in ver and b"http2" not in ver:
            self.skipTest("local curl lacks HTTP/2 support")
        payload = (b"waitless-h2-upload!" * 30_000)[: 512 * 1024]  # 512 KiB
        self.assertGreater(len(payload), 256 * 1024, "must exceed the old buffer cap")
        proc = subprocess.run(
            [
                "curl",
                "-s",
                "--http2",
                "--cacert",
                str(DEV_CERT),
                "--resolve",
                f"waitless.local:{TLS_PORT}:127.0.0.1",
                "-X",
                "POST",
                "--data-binary",
                "@-",
                "-H",
                "Content-Type: application/octet-stream",
                "-o",
                "-",
                "-w",
                "\n__CODE__:%{http_code}__VER__:%{http_version}\n",
                f"https://waitless.local:{TLS_PORT}/discard",
            ],
            input=payload,
            capture_output=True,
            timeout=25,
        )
        out = proc.stdout
        self.assertIn(
            b"__VER__:2", out, f"curl didn't use HTTP/2 (stderr={proc.stderr[:200]!r})"
        )
        self.assertIn(
            b"__CODE__:200",
            out,
            f"512 KiB h2 upload should stream to 200 (out={out[:200]!r}, "
            f"stderr={proc.stderr[:200]!r})",
        )
        self.assertIn(b"discarded", out, "missing /discard body")

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
            port=TLS_PORT,
            ca_file=DEV_CERT,
        )
        self.assertTrue(
            first_was_fresh, "first handshake should be fresh (no cached session)"
        )
        self.assertTrue(
            second_was_resumed, "second handshake should reuse the ticket from #1"
        )

    # ── HTTP/3 over QUIC ─────────────────────────────────────────
    def test_h3_health(self) -> None:
        """End-to-end HTTP/3 GET against the same handler that
        serves HTTPS/1.1 — exercises the full stack
        `waitless-quic` (QUIC v1 transport) → `waitless-http3` (H3 frames +
        QPACK static-only) → `waitless-http` Request/Response.
        Skips if `aioquic` isn't available locally.
        """
        status, body = h3_get("/health", port=TLS_PORT)
        self.assertEqual(status, 200)
        self.assertIn(b"status", body)

    def test_h3_all_shell_pages(self) -> None:
        """Same body-integrity check as `test_https_all_shell_pages`
        but over HTTP/3. The H3 server's `write_response` walks the
        same `ResponseBody::Chain`, queuing each chunk as a separate
        SendStream Bytes — a multi-KiB page therefore spans multiple
        QUIC packets and exercises the SendStream `head_consumed`
        cursor (chunk too big for one packet → split). Anything that
        breaks chunk ordering, FIN-on-last-chunk, or QPACK content-
        length encoding shows up as a size/boundary mismatch here."""
        for path, title, active in self.SHELL_PAGES:
            with self.subTest(path=path):
                status, body = h3_get(path, port=TLS_PORT)
                self.assertEqual(status, 200)
                self._assert_full_html(body, title, active)

    def test_h3_upload_streams_past_old_cap(self) -> None:
        """POST a 64 KiB body over HTTP/3 to `/discard`.

        Regression guard for the streamed request-body work: h3 used to
        buffer the whole body in a fixed 16 KiB `RECV_CAP` and close the
        stream on overflow, so an upload this size would have failed.
        With `H3BodySource` the body streams through `BodyReader`
        (no whole-body buffer, no cap), so `/discard` drains all 64 KiB
        and returns 200. Exercises the streaming path end-to-end —
        dispatch-after-HEADERS, incremental DATA parsing, FIN-delimited
        drain — that GET-only tests never touch.

        Sized at 64 KiB: comfortably past the old 16 KiB cap, but under
        the QUIC `initial_max_stream_data` window (256 KiB) so the test
        doesn't depend on `MAX_STREAM_DATA` flow-control extension (a
        separate QUIC-transport item)."""
        payload = (b"waitless-h3-upload!" * 4000)[: 64 * 1024]  # 64 KiB
        self.assertGreater(len(payload), 16 * 1024, "must exceed the old cap")
        status, body = h3_post("/discard", payload, port=TLS_PORT)
        self.assertEqual(status, 200, "large h3 upload should stream, not overflow")
        self.assertIn(b"discarded", body)

    def test_h3_upload_past_flow_control_window(self) -> None:
        """POST a 1.5 MiB body over HTTP/3 to `/discard`.

        Exercises the QUIC receive-flow-control extension
        (MAX_STREAM_DATA + MAX_DATA). The body is larger than BOTH
        initial windows we advertise in transport params — 256 KiB per
        stream and 1 MiB per connection — so completing it *requires*
        the server to slide both windows forward as the handler drains
        the body. aioquic blocks at each window edge (and sends
        STREAM_DATA_BLOCKED / DATA_BLOCKED); the upload only finishes if
        our reactive credit reaches the client. Before the flow-control
        work this would stall at 256 KiB and time out."""
        # QEMU-TCG can't push 1.5 MiB through QUIC's flow-controlled,
        # many-round-trip transfer within 25 s — each credit grant costs
        # an emulated RTT, so the upload stalls at a window edge waiting
        # for the next MAX_DATA. HVF + native (the representative paths)
        # cover the window-sliding; test_h3_upload_streams_past_old_cap
        # exercises h3 streaming under TCG with a body small enough to
        # finish. So skip the heavy case on the slow emulated runners.
        if "qemu" in LAUNCHER_NAME:
            self.skipTest(
                f"1.5 MiB h3 upload is too slow under TCG emulation; "
                f"launcher={LAUNCHER_NAME}"
            )
        payload = (b"waitless-h3-bigupload!" * 80_000)[: 3 * 512 * 1024]  # 1.5 MiB
        self.assertGreater(len(payload), 1 << 20, "must exceed the 1 MiB conn window")
        status, body = h3_post("/discard", payload, port=TLS_PORT, timeout=25.0)
        self.assertEqual(status, 200, "upload must stream past both initial windows")
        self.assertIn(b"discarded", body)

    def test_h3_concurrent_uploads(self) -> None:
        """Several streamed h3 uploads in flight at once.

        Opens N concurrent HTTP/3 connections (one upload stream each),
        each POSTing a body past the 256 KiB per-stream initial window
        to `/discard` — so every upload must slide its own stream window
        (MAX_STREAM_DATA) while the others are mid-flight. Stresses the
        per-connection QUIC tasks + reactive flow control *under
        concurrency*, the h3-specific risk in the streamed-body path.
        (The gve NIC datapath under upload load is covered transport-
        agnostically by the h1.1/h2 upload tests.)"""
        # TCG can't push many concurrent flow-controlled QUIC uploads in
        # reasonable wall-time (each credit grant is an emulated RTT);
        # native + HVF are the representative runners for this.
        if "qemu" in LAUNCHER_NAME:
            self.skipTest(f"concurrent h3 uploads too slow under TCG; launcher={LAUNCHER_NAME}")
        from concurrent.futures import ThreadPoolExecutor

        n = 8
        payload = (b"waitless-h3-concurrent!" * 20_000)[: 384 * 1024]  # 384 KiB
        self.assertGreater(len(payload), 256 * 1024, "must exceed the 256 KiB stream window")

        def one(_i: int) -> tuple[int, bytes]:
            return h3_post("/discard", payload, port=TLS_PORT, timeout=30.0)

        with ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(one, range(n)))

        for i, (status, body) in enumerate(results):
            self.assertEqual(status, 200, f"concurrent upload {i} failed (status={status})")
            self.assertIn(b"discarded", body, f"concurrent upload {i} missing discard ack")

    def test_h3_burst_20_conns(self) -> None:
        """20 sequential HTTP/3 GETs over fresh connections.

        Each `h3_get` opens a new QUIC connection. Below the
        per-IP slot cap (64) but enough to exercise repeated
        handshake + slot-table churn. Catches regressions in
        the QUIC connection lifecycle that wouldn't surface in
        a single-conn smoke test (slot recycling, generation
        bump, key derivation freshness, etc.).

        We don't go higher because aioquic's `async with` exit
        doesn't always send a CONNECTION_CLOSE before tearing
        the socket down — lingering server-side conns then hold
        slots until idle timeout, and a 200-burst test would
        exceed the cap in a way unrelated to the QUIC stack
        itself.
        """
        n = 20
        failures = []
        for i in range(n):
            try:
                status, body = h3_get("/health", port=TLS_PORT)
                if status != 200 or b"status" not in body:
                    failures.append(f"#{i}: status={status} body={body!r}")
            except Exception as e:
                failures.append(f"#{i}: {e!r}")
                if len(failures) >= 5:
                    break
        self.assertFalse(failures, f"{len(failures)}/{n} failed: {failures[:5]}")

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

    def test_https_burst_multi_part_body(self) -> None:
        """20 back-to-back HTTPS GETs against `/diagnostics` — the
        biggest multi-part body the server emits (~9 KiB across 9+
        chunks, several rendered dynamically per request).

        `test_https_burst_30` only hits `/health` (single 60 B body,
        one TLS record), so a regression that corrupts a chunk
        midstream — under-sized record header, off-by-one in the TLS
        TX buffer accounting, half-flushed `drain_tx` between chunks
        — slips past it. This burst hammers the chunked path 20×
        with full-body assertions; pre-fix any flake here would hit
        every iteration deterministically because `/diagnostics` is
        the same shape every refresh."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        n = 20
        failures = []
        for i in range(n):
            try:
                status, body = https_get(
                    "/diagnostics", port=TLS_PORT, ca_file=DEV_CERT
                )
                if status != 200:
                    failures.append(f"#{i}: status={status}")
                elif not body.startswith(b"<!DOCTYPE html>"):
                    failures.append(f"#{i}: head={body[:40]!r}")
                elif not body.rstrip().endswith(b"</html>"):
                    failures.append(f"#{i}: tail={body[-40:]!r}")
                elif len(body) < 5000:
                    failures.append(f"#{i}: short body ({len(body)} B)")
            except Exception as e:
                failures.append(f"#{i}: {e!r}")
        self.assertFalse(failures, f"{len(failures)}/{n} failed: {failures[:5]}")

    def test_https_echo_roundtrip(self) -> None:
        """POST a body to `/echo` over HTTP/1.1 and HTTP/2 (TLS) and
        assert it comes back byte-identical.

        `/echo` is the streaming-echo endpoint: the handler just calls
        `res.echo_request(ct)` and the transport splices the request body
        straight back as the response body — h1 streams it chunk-by-chunk
        with bounded `O(chunk)` memory (the serve-loop splice), h2
        materialises it. This guards the wire round-trip for the
        `echo_request` API across both transports; the bounded-memory
        proof at >RAM body sizes runs on GCE (HVF's userspace TCP proxy
        is unreliable for large transfers, so we keep this modest)."""
        if not DEV_CERT.is_file():
            self.skipTest("dev_cert.pem missing from runfiles")
        # 32 KiB of non-trivial bytes — spans several chunks/records so a
        # mid-stream corruption (off-by-one record header, half-flushed
        # splice) shows up as a mismatch, not just a length error.
        payload = bytes((i * 31 + 7) & 0xFF for i in range(32 * 1024))
        try:
            ver = subprocess.run(
                ["curl", "-V"], capture_output=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("curl not available")
        has_h2 = b"HTTP2" in ver or b"http2" in ver
        for mode, flag in (("h1", "--http1.1"), ("h2", "--http2")):
            if mode == "h2" and not has_h2:
                continue  # local curl lacks h2; the h1 leg still ran
            proc = subprocess.run(
                [
                    "curl", "-s", flag,
                    "--cacert", str(DEV_CERT),
                    "--resolve", f"waitless.local:{TLS_PORT}:127.0.0.1",
                    "-X", "POST", "--data-binary", "@-",
                    "-H", "Content-Type: application/octet-stream",
                    "-H", "Expect:",  # no 100-continue; send body straight away
                    f"https://waitless.local:{TLS_PORT}/echo",
                ],
                input=payload, capture_output=True, timeout=25,
            )
            self.assertEqual(
                proc.stdout, payload,
                f"{mode}: /echo not byte-identical "
                f"(got {len(proc.stdout)} B, want {len(payload)} B; "
                f"stderr={proc.stderr[:200]!r})",
            )

    # ── UDP ──────────────────────────────────────────────────────
    def test_udp_echo(self) -> None:
        self.assertEqual(udp_echo(port=UDP_PORT), b"hello")

    # ── IPv6 dual-stack reachability ─────────────────────────────
    # The HVF runner dual-binds every `-p tcp:H:G` / `-p udp:H:G`
    # mapping on `127.0.0.1` and `[::1]`; the guest sees v4 and v6
    # frames for the same listening port via separate `IpFamily`
    # tags. Native and QEMU runners don't have a userspace v6
    # bridge, so these tests skip cleanly there.
    def _skip_unless_v6_bridge(self) -> None:
        if "hvf" not in LAUNCHER_NAME:
            self.skipTest(
                f"v6 host bridge is HVF-runner only; current launcher={LAUNCHER_NAME}"
            )

    def test_http_health_v6(self) -> None:
        self._skip_unless_v6_bridge()
        status, _ = http_get("/health", host="::1", port=PORT)
        self.assertEqual(status, 200)

    def test_https_health_v6(self) -> None:
        # Dev cert's SANs only cover 127.0.0.1 / localhost / waitless.local,
        # so a verified handshake to `[::1]` would fail Python's IP-SAN
        # check. Pass `ca_file=None` to exercise just the TLS-over-IPv6
        # transport — the verified-cert path is already covered by
        # `test_https_health` over `127.0.0.1`.
        self._skip_unless_v6_bridge()
        status, body = https_get("/health", host="::1", port=TLS_PORT, ca_file=None)
        self.assertEqual(status, 200)
        self.assertIn(b"status", body)

    def test_https_root_v6(self) -> None:
        """Multi-part body over IPv6 — regression guard for the
        family-unaware MSS bug. Pre-fix the guest TCP stack used
        `MSS=1460` for both v4 and v6, but v6 has a 40-byte
        header (vs v4's 20), so a 1460-byte v6 payload built a
        1534-byte Ethernet frame — over the 1500 MTU. /health
        fit in one short segment so it worked; the home page
        (~6 KiB across multiple full-size segments) lost data
        starting at the first 1460-byte payload, surfacing as
        Chrome's `ERR_SSL_PROTOCOL_ERROR` on
        `https://localhost/`. Resolves localhost via IPv6 first
        is exactly the path Chrome takes."""
        self._skip_unless_v6_bridge()
        status, body = https_get("/", host="::1", port=TLS_PORT, ca_file=None)
        self.assertEqual(status, 200)
        self._assert_full_html(body, "Home", '/" class="active"')

    def test_udp_echo_v6(self) -> None:
        self._skip_unless_v6_bridge()
        self.assertEqual(udp_echo(host="::1", port=UDP_PORT), b"hello")

    # ── Async TCP reactor end-to-end (waitless::runtime::TcpListener) ──
    def test_tcp_echo(self) -> None:
        """Validates `waitless::runtime::TcpListener::bind(9)?.run(...)` —
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
        sourced from `waitless::boot_info()` — the user-facing API check
        that the boot snapshot makes it through the runfiles bundle on
        whichever runner this test happens to be running under
        (hvf / qemu / iso / native). Kernel-side hardware info appears
        on separate `cpu:` / `mem:` / `nic:` lines from boot/entry.rs;
        this assertion specifically guards the *app-visible* surface.
        """
        log = self.launcher.log_path.read_bytes()
        self.assertIn(
            b"app: ram=",
            log,
            f"app boot_info line missing from serial log (length={len(log)})",
        )
        self.assertIn(b"cpus=", log)


class WebserverShutdownTest(unittest.TestCase):
    """Verify a Ctrl-C byte on the guest serial shuts the VM down promptly.

    Catches event-loop starvation: the kernel boots (HTTP works in
    WebserverServiceTest) but `check_shutdown` never runs because CPU
    is monopolised — e.g. the virtio-mmio IRQ storm that 38abf2d fixed.
    QEMU -chardev stdio / HVF raw-mode stdin / native POSIX SIGINT all
    funnel into the same 0x03 → PSCI/ACPI shutdown path in the guest.
    """

    def _run_shutdown_scenario(
        self,
        *,
        port_offset: int,
        hammer: bool,
        h3_hammer: bool = False,
        h3_persistent: bool = False,
    ):
        """Boot, optionally hammer HTTP and/or HTTP/3, send ^C, wait for VM
        exit. Returns the captured serial buffer for further assertions."""
        port = PORT + port_offset
        tls_port = TLS_PORT + port_offset
        udp_port = UDP_PORT + port_offset
        tcp_echo_port = TCP_ECHO_PORT + port_offset
        pty_launcher = PtyLauncher(
            LAUNCHER,
            env=_launcher_env(port, tls_port, udp_port, tcp_echo_port),
        )
        stop_hammer = [False]
        # Track every hammer thread so `finally` can `join` them. Each
        # iteration parks in `subprocess.run(... --max-time 1)` /
        # `asyncio.run(h3_get)` for up to ~2 s after `stop_hammer[0]`
        # flips, so without joining, daemons leak into the next test
        # method's `PtyLauncher.__init__` — and `pty.fork()` in a
        # multi-threaded process can deadlock the child on the macOS
        # malloc lock, stalling the guest mid-boot.
        workers: list[threading.Thread] = []

        def _spawn(target) -> None:
            w = threading.Thread(target=target, daemon=True)
            workers.append(w)
            w.start()

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
                            [
                                "curl",
                                "-s",
                                "--max-time",
                                "1",
                                f"http://127.0.0.1:{port}/health",
                            ],
                            capture_output=True,
                        )

                for _ in range(3):
                    _spawn(_hammer)
            if h3_hammer:
                # H3 hammer: each iteration opens a fresh QUIC conn,
                # sends one GET, awaits the response, closes. Exercises
                # the handshake → request → reap path (which item B2
                # and the recent stream-retransmit fix touch). 8 parallel
                # workers and a 5-second window run hundreds of conns
                # through the reaper, so any per-conn alloc that
                # doesn't drop on conn teardown shows up as a clear
                # multi-alloc leak in the post-shutdown delta.
                def _h3_hammer() -> None:
                    while not stop_hammer[0]:
                        try:
                            h3_get("/health", port=tls_port, timeout=2.0)
                        except Exception:
                            pass

                for _ in range(8):
                    _spawn(_h3_hammer)
            if h3_persistent:
                # Single LONG-LIVED H3 conn that stays alive across ^C.
                # Mirrors a real browser keeping a tab open: conn stays
                # in mid-await state when shutdown_and_drop fires, and
                # `mark_terminated` doesn't get a chance to run (the
                # future is force-dropped by `drain_all_arenas`).
                # Connection's Rc count must still hit 0 via captured-
                # field drops — if it doesn't, we leak the conn-state
                # heap (BTreeMaps + per-stream Vecs).
                #
                # We start the session in a daemon thread so the
                # main test thread can ^C the launcher while the
                # session is still actively pumping packets.
                def _persistent() -> None:
                    try:
                        import asyncio
                        import aioquic.asyncio.client as aclient
                        from aioquic.asyncio.protocol import QuicConnectionProtocol
                        from aioquic.h3.connection import H3_ALPN, H3Connection
                        from aioquic.quic.configuration import QuicConfiguration

                        class P(QuicConnectionProtocol):
                            def __init__(self, *a, **kw):
                                super().__init__(*a, **kw)
                                self.h3 = H3Connection(self._quic)

                            def quic_event_received(self, event):
                                for _ in self.h3.handle_event(event):
                                    pass

                        async def go() -> None:
                            cfg = QuicConfiguration(
                                is_client=True, alpn_protocols=H3_ALPN
                            )
                            cfg.verify_mode = False
                            cfg.idle_timeout = 60
                            async with aclient.connect(
                                "127.0.0.1",
                                tls_port,
                                configuration=cfg,
                                create_protocol=P,
                                wait_connected=True,
                            ) as c:
                                assert isinstance(c, P)
                                while not stop_hammer[0]:
                                    sid = c._quic.get_next_available_stream_id()
                                    c.h3.send_headers(
                                        stream_id=sid,
                                        headers=[
                                            (b":method", b"GET"),
                                            (b":scheme", b"https"),
                                            (
                                                b":authority",
                                                f"127.0.0.1:{tls_port}".encode(),
                                            ),
                                            (b":path", b"/diagnostics"),
                                        ],
                                        end_stream=True,
                                    )
                                    c.transmit()
                                    await asyncio.sleep(0.5)

                        asyncio.run(go())
                    except Exception:
                        pass

                _spawn(_persistent)
            # Longer dwell when h3-hammering so the test exercises
            # enough conns to surface a per-conn leak signal above
            # noise. Plain HTTP hammer keeps the original 2 s.
            time.sleep(5 if (h3_hammer or h3_persistent) else 2)

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
            for w in workers:
                w.join(timeout=3.0)
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
        if leak_line is None:
            self.fail("no HEAP_LEAK_CHECK line in serial log")
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK",
            leak_line,
            "active-traffic shutdown leaked memory — "
            "drain_all_arenas didn't reclaim in-flight task storage",
        )

    def test_ctrlc_h3_hammer_no_per_conn_leak(self) -> None:
        """Active-traffic ^C with HTTP/3 hammer doesn't leak per-conn
        state. The QUIC reactor's per-conn `Connection` (with its
        recv/send pools, outbound-Vec recycle pool, stream BTreeMaps,
        and reaped-streams ring) must drop cleanly when
        `drain_all_arenas` reclaims both the conn task and the user
        handler.

        Originally caught by the user as `delta=+12251B,+10allocs`
        after a real H3 bench. Root cause: conn-task `break` paths
        (idle timeout, batch-limit reached, …) didn't transition the
        Connection to `Failed`, so the user handler's `accept_stream`
        kept waiting on `progress.wait()` forever and its
        `Rc<Connection>` never dropped. Fixed by `mark_terminated`
        before the final `progress.set()` in `conn_task`.

        Aioquic-driven hammer: serial GETs only, no Chrome-specific
        frame patterns (PRIORITY_UPDATE, QPACK encoder probes, etc.)
        — see the Chrome residue bullet under item O in
        `docs/tx-path-optimizations.md`. Currently lands at
        delta=-55 allocs / -3680 bytes post-preinit, so this test
        asserts strict `ok` (no `LEAK` line at all).

        Skips if `aioquic` isn't importable."""
        try:
            import aioquic  # noqa: F401
        except ImportError:
            self.skipTest("aioquic not installed")
        buf = self._run_shutdown_scenario(
            port_offset=300,
            hammer=False,
            h3_hammer=True,
        )
        leak_line = next(
            (line for line in buf.splitlines() if b"HEAP_LEAK_CHECK" in line),
            None,
        )
        if leak_line is None:
            self.fail("no HEAP_LEAK_CHECK line in serial log")
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK",
            leak_line,
            "H3-hammer leaked memory — per-conn cleanup regression "
            f"({leak_line.decode(errors='replace')})",
        )

    def test_ctrlc_h3_persistent_session_no_leak(self) -> None:
        """Active QUIC conn at ^C — matches a browser tab kept open.

        Mirrors what Chrome does: open ONE QUIC conn, hold it across
        many requests, never CONNECTION_CLOSE the conn. When the user
        ^Cs the unikernel mid-session, `drain_all_arenas` force-drops
        the conn_task and user-handler futures while they're both
        suspended on awaits. `mark_terminated` (commit `1e73a40`)
        doesn't run on this path — it's after the conn_task loop, and
        the future is destroyed before the loop returns. Connection
        cleanup must therefore happen via the future's struct-field
        drop chain (Rc<RefCell<Connection>> → strong count 0 →
        Connection drops → recv/send_streams BTreeMaps drop → all
        per-stream allocations release).

        User-reported leak in this exact shape was
        `delta=+12412B,+10allocs` after Chrome auto-refreshed
        /diagnostics on a kept-open tab. The cold-conn lazy-init
        portion (~12 KB) was killed by `waitless_tls::preinit` +
        `huffman::warmup`; the small Chrome-specific residue that
        survives is tracked under item O in
        `docs/tx-path-optimizations.md` and only reproduces on
        Chrome (not aioquic — see commit message for the smoking-
        gun PRIORITY_UPDATE / QPACK-encoder-probe analysis).
        Aioquic-driven persistent session lands at delta=-55
        allocs / -3680 bytes post-preinit, so this test asserts
        strict `ok` (no `LEAK` line at all).

        Skips if `aioquic` isn't importable."""
        try:
            import aioquic  # noqa: F401
        except ImportError:
            self.skipTest("aioquic not installed")
        buf = self._run_shutdown_scenario(
            port_offset=400,
            hammer=False,
            h3_persistent=True,
        )
        leak_line = next(
            (line for line in buf.splitlines() if b"HEAP_LEAK_CHECK" in line),
            None,
        )
        if leak_line is None:
            self.fail("no HEAP_LEAK_CHECK line in serial log")
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK",
            leak_line,
            "H3-persistent leaked memory — Connection didn't drop "
            f"on force-shutdown ({leak_line.decode(errors='replace')})",
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
        if leak_line is None:
            self.fail(
                "no HEAP_LEAK_CHECK line in serial log — shutdown_and_drop didn't run?"
            )
        print(f"    {leak_line.decode(errors='replace')}", flush=True)
        self.assertNotIn(
            b"HEAP_LEAK_CHECK LEAK",
            leak_line,
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
                    tail,
                    b"",
                    f"unexpected post-shutdown payload: {tail[:80]!r}",
                )
                close_kind = "FIN"
            except ConnectionResetError:
                close_kind = "RST"
            finally:
                stop_drain[0] = True
                drainer.join(timeout=1.0)
            elapsed = time.monotonic() - t0
            print(
                f"    (peer observed {close_kind} in {elapsed * 1000:.0f} ms)",
                flush=True,
            )
            self.assertLess(
                elapsed,
                2.0,
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
