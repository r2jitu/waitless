#!/usr/bin/env python3
"""apps/socks/test.py — end-to-end test for the SOCKS5 proxy app.

Drives the proxy with a hand-rolled SOCKS5 client (no PySocks
dependency — the wire is simple enough to speak directly, and it keeps
the byte layout visible in the test) THROUGH the running proxy to a
tiny host-side TCP echo backend, asserting the relayed bytes survive
both directions.

NATIVE-ONLY. The full showcase needs three parties on one host: the
backend, the proxy, and the client. On the `native` variant the proxy
*is* a host process (binds 0.0.0.0:1080, dials the backend via the host
TCP stack), so all three share loopback and the relay is exercised
exactly as on bare metal. On VM runners the guest proxy would have to
`tcp_connect` out to a host backend through the runner's toy outbound
proxy — a different, flakier path that doesn't add coverage of the SOCKS
logic. The protocol *parsing* is pinned on every platform by the
`socks5_test` Rust host unit test; this file pins the live relay.
"""

from __future__ import annotations

import os
import socket
import socketserver
import struct
import sys
import threading
import time
import unittest

from scripts.test_helpers import (
    runfiles_root,
    spawn_backgrounded,
)

ROOT = runfiles_root()
LAUNCHER_NAME = os.environ["LAUNCHER_NAME"]
LAUNCHER = ROOT / "apps" / "socks" / LAUNCHER_NAME
BOOT_MARKER = b"socks5 CONNECT proxy"

# The proxy's front-door port (guest 1080 → host port). The native
# launcher reads WAITLESS_TCP_1080; we pick a high test port to avoid
# clashing with anything on 1080.
SOCKS_PORT = int(os.environ.get("TEST_SOCKS_PORT", 11080))

# SOCKS5 reply codes we assert on (mirror socks5::rep).
REP_SUCCEEDED = 0x00
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

if not (LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)):
    sys.exit(f"ERROR: launcher missing / not executable: {LAUNCHER}")


# ---- Host-side echo backend -------------------------------------------------
# The target the proxy relays to. Echoes whatever it receives — so the
# test can drive bytes through the proxy in both directions and compare.
class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _wait_port_open(port: int, timeout: float = 20.0) -> bool:
    """Poll until something accepts TCP on 127.0.0.1:port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---- SOCKS5 client (hand-rolled) --------------------------------------------
def _socks5_connect(
    proxy_port: int, dst_ip: str, dst_port: int, *, atyp: int = 0x01
) -> tuple[socket.socket, int]:
    """Open a SOCKS5 CONNECT through the proxy. Returns (socket, rep).

    Speaks the RFC 1928 sequence by hand: greeting (no-auth) → method
    reply → CONNECT request → reply. The socket is left positioned right
    after the 10-byte reply, ready to relay. On a non-success reply the
    socket is still returned (closed by the proxy) so callers can assert
    the code.
    """
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    # Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
    s.sendall(bytes([0x05, 0x01, 0x00]))
    sel = s.recv(2)
    assert sel == bytes([0x05, 0x00]), f"method selection: {sel!r}"
    # Request: VER CMD=CONNECT RSV ATYP DST.ADDR DST.PORT (IPv4).
    addr = socket.inet_aton(dst_ip)
    req = bytes([0x05, 0x01, 0x00, atyp]) + addr + struct.pack(">H", dst_port)
    s.sendall(req)
    reply = _recv_exact(s, 10)
    rep = reply[1] if len(reply) >= 2 else 0xFF
    return s, rep


def _recv_exact(s: socket.socket, n: int) -> bytes:
    """Read exactly n bytes (or whatever arrives before EOF)."""
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


class SocksProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if "native" not in LAUNCHER_NAME:
            raise unittest.SkipTest(
                f"socks relay e2e is native-only; launcher={LAUNCHER_NAME} "
                "(protocol parsing is covered by //apps/socks:socks5_test)"
            )
        # Host-side echo backend on an ephemeral loopback port.
        cls.echo = _EchoServer(("127.0.0.1", 0), _EchoHandler)
        cls.echo_port = cls.echo.server_address[1]
        cls.echo_thread = threading.Thread(target=cls.echo.serve_forever, daemon=True)
        cls.echo_thread.start()

        # The proxy itself, listening on SOCKS_PORT (native reads
        # WAITLESS_TCP_1080 to override the BUILD-default guest port).
        cls.launcher = spawn_backgrounded(
            LAUNCHER,
            env={"WAITLESS_TCP_1080": str(SOCKS_PORT)},
            log_prefix="socks_svc",
        )
        if not _wait_port_open(SOCKS_PORT, timeout=20.0):
            try:
                sys.stderr.buffer.write(cls.launcher.log_path.read_bytes())
            except OSError:
                pass
            cls.launcher.terminate()
            raise RuntimeError(f"socks proxy not accepting on :{SOCKS_PORT} after 20s")

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "launcher"):
            cls.launcher.cleanup()
        if hasattr(cls, "echo"):
            cls.echo.shutdown()
            cls.echo.server_close()
            cls.echo_thread.join(timeout=3.0)

    def test_relay_roundtrip(self) -> None:
        """CONNECT to the echo backend, relay a payload, get it back."""
        s, rep = _socks5_connect(SOCKS_PORT, "127.0.0.1", self.echo_port)
        self.addCleanup(s.close)
        self.assertEqual(rep, REP_SUCCEEDED, "CONNECT should succeed")
        payload = b"hello through the socks5 relay\n"
        s.sendall(payload)
        got = _recv_exact(s, len(payload))
        self.assertEqual(got, payload, "relayed bytes must match")

    def test_relay_larger_than_one_segment(self) -> None:
        """A payload spanning several TCP segments + relay buffers."""
        s, rep = _socks5_connect(SOCKS_PORT, "127.0.0.1", self.echo_port)
        self.addCleanup(s.close)
        self.assertEqual(rep, REP_SUCCEEDED)
        payload = bytes((i & 0xFF) for i in range(200_000))  # ~200 KB
        s.sendall(payload)
        got = _recv_exact(s, len(payload))
        self.assertEqual(len(got), len(payload), "all relayed bytes received")
        self.assertEqual(got, payload, "large relay payload integrity")

    def test_domain_atyp_rejected(self) -> None:
        """A domain-target request gets REP=0x08 (addr-type unsupported)."""
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=5.0)
        self.addCleanup(s.close)
        s.sendall(bytes([0x05, 0x01, 0x00]))  # greeting
        self.assertEqual(s.recv(2), bytes([0x05, 0x00]))
        # CONNECT with ATYP=0x03 (domain) "example.com":80.
        host = b"example.com"
        req = (
            bytes([0x05, 0x01, 0x00, 0x03, len(host)])
            + host
            + struct.pack(">H", 80)
        )
        s.sendall(req)
        reply = _recv_exact(s, 10)
        self.assertGreaterEqual(len(reply), 2)
        self.assertEqual(reply[0], 0x05)
        self.assertEqual(reply[1], REP_ADDRESS_TYPE_NOT_SUPPORTED)

    def test_non_socks_greeting_closed(self) -> None:
        """A non-0x05 first byte makes the proxy close without a reply."""
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=5.0)
        self.addCleanup(s.close)
        s.sendall(b"GET / HTTP/1.1\r\n\r\n")  # VER byte 'G' != 0x05
        s.settimeout(5.0)
        # The proxy reads the bogus greeting and closes — we see EOF.
        self.assertEqual(s.recv(16), b"", "proxy should close a non-SOCKS client")

    def test_connect_refused_maps_to_reply(self) -> None:
        """CONNECT to a closed port yields a non-success reply, not a hang."""
        # 127.0.0.1:1 — nothing listens; the host stack RSTs promptly.
        s, rep = _socks5_connect(SOCKS_PORT, "127.0.0.1", 1)
        self.addCleanup(s.close)
        self.assertNotEqual(rep, REP_SUCCEEDED, "refused connect must not report success")


if __name__ == "__main__":
    unittest.main()
