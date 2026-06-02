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
    log_prefix: str = "waitless_test",
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
            stdout=log_fd,
            stderr=log_fd,
            stdin=subprocess.DEVNULL,
        )
    return Launcher(proc=proc, log_path=log_path)


def run_variant_and_capture(
    package: str,
    *,
    marker: str,
    timeout: float,
) -> str:
    """Spawn the `LAUNCHER_NAME` variant in `apps/<package>`, wait for
    `marker`, terminate, and return the captured serial log.

    Encapsulates the "boot, wait for a terminal marker, assert on the
    log" pattern used by apps that don't probe the guest over the
    network (test_smp, test_percpu, test_tls). setUpClass shrinks to
    one call; the launcher's lifecycle + temp-log cleanup happen
    inside this function.
    """
    import unittest  # local — this helper is only used in test setUp paths.

    launcher_name = os.environ["LAUNCHER_NAME"]
    launcher_path = runfiles_root() / "apps" / package / launcher_name
    if not (launcher_path.is_file() and os.access(launcher_path, os.X_OK)):
        raise unittest.SkipTest(f"launcher not executable: {launcher_path}")
    launcher = spawn_backgrounded(launcher_path, log_prefix=launcher_name)
    try:
        if not wait_for_marker(launcher, marker, timeout=timeout):
            raise RuntimeError(f"guest never printed {marker!r} within {timeout}s")
        launcher.terminate()
        return launcher.log_path.read_text(errors="replace")
    finally:
        launcher.cleanup()


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
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int,
    timeout: float = 3.0,
) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def h3_get(
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int,
    timeout: float = 6.0,
) -> tuple[int, bytes]:
    """HTTP/3 GET via `aioquic`. Returns `(status, body)` like `http_get`.

    Probes the unikernel's HTTP/3 endpoint over QUIC v1. Uses
    `aioquic`'s `QuicConnectionProtocol` subclass shape so events
    flow through `quic_event_received` (not `_quic.next_event()`,
    which bypasses the protocol's own dispatch and silently drops
    DataReceived).

    Raises `unittest.SkipTest` if `aioquic` isn't importable —
    the H3 stack is otherwise covered by host unit tests, so a
    missing `aioquic` install shouldn't break the test suite.
    """
    try:
        import asyncio
        import aioquic.asyncio.client as aclient
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived, DataReceived
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import QuicEvent
    except ImportError as exc:
        import unittest

        raise unittest.SkipTest(f"aioquic not installed: {exc}")

    class H3Probe(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)
            self.done = asyncio.get_event_loop().create_future()
            self.body = bytearray()
            self.status: Optional[bytes] = None

        def quic_event_received(self, event):
            for h3_event in self.h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    for k, v in h3_event.headers:
                        if k == b":status":
                            self.status = v
                    if h3_event.stream_ended and not self.done.done():
                        self.done.set_result((self.status, bytes(self.body)))
                elif isinstance(h3_event, DataReceived):
                    self.body.extend(h3_event.data)
                    if h3_event.stream_ended and not self.done.done():
                        self.done.set_result((self.status, bytes(self.body)))

    async def _fetch():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        cfg.verify_mode = False  # accept self-signed dev cert
        cfg.idle_timeout = timeout
        async with aclient.connect(
            host,
            port,
            configuration=cfg,
            create_protocol=H3Probe,
            wait_connected=True,
        ) as client:
            sid = client._quic.get_next_available_stream_id()
            client.h3.send_headers(
                stream_id=sid,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", path.encode()),
                ],
                end_stream=True,
            )
            client.transmit()
            status, body = await asyncio.wait_for(client.done, timeout=timeout)
            return int(status), body

    return asyncio.run(_fetch())


def h3_post(
    path: str,
    body: bytes,
    *,
    host: str = "127.0.0.1",
    port: int,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    """HTTP/3 POST of `body` via `aioquic`. Returns `(status, body)`.

    Sends HEADERS (with `content-length`) then the body as DATA frames
    and END_STREAM, so it exercises the server's streamed request-body
    path. Used to verify large uploads (past the old fixed RX cap) work.

    Raises `unittest.SkipTest` if `aioquic` isn't importable.
    """
    try:
        import asyncio
        import aioquic.asyncio.client as aclient
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived, DataReceived
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError as exc:
        import unittest

        raise unittest.SkipTest(f"aioquic not installed: {exc}")

    class H3Probe(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)
            self.done = asyncio.get_event_loop().create_future()
            self.body = bytearray()
            self.status: Optional[bytes] = None

        def quic_event_received(self, event):
            for h3_event in self.h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    for k, v in h3_event.headers:
                        if k == b":status":
                            self.status = v
                    if h3_event.stream_ended and not self.done.done():
                        self.done.set_result((self.status, bytes(self.body)))
                elif isinstance(h3_event, DataReceived):
                    self.body.extend(h3_event.data)
                    if h3_event.stream_ended and not self.done.done():
                        self.done.set_result((self.status, bytes(self.body)))

    async def _fetch():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        cfg.verify_mode = False
        cfg.idle_timeout = timeout
        async with aclient.connect(
            host,
            port,
            configuration=cfg,
            create_protocol=H3Probe,
            wait_connected=True,
        ) as client:
            sid = client._quic.get_next_available_stream_id()
            client.h3.send_headers(
                stream_id=sid,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", path.encode()),
                    (b"content-length", str(len(body)).encode()),
                ],
                end_stream=False,
            )
            client.h3.send_data(stream_id=sid, data=body, end_stream=True)
            client.transmit()
            status, resp = await asyncio.wait_for(client.done, timeout=timeout)
            return int(status), resp

    return asyncio.run(_fetch())


def https_get(
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int,
    ca_file: Optional[Path] = None,
    sni: str = "waitless.local",
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


def https_session_resume_check(
    *,
    host: str = "127.0.0.1",
    port: int,
    ca_file: Optional[Path] = None,
    sni: str = "waitless.local",
    timeout: float = 5.0,
) -> tuple[bool, bool]:
    """Open two TLS connections back-to-back to `host:port`, sharing
    one `SSLContext`, and report whether the second handshake reused
    the first connection's session ticket.

    Returns `(first_was_fresh, second_was_resumed)`. Both should be
    `(True, True)` on a server that correctly issues NewSessionTicket
    AND accepts the same ticket back via `pre_shared_key` on the
    next handshake.

    Useful for asserting end-to-end resumption (binder verify + Cert
    skip) without measuring timing — Python's `ssl.SSLSocket.session_reused`
    is the OpenSSL flag set after a handshake hits the resumption path.
    """
    if ca_file is not None:
        ctx = ssl.create_default_context(cafile=str(ca_file))
    else:
        ctx = ssl._create_unverified_context()

    def one_handshake(prev_session=None):
        # Plain TLS handshake without HTTPS layering; we just want the
        # `session_reused` flag and the populated `session` object.
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=sni, session=prev_session)
            try:
                # Drive a request so the server emits NewSessionTicket
                # (which it does after Client Finished verifies). Server
                # closes after the response per Connection: close, so we
                # read until EOF.
                req = (
                    f"GET /health HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                ).encode()
                ssock.sendall(req)
                while True:
                    buf = ssock.recv(4096)
                    if not buf:
                        break
                reused = ssock.session_reused
                session = ssock.session
                return reused, session
            finally:
                try:
                    ssock.unwrap()
                except OSError:
                    pass
                ssock.close()
        finally:
            sock.close()

    reused1, session = one_handshake(None)
    reused2, _ = one_handshake(session)
    return (not reused1), reused2


def udp_echo(
    payload: bytes = b"hello",
    *,
    host: str = "127.0.0.1",
    port: int,
    timeout: float = 2.0,
) -> Optional[bytes]:
    # `getaddrinfo` picks AF_INET or AF_INET6 based on the literal,
    # so callers can pass `"::1"` and we open the matching family
    # without a parallel `udp_echo_v6` helper.
    info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    s = socket.socket(info[0], info[1])
    s.settimeout(timeout)
    try:
        s.sendto(payload, info[4])
        data, _ = s.recvfrom(1024)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def wait_http_ready(
    port: int, *, timeout: float, host: str = "127.0.0.1", path: str = "/health"
) -> bool:
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
