#!/usr/bin/env python3
"""apps/webserver/test_mc.py — multi-core integration test.

Companion to `test.py` (single-vCPU), intentionally narrower:

    * Boots the webserver at `UNIKERNEL_CPUS=4` so the kernel actually
      exercises the Tier-1 multi-queue path (each vCPU polls its own
      RX queue pair; `activate_multi_queue()` in `Net::enable`
      negotiates N queue pairs via `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`).

    * Fans out a burst of concurrent HTTP GETs over distinct
      ephemeral source ports so vhost-net / host-RSS hashes them
      across multiple guest RX queues. Catches the class of
      regressions where the guest accept-task only spawns on some
      cores (e.g. `spawn_on_each_worker` one-shot semantics) or the
      Tier-1 `poll_qp(core_id)` routing is broken.

    * Asserts the serial log shows multi-queue activation, so we
      never silently fall back to Tier-2 and pass this test for
      the wrong reason.

Single-vCPU coverage is already good via `test.py`. This file
deliberately adds only the cases that are specifically a
multi-core-path regression risk.
"""

from __future__ import annotations

import concurrent.futures
import os
import socket
import sys
import unittest

from scripts.test_helpers import (
    http_get,
    runfiles_root,
    spawn_backgrounded,
    wait_http_ready,
)


ROOT = runfiles_root()
LAUNCHER_NAME = os.environ["LAUNCHER_NAME"]
LAUNCHER = ROOT / "apps" / "webserver" / LAUNCHER_NAME

# Distinct port numbers from `test.py` so the two can coexist when
# bazel ever relaxes the `exclusive` tag, and so a stale VM from
# `test.py` doesn't cause a mysterious "HTTP not ready" here.
PORT = int(os.environ.get("TEST_PORT", 19080))
TLS_PORT = int(os.environ.get("TEST_TLS_PORT", 19443))
UDP_PORT = int(os.environ.get("TEST_UDP_PORT", 19007))
TCP_ECHO_PORT = int(os.environ.get("TEST_TCP_ECHO_PORT", 19009))

# Boot at 4 vCPUs. Every Apple Silicon / modern x86 host has at least
# this many; `UNIKERNEL_CPUS` is read by every variant's launcher
# (hvf / qemu_* / native) — see `bazel/rules/variants.bzl`'s
# `default_cpus` attr.
CPU_COUNT = 4


def _launcher_env() -> dict[str, str]:
    return {
        "UNIKERNEL_CPUS": str(CPU_COUNT),
        "UNIKERNEL_TCP_80": str(PORT),
        "UNIKERNEL_TCP_443": str(TLS_PORT),
        "UNIKERNEL_UDP_7": str(UDP_PORT),
        "UNIKERNEL_TCP_9": str(TCP_ECHO_PORT),
    }


if not (LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)):
    sys.exit(f"ERROR: launcher missing / not executable: {LAUNCHER}")


class WebserverMultiCoreTest(unittest.TestCase):
    """Boot once at N vCPUs, exercise the multi-queue RX + accept path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = spawn_backgrounded(
            LAUNCHER,
            env=_launcher_env(),
            log_prefix="webserver_mc",
        )
        if not wait_http_ready(PORT, timeout=30.0):
            try:
                sys.stderr.buffer.write(cls.launcher.log_path.read_bytes())
            except OSError:
                pass
            cls.launcher.terminate()
            raise RuntimeError(
                f"HTTP not ready on :{PORT} after 30s "
                f"(UNIKERNEL_CPUS={CPU_COUNT})"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.launcher.cleanup()

    def _log(self) -> bytes:
        return self.launcher.log_path.read_bytes()

    def test_boot_reports_requested_cpu_count(self) -> None:
        """boot_info ships `cpus=N` through the serial log — if the
        launcher's `UNIKERNEL_CPUS` plumbing is broken we'll silently
        test single-vCPU here and miss the whole MQ path."""
        log = self._log()
        marker = f"cpus={CPU_COUNT}".encode()
        self.assertIn(
            marker, log,
            f"expected {marker!r} in serial log; this test is meaningless "
            f"at fewer vCPUs (log length={len(log)})",
        )

    def test_multiqueue_negotiated(self) -> None:
        """virtio-net's `activate_multi_queue()` must have promoted to
        > 1 queue pair. Catches regressions where `Net::enable` stops
        calling it, or where the driver silently falls back to
        single-queue because MQ negotiation with the host failed."""
        log = self._log()
        # `virtio_net: multi-queue: N queue pairs` is emitted by
        # activate_multi_queue() on success; its absence means we're
        # running the Tier-2 fallback path and this test is lying.
        self.assertIn(
            b"multi-queue:", log,
            "virtio-net multi-queue activation log line missing; "
            "guest booted single-queue, MQ path untested",
        )

    def test_concurrent_http_burst(self) -> None:
        """Fire 32 concurrent /health GETs from 32 distinct source
        ports. vhost-net hashes the 5-tuples across RX queues, so
        responses exercise every guest core's accept-task spawn
        and the Tier-1 `poll_qp(core_id)` path. Every response must
        succeed — a single 0-byte/timeout/connection-reset means a
        core's accept task didn't register (see the
        `spawn_on_each_worker` one-shot regression).
        """
        n = 32

        def one_request(_i: int) -> tuple[int, int]:
            status, body = http_get("/health", port=PORT, timeout=5.0)
            return status, len(body)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(one_request, range(n)))

        statuses = [r[0] for r in results]
        self.assertTrue(
            all(s == 200 for s in statuses),
            f"{statuses.count(200)}/{n} got 200; non-200: "
            f"{[s for s in statuses if s != 200][:5]}",
        )
        self.assertTrue(
            all(body_len > 0 for _, body_len in results),
            "some responses had empty body",
        )

    def test_tcp_echo_from_multiple_sources(self) -> None:
        """Open 8 TCP-echo connections and interleave sends. Each
        connection's 4-tuple hashes to a (likely different) RX queue
        — if a core's accept task isn't spawned, connects to that
        queue's target core hang at connect() or never get a reply.
        """
        n_conns = 8
        sockets: list[socket.socket] = []
        try:
            for _ in range(n_conns):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect(("127.0.0.1", TCP_ECHO_PORT))
                sockets.append(s)
            # Send from all, then read from all — interleaves the
            # flow across per-core handlers in time rather than
            # connection-order.
            payload = b"mc-ping"
            for s in sockets:
                s.sendall(payload)
            for i, s in enumerate(sockets):
                got = s.recv(32)
                self.assertEqual(
                    got, payload,
                    f"conn[{i}] echoed {got!r}, expected {payload!r}",
                )
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
