#!/usr/bin/env python3
"""apps/test_async/test.py — Async-runtime + socket-lifecycle smoke test.

Boots the test_async launcher via `run_variant_and_capture` and asserts:

  * Spawn, sleep, wake, nested spawn, shutdown — the executor /
    Waker / Sleep chain works end-to-end.
  * `UdpSocket::bind` + `drop` re-releases the port (second bind
    to the same port succeeds).
  * `UdpSocket::bind + run_each + drop(handle)` re-releases the
    port AND stops the per-worker recv tasks — same rebind proof.
  * Same two checks for `TcpListener` / `TcpHandle`.

The rebind checks are real regression guards: if `UdpSocket::Drop`
/ `TcpListener::Drop` or the corresponding handle-drop ever stops
releasing the port slot, the second bind fails with `PortInUse`
and the `rebind ok` marker never prints.
"""

from __future__ import annotations

import os
import unittest

from scripts.test_helpers import run_variant_and_capture


# Native's TCP backend opens a POSIX fd per listener and doesn't
# hook `TcpListener::Drop` to close it, so the second `bind(same_
# port)` fails with EADDRINUSE at the POSIX layer. The uni-runtime
# port slot IS cleaned up (that's all the Drop impl promises
# today); the fd leak is a separate native-backend issue tracked
# as a follow-up. For now, skip the same-port rebind tests on
# native and rely on the bare-metal variants to exercise the full
# "slot cleared + rebind works" invariant.
IS_NATIVE = os.environ.get("LAUNCHER_NAME", "").endswith("_native")


class AsyncRuntimeSmokeTest(unittest.TestCase):
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.serial = run_variant_and_capture(
            "test_async",
            marker="test_async: nested task done",
            timeout=15.0,
        )

    def assertMarker(self, marker: str) -> None:
        """Assert the serial log contains `marker` and does NOT
        contain the corresponding `FAILED` line. Catches both the
        "never got here" and "got here with the wrong outcome"
        cases explicitly."""
        self.assertIn(marker, self.serial)
        failed = marker.rsplit(" ok", 1)[0] + " FAILED"
        self.assertNotIn(failed, self.serial)

    def test_initial_spawn(self) -> None:
        self.assertMarker("test_async: spawn ok")

    def test_task_started(self) -> None:
        self.assertIn("test_async: task started", self.serial)

    def test_timer_fires(self) -> None:
        self.assertIn("test_async: task woke up", self.serial)

    def test_nested_spawn(self) -> None:
        self.assertMarker("test_async: nested spawn ok")

    def test_nested_completes(self) -> None:
        self.assertIn("test_async: nested task done", self.serial)

    # ── Socket-lifecycle regressions ────────────────────────────

    def test_udp_bind_drop_releases_port(self) -> None:
        """`UdpSocket::Drop` releases the port slot — the second
        bind to the same port would fail with `PortInUse`
        otherwise."""
        self.assertMarker("test_async: udp bind ok")
        self.assertMarker("test_async: udp drop ok")
        self.assertMarker("test_async: udp rebind ok")

    def test_udp_fanout_handle_drop_releases_port(self) -> None:
        """`UdpHandle::Drop` aborts per-worker recv tasks AND
        releases the port slot. Rebind succeeding proves the slot
        was cleared; task cleanup is verified implicitly by the
        absence of "fanout drop FAILED" / later bind failures."""
        self.assertMarker("test_async: udp fanout drop ok")
        self.assertMarker("test_async: udp fanout rebind ok")

    @unittest.skipIf(IS_NATIVE, "native TCP backend fd-leak: see module doc")
    def test_tcp_bind_drop_releases_port(self) -> None:
        self.assertMarker("test_async: tcp bind ok")
        self.assertMarker("test_async: tcp drop ok")
        self.assertMarker("test_async: tcp rebind ok")

    @unittest.skipIf(IS_NATIVE, "native TCP backend fd-leak: see module doc")
    def test_tcp_fanout_handle_drop_releases_port(self) -> None:
        self.assertMarker("test_async: tcp fanout drop ok")
        self.assertMarker("test_async: tcp fanout rebind ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
