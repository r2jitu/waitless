#!/usr/bin/env python3
"""apps/test_async/test.py — Async-runtime smoke test.

Boots the test_async launcher via `run_variant_and_capture` and asserts
that a spawned future runs, sleeps on a timer, wakes back up, spawns a
nested task, and requests shutdown — exercising the full executor path
end-to-end.
"""

from __future__ import annotations

import unittest

from scripts.test_helpers import run_variant_and_capture


class AsyncRuntimeSmokeTest(unittest.TestCase):
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.serial = run_variant_and_capture(
            "test_async",
            marker="test_async: nested task done",
            timeout=15.0,
        )

    def test_initial_spawn(self) -> None:
        self.assertIn("test_async: spawn ok", self.serial)

    def test_task_started(self) -> None:
        self.assertIn("test_async: task started", self.serial)

    def test_timer_fires(self) -> None:
        self.assertIn("test_async: task woke up", self.serial)

    def test_nested_spawn(self) -> None:
        self.assertIn("test_async: nested spawn ok", self.serial)

    def test_nested_completes(self) -> None:
        self.assertIn("test_async: nested task done", self.serial)
