#!/usr/bin/env python3
"""apps/test_percpu/test.py — Per-core state independence integration test.

Boots the test_percpu launcher (4 vCPUs by default from the
unikernel_binary attr) via `run_variant_and_capture` and asserts
that every core saw its own slot of TEST_DATA, tx_staging
round-tripped through each AP, etc.
"""

from __future__ import annotations

import unittest

from scripts.test_helpers import run_variant_and_capture


EXPECTED_CPUS = 4


class PerCoreStateTest(unittest.TestCase):
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.serial = run_variant_and_capture(
            "test_percpu",
            marker="Per-core state test complete",
            timeout=15.0,
        )

    def test_each_core_announced(self) -> None:
        # Each AP prints `[SMP] core N online` from its entry path
        # before joining the event loop. Core 0 (BSP) doesn't print
        # this line, so we check 1..EXPECTED_CPUS.
        for core in range(1, EXPECTED_CPUS):
            self.assertIn(
                f"[SMP] core {core} online",
                self.serial,
                f"core {core} didn't print its online message",
            )

    def test_each_core_percpu_state(self) -> None:
        # Core 0 runs the service callback inline; APs reach it through
        # the event loop. Every core should report OK for its own slot.
        for core in range(EXPECTED_CPUS):
            self.assertIn(
                f"Core {core}: inbox OK, tx_staging OK, id OK",
                self.serial,
                f"core {core} per-core state not verified",
            )

    def test_tx_staging_cross_core(self) -> None:
        self.assertIn("Core 0: verified TX staging from all APs", self.serial)


if __name__ == "__main__":
    unittest.main(verbosity=2)
