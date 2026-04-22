#!/usr/bin/env python3
"""apps/test_percpu/test.py — Per-core state independence integration test.

Boots the test_percpu launcher (per-variant QEMU / HVF invocation,
4 vCPUs by default from the unikernel_binary attr), waits for the
app's completion marker, then asserts that every core saw its own
slot of TEST_DATA, tx_staging round-tripped through each AP, etc.
"""

from __future__ import annotations

import os
import unittest

from scripts.test_helpers import (
    runfiles_root,
    spawn_backgrounded,
    wait_for_marker,
)


EXPECTED_CPUS = 4


class PerCoreStateTest(unittest.TestCase):
    launcher = None
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        launcher_name = os.environ["LAUNCHER_NAME"]
        launcher_path = runfiles_root() / "apps" / "test_percpu" / launcher_name
        if not (launcher_path.is_file() and os.access(launcher_path, os.X_OK)):
            raise unittest.SkipTest(f"launcher not executable: {launcher_path}")
        cls.launcher = spawn_backgrounded(launcher_path, log_prefix=launcher_name)

        if not wait_for_marker(cls.launcher, "Per-core state test complete",
                               timeout=15.0):
            cls.launcher.cleanup()
            raise RuntimeError("guest never finished the per-core test")
        cls.launcher.terminate()
        cls.serial = cls.launcher.log_path.read_text(errors="replace")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.launcher is not None:
            cls.launcher.cleanup()

    def test_all_cores_online(self) -> None:
        self.assertIn(f"{EXPECTED_CPUS}/{EXPECTED_CPUS} cores online", self.serial)

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
