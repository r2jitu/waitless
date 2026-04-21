#!/usr/bin/env python3
"""apps/test_smp/test.py — SMP boot + IPI delivery integration test.

Boots test_smp.elf with 4 vCPUs under QEMU, waits for the app's
"SMP test complete" marker, then asserts against the serial log:
  * All 4 cores come online.
  * Each AP logs its own online message.
  * The app reached main and shut down.
  * The IPI round-trip from core 0 to core 1 succeeded.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from scripts.test_helpers import (
    runfiles_root,
    spawn_qemu,
    wait_for_marker,
)


EXPECTED_CPUS = 4


class SmpBootTest(unittest.TestCase):
    launcher = None
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        # Each per-variant py_test passes `env = {"LAUNCHER_NAME": "test_smp_qemu_<arch>"}`.
        # The variant rule symlinks the transitioned .elf as
        # `<LAUNCHER_NAME>.elf` alongside the launcher.
        launcher_name = os.environ["LAUNCHER_NAME"]
        elf = runfiles_root() / "apps" / "test_smp" / f"{launcher_name}.elf"
        if not elf.is_file():
            raise unittest.SkipTest(f"{launcher_name}.elf not found at {elf}")
        cls.launcher = spawn_qemu(
            elf, cpus=EXPECTED_CPUS, memory_mb=128,
            log_prefix="test_smp",
        )
        if cls.launcher is None:
            raise unittest.SkipTest("no qemu-system-* on PATH for this ELF")

        # The app prints the completion marker then self-shuts-down.
        # 15 s is generous for TCG on a slow host.
        if not wait_for_marker(cls.launcher, "SMP test complete", timeout=15.0):
            cls.launcher.cleanup()
            raise RuntimeError("guest never printed 'SMP test complete'")
        cls.launcher.terminate()
        cls.serial = cls.launcher.log_path.read_text(errors="replace")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.launcher is not None:
            cls.launcher.cleanup()

    def test_all_cores_online(self) -> None:
        self.assertIn(f"{EXPECTED_CPUS}/{EXPECTED_CPUS} cores online", self.serial)

    def test_each_core_reported(self) -> None:
        # Core 0 is implicit; APs print "[SMP] core N online".
        for core in range(1, EXPECTED_CPUS):
            self.assertIn(f"[SMP] core {core} online", self.serial,
                          f"core {core} didn't print its online message")

    def test_app_reached_main(self) -> None:
        self.assertIn("SMP test: cores booted.", self.serial)
        self.assertIn("SMP test complete.", self.serial)

    def test_ipi_round_trip(self) -> None:
        """Core 0 → core 1 SGI 0 delivery.

        Regression guard: `sgi_handler` must increment IPI_COUNT (the
        production path uses the SGI purely as a WFI wakeup, but the
        test asserts on the counter — see kernel/aarch64/smp.rs).
        """
        self.assertIn("IPI test: PASS", self.serial,
                      "IPI was not received — sgi_handler / ICC_SGI1_EL1 path broken")


if __name__ == "__main__":
    unittest.main(verbosity=2)
