#!/usr/bin/env python3
"""apps/test_smp/test.py — SMP boot + IPI delivery integration test.

Boots the test_smp launcher (which handles the per-variant QEMU /
HVF invocation, including the 4-vCPU default from the
unikernel_binary attr) via `run_variant_and_capture`, then asserts
against the captured serial log:
  * All 4 cores come online.
  * Each AP logs its own online message.
  * The app reached main and shut down.
  * The IPI round-trip from core 0 to core 1 succeeded.
"""

from __future__ import annotations

import os
import unittest

from scripts.test_helpers import run_variant_and_capture


EXPECTED_CPUS = 4


class SmpBootTest(unittest.TestCase):
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.serial = run_variant_and_capture(
            "test_smp", marker="SMP test complete", timeout=15.0,
        )

    def test_each_core_reported(self) -> None:
        # Core 0 is implicit; APs print "[SMP] core N online".
        for core in range(1, EXPECTED_CPUS):
            self.assertIn(f"[SMP] core {core} online", self.serial,
                          f"core {core} didn't print its online message")

    def test_app_reached_main(self) -> None:
        self.assertIn("SMP test: cores booted.", self.serial)
        self.assertIn("SMP test complete.", self.serial)

    def test_ipi_round_trip(self) -> None:
        """Core 0 → core 1 SGI 0 delivery (aarch64-only).

        Regression guard: `sgi_handler` must increment IPI_COUNT (the
        production path uses the SGI purely as a WFI wakeup, but the
        test asserts on the counter — see kernel/aarch64/smp.rs). The
        test_smp app emits the `IPI test:` marker only under
        `#[cfg(target_arch = "aarch64")]`; on x86_64 there's no
        equivalent IPI path plumbed yet, so this assertion is
        skipped.
        """
        if "aarch64" not in os.environ["LAUNCHER_NAME"]:
            self.skipTest("IPI test is aarch64-specific; x86_64 path not wired up")
        self.assertIn("IPI test: PASS", self.serial,
                      "IPI was not received — sgi_handler / ICC_SGI1_EL1 path broken")


if __name__ == "__main__":
    unittest.main(verbosity=2)
