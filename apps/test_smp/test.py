#!/usr/bin/env python3
"""apps/test_smp/test.py — SMP boot + IPI delivery integration test.

Boots the test_smp app with 4 vCPUs, waits for the app's "SMP test
complete" marker, then asserts against the serial log:
  * All 4 cores come online.
  * Each AP logs its own online message.
  * The app reached main and shut down.
  * The IPI round-trip from core 0 to core 1 succeeded.

Dispatches on `LAUNCHER_NAME`:
  * `test_smp_hvf`         → run-hvf on the .img (aarch64 real hw).
  * `test_smp_qemu_<arch>` → spawn_qemu on the .elf (TCG emulation).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.test_helpers import (
    Launcher,
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
        # Each per-variant py_test passes `env = {"LAUNCHER_NAME": ...}`.
        # The variant rule symlinks the transitioned .elf + .img as
        # `<LAUNCHER_NAME>.{elf,img}` alongside the launcher; the HVF
        # runner binary lives at its natural `tools/hvf-runner/run-hvf`
        # runfiles path.
        launcher_name = os.environ["LAUNCHER_NAME"]
        root = runfiles_root()
        pkg = root / "apps" / "test_smp"
        img = pkg / f"{launcher_name}.img"
        if not img.is_file():
            raise unittest.SkipTest(f"{launcher_name}.img not found at {img}")

        if launcher_name == "test_smp_hvf":
            hvf = root / "tools" / "hvf-runner" / "run-hvf"
            if not (hvf.is_file() and os.access(hvf, os.X_OK)):
                raise unittest.SkipTest(f"HVF runner not executable: {hvf}")
            fd, log_path_str = tempfile.mkstemp(prefix="test_smp_hvf_", suffix=".log")
            os.close(fd)
            log_path = Path(log_path_str)
            with open(log_path, "wb") as log_fd:
                proc = subprocess.Popen(
                    [str(hvf), str(img),
                     f"--ram=128", f"--cpus={EXPECTED_CPUS}"],
                    stdout=log_fd, stderr=log_fd, stdin=subprocess.DEVNULL,
                )
            cls.launcher = Launcher(proc=proc, log_path=log_path)
        else:
            elf = pkg / f"{launcher_name}.elf"
            if not elf.is_file():
                raise unittest.SkipTest(f"{launcher_name}.elf not found at {elf}")
            cls.launcher = spawn_qemu(
                elf, img_path=img, cpus=EXPECTED_CPUS, memory_mb=128,
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
