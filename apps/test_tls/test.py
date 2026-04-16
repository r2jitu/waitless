#!/usr/bin/env python3
"""apps/test_tls/test.py — TLS primitives smoke test.

Drives //net:tls_crypto + //net:tls through a full-stack boot
(AEAD roundtrip + tamper, X25519, HKDF-Expand-Label, key schedule
cascade, traffic-key record roundtrip) inside a real unikernel boot
rather than a host unit test. Passes if the serial log contains
`TLS TESTS: ALL PASSED` and no `[tls] FAIL`.

Picks the runner from what's actually in runfiles (run-hvf or
<name>.elf) rather than host arch — so `--config=aarch64-qemu` runs
under QEMU on a macOS arm64 host instead of defaulting to HVF.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from scripts.test_helpers import (
    Launcher,
    runfiles_root,
    spawn_qemu,
    wait_for_marker,
)


class TlsPrimitiveTest(unittest.TestCase):
    launcher: Launcher | None = None
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        root = runfiles_root()
        hvf = root / "tools" / "hvf-runner" / "run-hvf"
        elf = root / "apps" / "test_tls" / "test_tls.elf"
        img = root / "apps" / "test_tls" / "test_tls.img"

        if hvf.is_file() and os.access(hvf, os.X_OK):
            if not img.is_file():
                raise RuntimeError(f"test_tls.img not found at {img}")
            fd, log_path_str = tempfile.mkstemp(
                prefix="test_tls_hvf_", suffix=".log",
            )
            os.close(fd)
            log_path = Path(log_path_str)
            with open(log_path, "wb") as log_fd:
                proc = subprocess.Popen(
                    [str(hvf), str(img), "--ram=128", "--cpus=1"],
                    stdout=log_fd, stderr=log_fd, stdin=subprocess.DEVNULL,
                )
            cls.launcher = Launcher(proc=proc, log_path=log_path)
        elif elf.is_file():
            cls.launcher = spawn_qemu(elf, cpus=1, memory_mb=128,
                                      log_prefix="test_tls_qemu")
            if cls.launcher is None:
                raise unittest.SkipTest("no qemu-system-* on PATH for this ELF")
        else:
            raise unittest.SkipTest("no runner available (no run-hvf / .elf)")

        # Wait for the TLS test summary line. 20 s covers TCG under
        # heavy crypto.
        assert cls.launcher is not None
        if not wait_for_marker(cls.launcher, "TLS TESTS:", timeout=20.0):
            cls.launcher.cleanup()
            raise RuntimeError("guest never printed 'TLS TESTS:' line")
        # Let the VM drain and shut down cleanly.
        time.sleep(0.5)
        cls.launcher.terminate()
        cls.serial = cls.launcher.log_path.read_text(errors="replace")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.launcher is not None:
            cls.launcher.cleanup()

    def test_all_primitives_passed(self) -> None:
        self.assertIn("TLS TESTS: ALL PASSED", self.serial,
                      "TLS primitives smoke test did not report ALL PASSED")

    def test_no_subtest_failures(self) -> None:
        self.assertNotIn("[tls] FAIL", self.serial,
                         "one or more TLS subtests reported FAIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
