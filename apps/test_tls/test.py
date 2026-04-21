#!/usr/bin/env python3
"""apps/test_tls/test.py — TLS primitives smoke test.

Drives //net:tls_crypto + //net:tls through a full-stack boot
(AEAD roundtrip + tamper, X25519, HKDF-Expand-Label, key schedule
cascade, traffic-key record roundtrip) inside a real unikernel boot
rather than a host unit test. Passes if the serial log contains
`TLS TESTS: ALL PASSED` and no `[tls] FAIL`.

Dispatches on `LAUNCHER_NAME` (set by the per-variant py_test's
`env` attr): `test_tls_hvf` → run-hvf on the co-located .img;
`test_tls_qemu_<arch>` → spawn_qemu on the co-located .elf.
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
        launcher_name = os.environ["LAUNCHER_NAME"]
        pkg = root / "apps" / "test_tls"

        if launcher_name == "test_tls_hvf":
            hvf = pkg / f"{launcher_name}.runner"
            img = pkg / f"{launcher_name}.img"
            if not (hvf.is_file() and os.access(hvf, os.X_OK)):
                raise unittest.SkipTest(f"HVF runner not executable: {hvf}")
            if not img.is_file():
                raise RuntimeError(f"{launcher_name}.img not found at {img}")
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
        else:
            elf = pkg / f"{launcher_name}.elf"
            img = pkg / f"{launcher_name}.img"
            if not elf.is_file():
                raise RuntimeError(f"{launcher_name}.elf not found at {elf}")
            cls.launcher = spawn_qemu(elf, img_path=img, cpus=1, memory_mb=128,
                                      log_prefix=launcher_name)
            if cls.launcher is None:
                raise unittest.SkipTest("no qemu-system-* on PATH for this ELF")

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
