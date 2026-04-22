#!/usr/bin/env python3
"""apps/test_tls/test.py — TLS primitives smoke test.

Drives //net:tls_crypto + //net:tls through a full-stack boot
(AEAD roundtrip + tamper, X25519, HKDF-Expand-Label, key schedule
cascade, traffic-key record roundtrip). Passes if the log contains
`TLS TESTS: ALL PASSED` and no `[tls] FAIL`.

The per-variant launcher owns the runner-specific invocation
(HVF / QEMU / native); this test just spawns it as a subprocess
and scrapes stdout.
"""

from __future__ import annotations

import os
import time
import unittest

from scripts.test_helpers import (
    runfiles_root,
    spawn_backgrounded,
    wait_for_marker,
)


class TlsPrimitiveTest(unittest.TestCase):
    launcher = None
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        launcher_name = os.environ["LAUNCHER_NAME"]
        launcher_path = runfiles_root() / "apps" / "test_tls" / launcher_name
        if not (launcher_path.is_file() and os.access(launcher_path, os.X_OK)):
            raise unittest.SkipTest(f"launcher not executable: {launcher_path}")
        cls.launcher = spawn_backgrounded(launcher_path, log_prefix=launcher_name)

        # Wait for the TLS test summary line. 20 s covers TCG under
        # heavy crypto.
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
