#!/usr/bin/env python3
"""apps/test_tls/test.py — TLS primitives smoke test.

Drives //net:tls_crypto + //net:tls through a full-stack boot
(AEAD roundtrip + tamper, X25519, HKDF-Expand-Label, key schedule
cascade, traffic-key record roundtrip). Passes if the log contains
`TLS TESTS: ALL PASSED` and no `[tls] FAIL`.

The per-variant launcher owns the runner-specific invocation
(HVF / QEMU / native); this test just spawns it via
`run_variant_and_capture` and scrapes the serial log.
"""

from __future__ import annotations

import unittest

from scripts.test_helpers import run_variant_and_capture


class TlsPrimitiveTest(unittest.TestCase):
    serial: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        # 20 s covers TCG under heavy crypto; native is ~1 s.
        cls.serial = run_variant_and_capture(
            "test_tls",
            marker="TLS TESTS:",
            timeout=20.0,
        )

    def test_all_primitives_passed(self) -> None:
        self.assertIn(
            "TLS TESTS: ALL PASSED",
            self.serial,
            "TLS primitives smoke test did not report ALL PASSED",
        )

    def test_no_subtest_failures(self) -> None:
        self.assertNotIn(
            "[tls] FAIL", self.serial, "one or more TLS subtests reported FAIL"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
