#!/usr/bin/env python3
"""Thin launcher so `python3 scripts/bench.py ...` still works after
the split into a package. All real code lives in `scripts/bench/`
(imported as `bench.*` since Python adds this file's directory —
`scripts/` — to sys.path automatically).
"""

from bench.cli import main

main()
