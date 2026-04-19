#!/usr/bin/env python3
"""Thin launcher so `python3 scripts/bench.py ...` still works after
the split into a package. All real code lives in `scripts/bench/`
(imported as `bench.*` since Python adds this file's directory —
`scripts/` — to sys.path automatically).

The `if __name__ == "__main__"` guard is load-bearing on macOS +
Python 3.8+: the default `multiprocessing` start method there is
`spawn` (not `fork`), and `spawn` reimports the entry module in
every child process. Without the guard, each spawned worker would
re-run `main()` and attempt to start its own multiprocessing Pool,
producing the "An attempt has been made to start a new process
before the current process has finished its bootstrapping phase"
error and (worse) cascading runaway process trees when a parent
crashed mid-bench.
"""

from bench.cli import main

if __name__ == "__main__":
    main()
