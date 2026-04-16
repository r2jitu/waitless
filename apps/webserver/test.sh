#!/usr/bin/env bash
# Thin wrapper: the real test is apps/webserver/test.py (unittest-based,
# stdlib only). Kept as sh_test because rules_python isn't wired into
# this project — see MODULE.bazel. Switching to a proper py_test is a
# ~10-line MODULE.bazel change away if we ever add more Python tests.
set -euo pipefail
RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
exec python3 "${RUNFILES}/_main/apps/webserver/test.py"
