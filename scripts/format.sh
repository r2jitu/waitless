#!/usr/bin/env bash
# format.sh -- apply every code formatter used in this repo.
#
# Usage:
#   scripts/format.sh                  format every tracked file
#   scripts/format.sh FILE [FILE...]   format only the given files
#   scripts/format.sh --check [FILE…]  report violations only; exit 1 if any
#
# Dispatch is by extension:
#   *.rs                          rustfmt       (reads ./rustfmt.toml)
#   *.bazel *.bzl BUILD WORKSPACE  buildifier
#   *.c *.cc *.cpp *.h *.hpp       clang-format  (reads ./.clang-format)
#   *.py                          ruff format
#   *.sh                          shfmt -i 4
# Files of any other type are ignored.
#
# scripts/git-hooks/pre-commit calls this with the list of staged files.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

check=0
if [ "${1:-}" = "--check" ]; then
    check=1
    shift
fi

# Target files: explicit arguments, otherwise every tracked file.
files=()
if [ "$#" -gt 0 ]; then
    files=("$@")
else
    while IFS= read -r f; do
        files+=("$f")
    done < <(git ls-files)
fi

# Bucket the files by language.
rs=()
bzl=()
cc=()
py=()
sh=()
for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    case "$f" in
    *.rs) rs+=("$f") ;;
    *.c | *.cc | *.cpp | *.h | *.hpp) cc+=("$f") ;;
    *.py) py+=("$f") ;;
    *.sh) sh+=("$f") ;;
    *.bazel | *.bzl | BUILD | WORKSPACE | */BUILD | */WORKSPACE) bzl+=("$f") ;;
    esac
done

if [ "$check" -eq 1 ]; then
    rc=0
    [ ${#rs[@]} -gt 0 ] && { echo "rustfmt --check (${#rs[@]})" && rustfmt --check "${rs[@]}" || rc=1; }
    [ ${#bzl[@]} -gt 0 ] && { echo "buildifier check (${#bzl[@]})" && buildifier -mode=check "${bzl[@]}" || rc=1; }
    [ ${#cc[@]} -gt 0 ] && { echo "clang-format check (${#cc[@]})" && clang-format --dry-run --Werror "${cc[@]}" || rc=1; }
    [ ${#py[@]} -gt 0 ] && { echo "ruff format --check (${#py[@]})" && ruff format --check "${py[@]}" || rc=1; }
    [ ${#sh[@]} -gt 0 ] && { echo "shfmt -d (${#sh[@]})" && shfmt -i 4 -d "${sh[@]}" || rc=1; }
    exit $rc
fi

[ ${#rs[@]} -gt 0 ] && { echo "rustfmt: ${#rs[@]} file(s)" && rustfmt "${rs[@]}"; }
[ ${#bzl[@]} -gt 0 ] && { echo "buildifier: ${#bzl[@]} file(s)" && buildifier "${bzl[@]}"; }
[ ${#cc[@]} -gt 0 ] && { echo "clang-format: ${#cc[@]} file(s)" && clang-format -i "${cc[@]}"; }
[ ${#py[@]} -gt 0 ] && { echo "ruff format: ${#py[@]} file(s)" && ruff format "${py[@]}"; }
[ ${#sh[@]} -gt 0 ] && { echo "shfmt: ${#sh[@]} file(s)" && shfmt -i 4 -w "${sh[@]}"; }
echo "format.sh: done"
