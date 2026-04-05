#!/bin/bash
# ld.lld — uses the Rust toolchain's linker.
#
# The Rust toolchain bin dir is on PATH in the Bazel sandbox.
# gcc-ld/ld.lld is adjacent to that directory with GNU ELF flavor.

[ "$1" = "-flavor" ] && shift 2

# PATH contains the Rust toolchain bin dir. Find gcc-ld/ld.lld there.
IFS=: read -ra DIRS <<< "$PATH"
for dir in "${DIRS[@]}"; do
    [ -x "$dir/gcc-ld/ld.lld" ] && exec "$dir/gcc-ld/ld.lld" "$@"
done

echo "error: ld.lld not found on PATH" >&2; exit 1
