#!/bin/bash
# ld.lld shim — finds lld from the Rust toolchain sysroot.
#
# rustc passes -L <sysroot>/lib/rustlib/<target>/lib to the linker.
# We extract the sysroot from these paths and find gcc-ld/ld.lld there.

# Strip "-flavor gnu" if present (gcc-ld/ld.lld has GNU flavor baked in)
[ "$1" = "-flavor" ] && shift 2

# Find ld.lld by extracting the Rust sysroot from -L args
for arg in "$@"; do
    case "$arg" in
        */lib/rustlib/*/lib)
            # Derive: .../lib/rustlib/<target>/lib → .../lib/rustlib/<host>/bin/gcc-ld/ld.lld
            sysroot="${arg%/lib/rustlib/*/lib}"
            for lld in "$sysroot"/lib/rustlib/*/bin/gcc-ld/ld.lld; do
                [ -x "$lld" ] && exec "$lld" "$@"
            done
            ;;
    esac
done

# Fallback to system lld
for p in /opt/homebrew/bin/ld.lld /usr/bin/ld.lld; do
    [ -x "$p" ] && exec "$p" "$@"
done
echo "error: ld.lld not found" >&2; exit 1
