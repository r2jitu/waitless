#!/bin/bash
# ld.lld shim — finds lld from the Rust toolchain or system.
#
# rustc for bare-metal targets passes "-flavor gnu" as the first args.
# Rust's gcc-ld/ld.lld already has GNU flavor baked in, so strip those.

# Strip "-flavor gnu" if present (gcc-ld/ld.lld doesn't need them)
[ "$1" = "-flavor" ] && shift 2

for p in \
    /var/tmp/_bazel_*/*/external/rules_rust*stable_tools/lib/rustlib/*/bin/gcc-ld/ld.lld \
    /opt/homebrew/bin/ld.lld \
    /usr/bin/ld.lld; do
    [ -x "$p" ] && exec "$p" "$@"
done
echo "error: ld.lld not found" >&2; exit 1
