#!/bin/bash
# Homebrew LLVM clang for cross-compilation.
#
# When rustc uses this as the linker, it passes LLD-flavored arguments
# (e.g. -flavor gnu). Detect this and dispatch to ld.lld directly.

if [ "$1" = "-flavor" ]; then
    # rustc is invoking us as a linker — use ld.lld directly
    LLD="/opt/homebrew/bin/ld.lld"
    if [ ! -x "$LLD" ]; then
        LLD="/opt/homebrew/opt/llvm/bin/ld.lld"
    fi
    if [ ! -x "$LLD" ]; then
        echo "error: ld.lld not found" >&2
        exit 1
    fi
    exec "$LLD" "$@"
fi

# Normal clang invocation (compile or clang-driver link)
LLVM_CLANG="/opt/homebrew/opt/llvm/bin/clang"
if [ ! -x "$LLVM_CLANG" ]; then
    echo "error: Homebrew LLVM clang not found at $LLVM_CLANG" >&2
    echo "       Install with: brew install llvm" >&2
    exit 1
fi
export PATH="/usr/bin:/bin:$PATH"
exec "$LLVM_CLANG" "$@"
