#!/bin/bash
# clang wrapper for macOS native builds (aarch64-macos platform only).
# Finds Homebrew clang or system clang.
for CLANG in /opt/homebrew/opt/llvm/bin/clang /usr/bin/clang; do
    if [ -x "$CLANG" ]; then
        export PATH="/usr/bin:/bin:$PATH"
        exec "$CLANG" "$@"
    fi
done
echo "error: clang not found" >&2; exit 1
