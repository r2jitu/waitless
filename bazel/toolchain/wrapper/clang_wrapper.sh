#!/bin/bash
# Use Homebrew LLVM clang which supports cross-compilation targets.
# Apple's /usr/bin/clang does not support --target=x86_64-unknown-none-elf.
LLVM_CLANG="/opt/homebrew/opt/llvm/bin/clang"
if [ ! -x "$LLVM_CLANG" ]; then
  echo "error: Homebrew LLVM clang not found at $LLVM_CLANG" >&2
  echo "       Install with: brew install llvm" >&2
  exit 1
fi
# Ensure system tools (ld, dsymutil, etc.) are findable. Some callers
# (e.g. rules_rust) invoke the wrapper with a restricted PATH that does
# not include /usr/bin, causing clang to fail to spawn the linker.
export PATH="/usr/bin:/bin:$PATH"
exec "$LLVM_CLANG" "$@"
