#!/bin/bash
# Use Homebrew LLVM clang which supports cross-compilation targets.
# Apple's /usr/bin/clang does not support --target=x86_64-unknown-none-elf.
LLVM_CLANG="/opt/homebrew/opt/llvm/bin/clang"
if [ ! -x "$LLVM_CLANG" ]; then
  echo "error: Homebrew LLVM clang not found at $LLVM_CLANG" >&2
  echo "       Install with: brew install llvm" >&2
  exit 1
fi
exec "$LLVM_CLANG" "$@"
