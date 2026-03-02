#!/bin/bash
# Use Homebrew LLVM's llvm-ar for bare-metal archives.
LLVM_AR="/opt/homebrew/opt/llvm/bin/llvm-ar"
if [ ! -x "$LLVM_AR" ]; then
  echo "error: llvm-ar not found at $LLVM_AR" >&2
  echo "       Install with: brew install llvm" >&2
  exit 1
fi
exec "$LLVM_AR" "$@"
