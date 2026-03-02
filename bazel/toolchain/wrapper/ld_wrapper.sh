#!/bin/bash
# Use Homebrew lld for bare-metal ELF linking.
LLD="/opt/homebrew/bin/ld.lld"
if [ ! -x "$LLD" ]; then
  echo "error: ld.lld not found at $LLD" >&2
  echo "       Install with: brew install lld" >&2
  exit 1
fi
exec "$LLD" "$@"
