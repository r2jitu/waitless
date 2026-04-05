#!/bin/bash
# Linker dispatch for cross-compilation from macOS.
#
# rustc invokes this as the linker. We detect the target format and
# dispatch to the right tool:
#   - "-flavor gnu": bare-metal ELF (rustc for *-unknown-none) → ld.lld
#   - "--eh-frame-hdr" or "-Bstatic": Linux ELF (rustc for *-linux-*) → ld.lld
#   - Otherwise: macOS native (rustc for *-apple-*) → Homebrew clang

find_lld() {
    for p in /opt/homebrew/bin/ld.lld /opt/homebrew/opt/llvm/bin/ld.lld; do
        [ -x "$p" ] && echo "$p" && return
    done
    echo "error: ld.lld not found" >&2
    exit 1
}

# Check if this is an ELF link invocation (not macOS Mach-O).
# rustc passes ELF linker flags as -Wl,--flag or bare --flag.
for arg in "$@"; do
    case "$arg" in
        -flavor|-Wl,--eh-frame-hdr|-Wl,--as-needed|-Wl,-Bstatic)
            # Strip -Wl, prefixes and pass to lld directly
            args=()
            for a in "$@"; do
                args+=("${a#-Wl,}")
            done
            exec "$(find_lld)" "${args[@]}"
            ;;
    esac
done

# macOS native: use Homebrew LLVM clang
LLVM_CLANG="/opt/homebrew/opt/llvm/bin/clang"
if [ ! -x "$LLVM_CLANG" ]; then
    echo "error: Homebrew LLVM clang not found at $LLVM_CLANG" >&2
    echo "       Install with: brew install llvm" >&2
    exit 1
fi
export PATH="/usr/bin:/bin:$PATH"
exec "$LLVM_CLANG" "$@"
