#!/bin/bash
# Linker dispatch for cross-compilation from macOS.
#
# rustc invokes this as the linker. We detect the target:
#   - "-flavor gnu": bare-metal (*-unknown-none) → ld.lld, pass all args raw
#   - "-Wl,--as-needed": Linux ELF (*-linux-*) → ld.lld, strip clang-driver flags
#   - Otherwise: macOS native (*-apple-*) → Homebrew clang

find_lld() {
    for p in /opt/homebrew/bin/ld.lld /opt/homebrew/opt/llvm/bin/ld.lld \
             /usr/bin/ld.lld; do
        [ -x "$p" ] && echo "$p" && return
    done
    echo "error: ld.lld not found" >&2; exit 1
}

# Check first arg for bare-metal (raw LLD invocation from rustc)
if [ "$1" = "-flavor" ]; then
    exec "$(find_lld)" "$@"
fi

# Check for Linux ELF target (rustc passes clang-driver style flags)
for arg in "$@"; do
    case "$arg" in
        -Wl,--as-needed)
            # Linux cross-compile: strip -Wl, prefixes and clang-driver flags
            LLD="$(find_lld)"
            args=()
            for a in "$@"; do
                case "$a" in
                    -Wl,*)   args+=("${a#-Wl,}") ;;
                    -m64|-m32|-pie|-nostdlib|-nodefaultlibs|-nostartfiles) ;;
                    *)       args+=("$a") ;;
                esac
            done
            exec "$LLD" "${args[@]}"
            ;;
    esac
done

# macOS native
for CLANG in /opt/homebrew/opt/llvm/bin/clang /usr/bin/clang; do
    if [ -x "$CLANG" ]; then
        export PATH="/usr/bin:/bin:$PATH"
        exec "$CLANG" "$@"
    fi
done
echo "error: clang not found" >&2; exit 1
