#!/bin/bash
# Linker dispatch for Rust cross-compilation.
#
# rustc invokes this as the linker. We detect the target and dispatch:
#   - "-flavor gnu": bare-metal (*-unknown-none) → lld, pass all args raw
#   - "-Wl,--as-needed": Linux ELF (*-linux-*) → lld, strip clang-driver flags
#   - Otherwise: macOS native (*-apple-*) → clang
#
# lld is found portably: PATH first (works in Bazel sandbox where
# rules_rust adds the Rust toolchain bin dir), then Homebrew, then system.

find_lld() {
    # Check PATH first (Bazel sandbox may have Rust toolchain on PATH)
    command -v ld.lld 2>/dev/null && return
    # Rust toolchain's gcc-ld/ld.lld (search common Bazel cache locations)
    for base in /var/tmp/_bazel_*/*/external/rules_rust*stable_tools/lib/rustlib/*/bin/gcc-ld; do
        [ -x "$base/ld.lld" ] && echo "$base/ld.lld" && return
    done
    # Homebrew / system fallback
    for p in /opt/homebrew/bin/ld.lld /opt/homebrew/opt/llvm/bin/ld.lld \
             /usr/bin/ld.lld; do
        [ -x "$p" ] && echo "$p" && return
    done
    echo "error: no ld.lld found" >&2; exit 1
}

find_clang() {
    command -v clang 2>/dev/null && return
    for p in /opt/homebrew/opt/llvm/bin/clang /usr/bin/clang; do
        [ -x "$p" ] && echo "$p" && return
    done
    echo "error: clang not found" >&2; exit 1
}

# Bare-metal: rustc passes raw LLD flags (first arg is -flavor gnu)
if [ "$1" = "-flavor" ]; then
    LLD="$(find_lld)"
    # gcc-ld/ld.lld already has GNU flavor baked in — strip "-flavor gnu"
    if [[ "$LLD" == *gcc-ld* ]]; then
        shift 2  # remove "-flavor" "gnu"
    fi
    exec "$LLD" "$@"
fi

# Linux cross-compile: rustc passes clang-driver style flags
for arg in "$@"; do
    case "$arg" in
        -Wl,--as-needed)
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
export PATH="/usr/bin:/bin:$PATH"
exec "$(find_clang)" "$@"
