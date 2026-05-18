#!/bin/bash
# clang — system C compiler for native builds.
# macOS: Xcode CommandLineTools clang. Linux: system cc/gcc/clang.

case "$(/usr/bin/uname -s)" in
Darwin) exec /usr/bin/clang "$@" ;;
*)
    for cc in /usr/bin/cc /usr/bin/gcc /usr/bin/clang; do
        [ -x "$cc" ] && exec "$cc" "$@"
    done
    ;;
esac
echo "error: no C compiler found" >&2
exit 1
