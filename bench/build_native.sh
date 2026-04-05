#!/bin/sh
# bench/build_native.sh — compile the native webserver binary with rustc
#
# Mirrors the Bazel crate graph: uni_macros → uni → app → native_main.
# Run from the project root.
set -e
mkdir -p out

# 1. Proc macro (host tool)
rustc --edition 2024 \
    --crate-type proc-macro --crate-name uni_macros \
    uni/macros/lib.rs -o out/libuni_macros.so

# 2. uni crate (platform abstraction)
rustc --edition 2024 -C opt-level=2 -C panic=abort \
    --cfg platform_native \
    --crate-type rlib --crate-name uni \
    --extern uni_macros=out/libuni_macros.so \
    uni/lib.rs -o out/libuni.rlib

# 3. app crate (webserver)
rustc --edition 2024 -C opt-level=2 -C panic=abort \
    --crate-type rlib --crate-name app \
    -L dependency=out \
    --extern uni=out/libuni.rlib \
    apps/webserver/main.rs -o out/libapp.rlib

# 4. native binary
rustc --edition 2024 -C opt-level=2 -C panic=abort \
    --crate-type bin \
    -L dependency=out \
    --extern app=out/libapp.rlib \
    --extern uni=out/libuni.rlib \
    -C link-arg=-lc -C link-arg=-lpthread \
    bazel/rules/native_main.rs -o out/webserver
