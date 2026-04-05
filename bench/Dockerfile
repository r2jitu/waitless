# bench/Dockerfile — builds webserver_native for Linux
#
# Compiles the same HTTP server that runs as a unikernel, using Rust
# with POSIX sockets. Compares unikernel vs Linux kernel overhead.
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t webserver_linux .
#   docker run --rm -p 18080:80 webserver_linux

FROM rust:bookworm AS build
WORKDIR /build

# Copy entire source directories — avoids breaking on file renames/moves.
COPY uni/ uni/
COPY apps/webserver/ apps/webserver/
COPY bazel/rules/native_main.rs bazel/rules/

RUN mkdir -p out \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --cfg platform_native \
         --crate-type rlib --crate-name uni \
         uni/lib.rs \
         -o out/libuni.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type rlib --crate-name app \
         -L dependency=out \
         apps/webserver/main.rs \
         --extern uni=out/libuni.rlib \
         -o out/libapp.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type staticlib \
         -L dependency=out \
         bazel/rules/native_main.rs \
         --extern app=out/libapp.rlib \
         --extern uni=out/libuni.rlib \
         -o out/libwebserver.a \
    && cc out/libwebserver.a -o /webserver -lpthread -ldl -lm

FROM debian:bookworm-slim
COPY --from=build /webserver /webserver
EXPOSE 80
CMD ["/webserver"]
