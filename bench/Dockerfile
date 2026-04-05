# bench/Dockerfile — builds webserver_native for Linux
#
# Compiles the full crate graph with rustc, including the proc macro.
# Copies entire directories so file renames don't break the build.
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t webserver_linux .
#   docker run --rm -p 18080:80 webserver_linux

FROM rust:bookworm AS build
WORKDIR /build
COPY uni/ uni/
COPY apps/webserver/ apps/webserver/
COPY bazel/rules/native_main.rs bazel/rules/

RUN mkdir -p out \
    && rustc --edition 2024 \
         --crate-type proc-macro --crate-name uni_macros \
         uni/macros/lib.rs -o out/libuni_macros.so \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --cfg platform_native \
         --crate-type rlib --crate-name uni \
         --extern uni_macros=out/libuni_macros.so \
         uni/lib.rs -o out/libuni.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type rlib --crate-name app \
         -L dependency=out \
         --extern uni=out/libuni.rlib \
         apps/webserver/main.rs -o out/libapp.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type staticlib \
         -L dependency=out \
         --extern app=out/libapp.rlib \
         --extern uni=out/libuni.rlib \
         bazel/rules/native_main.rs -o out/libwebserver.a \
    && cc out/libwebserver.a -o /webserver -lpthread -ldl -lm

FROM debian:bookworm-slim
COPY --from=build /webserver /webserver
EXPOSE 80
CMD ["/webserver"]
