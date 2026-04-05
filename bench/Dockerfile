# bench/Dockerfile — builds webserver_native for Linux (same app code, POSIX TCP)
#
# Compiles the same HTTP server application that runs as a unikernel, using
# Rust with POSIX sockets.  Allows comparing unikernel overhead vs Linux
# kernel + VZ.framework overhead with identical app logic.
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t webserver_linux .
#   docker run --rm -p 18080:80 webserver_linux

FROM rust:bookworm AS build
WORKDIR /build
COPY uni/native.rs uni/
COPY uni/api.rs uni/
COPY net/http.rs net/
COPY apps/webserver/main.rs apps/webserver/
RUN mkdir -p out \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type rlib --crate-name uni_native \
         uni/native.rs -o out/libuni_native.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --cfg platform_native \
         --crate-type rlib --crate-name uni \
         uni/api.rs --extern uni_native=out/libuni_native.rlib \
         -o out/libuni.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type rlib --crate-name http \
         net/http.rs --extern uni=out/libuni.rlib \
         -o out/libhttp.rlib \
    && rustc --edition 2024 -C opt-level=2 -C panic=abort \
         --crate-type staticlib \
         apps/webserver/main.rs \
         --extern http=out/libhttp.rlib --extern uni=out/libuni.rlib \
         -o out/libwebserver.a \
    && cc out/libwebserver.a -o /webserver -lpthread -ldl -lm

FROM debian:bookworm-slim
COPY --from=build /webserver /webserver
EXPOSE 80
CMD ["/webserver"]
