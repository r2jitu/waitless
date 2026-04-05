# bench/Dockerfile — builds webserver_native for Linux
#
# Uses bench/build_native.sh which mirrors the Bazel crate graph.
# The script compiles: uni_macros → uni → app → native_main.
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t webserver_linux .
#   docker run --rm -p 18080:80 webserver_linux

FROM rust:bookworm AS build
WORKDIR /build
COPY . .
RUN bench/build_native.sh

FROM debian:bookworm-slim
COPY --from=build /build/out/webserver /webserver
EXPOSE 80
CMD ["/webserver"]
