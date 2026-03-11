# bench/Dockerfile — builds webserver_native for Linux (same app code, POSIX TCP)
#
# Compiles the same HTTP server application that runs as a unikernel, using
# standard Linux clang with POSIX sockets.  Allows comparing unikernel
# overhead vs Linux kernel + VZ.framework overhead with identical app logic.
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t webserver_linux .
#   docker run --rm -p 18080:80 webserver_linux

FROM debian:bookworm-slim AS build
WORKDIR /build
COPY apps/webserver/main.cc .
COPY net/ net/
COPY uni/ uni/
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
    && rm -rf /var/lib/apt/lists/* \
    && g++ -std=c++17 -O2 -I. \
        main.cc net/http.cc uni/native.cc uni/native_main.cc \
        -o /webserver

FROM debian:bookworm-slim
COPY --from=build /webserver /webserver
EXPOSE 80
CMD ["/webserver"]
