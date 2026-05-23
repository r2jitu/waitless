# Multi-stage build: compile against the rust:slim toolchain image,
# ship the resulting binary on debian:bookworm-slim. Final image is
# ~80 MB instead of ~800 MB.

FROM rust:slim-bookworm AS build

WORKDIR /src

# Single-shot build. Docker's layer cache covers "no source changed,
# don't rebuild." The stub-main dep-cache trick is fragile (stale
# `deps/` object files leak past `rm` globs and produce empty
# binaries) and saves at most a minute on subsequent builds.
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/tokio-hyper-peer /usr/local/bin/

# TLS certs are bind-mounted at run time so the same ECDSA P-256 dev
# cert is used by both peers and waitless. Mount path matches the
# binary's --cert / --key defaults.
RUN mkdir -p /etc/tokio-hyper/tls

EXPOSE 80 443 8080

ENTRYPOINT ["/usr/local/bin/tokio-hyper-peer"]
