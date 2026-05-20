# scripts/bench/Dockerfile — packages the Bazel-built Linux binary
#
# The binary is cross-compiled on the host via Bazel:
#   bazel build --config=x86_64-linux //apps/webserver:webserver_native
#
# Then packaged into a minimal Docker image (no Rust compiler needed):
#   cp -L bazel-bin/apps/webserver/webserver_native scripts/bench/
#   docker build -t webserver_linux scripts/bench/

FROM scratch
COPY webserver_native /webserver
EXPOSE 80
ENTRYPOINT ["/webserver"]
