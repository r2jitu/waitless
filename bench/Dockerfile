# bench/Dockerfile — builds bench_server for the Linux benchmark scenario
#
# Multi-stage: compile in a builder then copy the static binary into a
# minimal Alpine image so the final container is tiny (~10 MB).
#
# Usage (from project root):
#   docker build -f bench/Dockerfile -t bench_server .
#   docker run --rm -p 18080:80 bench_server

FROM alpine:3.19 AS build
WORKDIR /src
COPY bench/bench_server.c .
RUN apk add --no-cache gcc musl-dev && \
    gcc -O2 -static -DRUNTIME='"linux"' -o /bench_server bench_server.c

FROM alpine:3.19
COPY --from=build /bench_server /bench_server
EXPOSE 80
ENTRYPOINT ["/bench_server"]
CMD ["80"]
