# loadgen

Async TCP/TLS load generator that drives the unikernel benchmark
suite. Replaces the Python `multiprocessing` paths for two
workloads in `bench.py`:

* `tls_handshake_max` — full TLS 1.3 handshake rate (open TCP →
  handshake → GET → response → close, repeat).
* `tcp_echo_max` — TCP ping-pong throughput on a fixed pool of
  connections.

The Python implementations were client-bound on every host we ran
them on — `tls_handshake_max` ceilinged near 7 k hs/s and
`tcp_echo_max` near 220 k msg/s regardless of which side of the
client/server divide changed. Replacing the client unblocks the
real ceiling of the unikernel.

## Stack

* `tokio` — multi-thread async runtime.
* `rustls` + `tokio-rustls` (with the `ring` crypto provider) —
  pure-Rust TLS 1.3 client. Bypasses cert verification (the
  unikernel ships a self-signed dev cert; this measures throughput
  not chain validation).
* `hdrhistogram` — high-resolution percentile sketches.
* `clap` — arg parsing.

## Building

```
cd scripts/bench/loadgen
cargo build --release
```

Output: `target/release/loadgen`.

The binary is built on demand by `bench.py` on first invocation
(`scripts/bench/workloads.py::_loadgen_bin()`). Subsequent runs hit
the cargo cache and pay milliseconds. If `cargo` isn't on `PATH`,
the harness logs a one-time warning and falls back to the Python
implementations.

## Running on GCP

The GCP host doesn't ship Rust by default. Two ways to provide it:

1. **Install rustup on the GCP host** (recommended for iterative dev):
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
   First `gcp-bench.sh` run after that will compile the binary on
   the host (~30 s); subsequent runs reuse it.

2. **Cross-compile from the dev box** (requires `rustup target add
   x86_64-unknown-linux-gnu` and a Linux cross-linker like
   `x86_64-linux-gnu-gcc` from `homebrew/cask`):
   ```
   cd scripts/bench/loadgen
   cargo build --release --target x86_64-unknown-linux-gnu
   ```
   `gcp-bench.sh` would then need to ship the pre-built binary
   instead of the sources. Not wired today.

If neither is set up, `bench.py` falls back to the Python loadgen
with a warning. Numbers will reflect Python's client overhead, not
the server ceiling — see the `cli=N.Ncpu` column in the bench
output for visibility.

## Output format

Stdout is parsed line-by-line by `bench.py::_parse_loadgen_output`:

```
RPS 6803.412
P50_US 1539
P99_US 3839
```

Anything else on stdout is informational. Stderr is for logs.

## Keep-alive HTTP across versions (`http`)

The `http` subcommand drives keep-alive GET throughput over any of
the three HTTP versions, so an A/B across them is apples-to-apples
(one runtime, one timing harness, one percentile sketch):

```
loadgen http --proto h1|h2|h3 --host H --port P [--endpoint /health] \
    --connections C --streams M --duration-secs D [--warmup-secs W] \
    [--plaintext]
```

* `--connections` (h2load `-c`) — parallel transport connections.
* `--streams` (h2load `-m`) — concurrent in-flight requests **per
  connection**; h2/h3 only (HTTP/1.1 has no multiplexing, so it's
  forced to 1 — sequential keep-alive).
* `--proto h1` is TLS by default; `--plaintext` drops to cleartext
  HTTP. `h2`/`h3` always run over TLS/QUIC (ALPN `h2` / `h3`).

`h2` uses the low-level hyperium `h2` crate; `h3` reuses the
quinn + `h3` stack (it subsumes the older `h3-health` workload,
which stays for back-compat).

## Future work

* Migrate the throughput workloads in `bench.py` from `wrk` to the
  `http --proto h1` subcommand so all HTTP workloads share one binary
  (smaller dep tree on bench hosts).
* Replace `udp_bench.c` with a `loadgen udp` subcommand for the
  same reason.
* Wire into Bazel via `rust_binary` once the cc_toolchain provides
  a working `ar` so `ring`'s build script can cross-compile under
  Bazel without falling over.
