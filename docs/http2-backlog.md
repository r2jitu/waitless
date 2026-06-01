# HTTP/2 — build plan + hardening backlog

Last updated 2026-05-31. **Status: not started.** HTTP/2 is not yet
implemented; this doc is the build companion (what to remix, what to
scope into the first session) and the tracker for the conformance /
interop / security tail that the build will generate.

For *why* H2 (the first-visit/TCP-path multiplexing win, the H3 fallback
that keeps multiplexing) and *how it relates to H1.1/H3* see the strategic
notes in [`roadmap.md`](roadmap.md). H2 does **not** supersede H1.1 — they
coexist, selected per-connection by ALPN.

## Crate structure (decided)

- New crate **`crates/proto/http2`**, mirroring `proto/http3`. Depends on
  `proto/http` (the transport-agnostic shared HTTP core — Request /
  Response / BodyReader / handler API) and is **generic over the byte
  stream**, so it needs *no* tls/tcp dep (exactly like `proto/http`'s
  `serve_conn`).
- **Do not merge** h1/h2/h3 into one `http` lib: it would have to depend
  on `proto/quic` (for h3) and all transports, so every consumer of plain
  H1.1 would transitively pull QUIC/UDP — undoing the transport
  separation. The shared semantics are already shared via `proto/http`
  *without* that coupling.
- Extract `proto/http3/src/huffman.rs` into a small shared leaf crate
  (e.g. `proto/field-huffman`); both `http2` (HPACK) and `http3` (QPACK)
  depend on it — the RFC 7541 Huffman table is identical. The static
  tables differ (HPACK 61 entries vs QPACK 99) and stay per-crate.
- `proto/tls` gains a dep on `proto/http2` and dispatches on the
  negotiated ALPN at `proto/tls/src/lib.rs` (the `http::serve_conn` call):
  `"h2"` → `http2::serve_conn`, else `http::serve_conn`.

## Reuse map (don't reinvent)

| Need | Reuse |
|---|---|
| HTTP semantics, handler API, body streaming | `proto/http` (h3 already rides it) |
| Huffman (HPACK == QPACK table) | `proto/http3/src/huffman.rs` → shared leaf |
| HPACK reference | `proto/http3/src/qpack.rs` — HPACK is the simpler cousin (same Huffman + integer/string primitives; a different static table; a dynamic table **without** QPACK's encoder/decoder-stream reordering dance) |
| ALPN negotiation | `proto/tls/src/handlers.rs` (~line 249) — already negotiates ALPN, selects `http/1.1` today; add `"h2"` and surface the choice to the serve dispatch |
| Per-conn async task + multiplexing pattern | the h3 server's stream-dispatch shape (`proto/http3/src/server.rs`) |

## Build scope — first session (happy path)

A working server-role H2 that real `curl --http2` and a browser use:

- **HPACK** encode/decode (reuse shared Huffman; static table; a basic
  dynamic table). The decoder is correctness-critical.
- **Frame codec**: SETTINGS, HEADERS, DATA, WINDOW_UPDATE, RST_STREAM,
  GOAWAY, PING (parse CONTINUATION).
- **Connection preface** + SETTINGS exchange.
- **Multiplexing serve loop over one stream**: per-stream state, **connection-
  and stream-level flow control** (this is the hard part QUIC gave H3 for
  free), interleaved responses, N concurrent streams mapped onto the
  executor.
- Wire each stream's request + body to the `proto/http` handler API
  (`BodyReader` over DATA frames + the stream's flow-control window).
- **ALPN dispatch** in `proto/tls`.

## Hardening backlog (the tail — track here as found)

### Security / DoS — required before any public deploy (P0)

HTTP/2's framing opens DoS vectors that H1.1 doesn't have; a public
server **must** bound them. None are noted elsewhere yet.

- **H2-1 — Rapid Reset (CVE-2023-44487).** A client opens streams and
  immediately RST_STREAMs them, forcing unbounded server work per RTT.
  Cap the rate of resets / concurrent-stream churn; count canceled
  streams against `SETTINGS_MAX_CONCURRENT_STREAMS`.
- **H2-2 — HPACK bomb / decompression ratio.** A small compressed header
  block can expand hugely. Bound decoded header-list size
  (`SETTINGS_MAX_HEADER_LIST_SIZE`) and total dynamic-table memory.
- **H2-3 — Frame floods.** SETTINGS flood, PING flood, empty-DATA flood,
  WINDOW_UPDATE flood, 0-length-HEADERS flood. Rate-limit / cap
  outstanding control frames; bound per-connection memory.
- **H2-4 — `MAX_CONCURRENT_STREAMS` enforcement.** Advertise and enforce
  a sane cap so one connection can't exhaust per-conn memory.

### Conformance / interop (P1–P2)

- **H2-5 — CONTINUATION handling.** Header blocks split across
  CONTINUATION frames; the "CONTINUATION flood" (CVE-2024-27316) is a
  related DoS — bound total header-block bytes before completion.
- **H2-6 — Full SETTINGS surface.** Honor peer `INITIAL_WINDOW_SIZE`,
  `MAX_FRAME_SIZE`, `HEADER_TABLE_SIZE`, `MAX_HEADER_LIST_SIZE`; apply
  `INITIAL_WINDOW_SIZE` retroactively to open streams (the tricky one).
- **H2-7 — HPACK dynamic-table eviction subtleties** — size accounting
  (entry overhead = 32 bytes/entry, RFC 7541 §4.1), eviction on resize.
- **H2-8 — Error handling completeness** — connection vs stream errors,
  the right `GOAWAY` / `RST_STREAM` error codes (RFC 7540 §7), `last-
  stream-id` on GOAWAY for clean drain.
- **H2-9 — h2spec.** Run the h2spec conformance suite; track failures here.

### Deferred by design / non-goals

- **PRIORITY frames / the priority tree** — deprecated (RFC 9218
  Extensible Priorities replaced it; most servers ignore the tree).
  Parse-and-ignore.
- **Server push (`PUSH_PROMISE`)** — dead; Chrome removed it. Don't build.
- **h2c (cleartext H2 / HTTP Upgrade)** — browsers only do H2 over TLS via
  ALPN. Skip unless a non-browser consumer needs it.

## Multiplexing / flow-control design sketch

One `http2::serve_conn(handler, stream)` task per connection (mirrors
`http::serve_conn`). It owns the HPACK decoder, the connection
flow-control window, and a small map of active streams. The loop:

1. Read a frame off the stream.
2. **HEADERS** → decode (HPACK) → build a `proto/http` `Request` → start
   serving that stream (its body, if any, arrives as later DATA frames;
   expose it to the handler via a `BodyReader` backed by a per-stream
   inbound queue gated on the stream's receive window).
3. **DATA** → credit into the target stream's inbound queue; emit
   `WINDOW_UPDATE` as the handler drains (connection + stream level).
4. Responses from concurrently-serving handlers are framed (HEADERS +
   DATA) and **interleaved** onto the single output stream, each capped by
   the peer's stream + connection send windows (the `min(cwnd, rwnd)`
   discipline, but at the H2 layer — note this is *above* TCP's own
   window; both apply).

The open design question is how concurrent per-stream handlers share the
one output stream cooperatively under the executor — the cleanest fit is
likely a single writer task draining a per-stream ready-set (mirror the
reactor's bitmap sweep), not a task per stream contending on the socket.

## Validation

- Host unit tests: HPACK round-trip (incl. dynamic-table eviction), frame
  codec, flow-control accounting.
- Integration: `curl --http2 https://…` serves a real response over h2; a
  browser negotiates h2 via ALPN and multiplexes the test page's assets.
  h2spec as a stretch.
- Regression: H1.1 and H3 paths must keep working; ALPN fallback to
  `http/1.1` intact; `tcp_test` + HVF integration green; both arches build.

## References

- [`stack-architecture.md`](stack-architecture.md) — the shared HTTP core
  (Contract 3) and the two-stacks → one-golden-path convergence H2 joins.
- [`http3-backlog.md`](http3-backlog.md) — the sibling app-layer backlog;
  QPACK is the HPACK reference, and the shared Huffman lives between them.
- [`conformance-roadmap.md`](conformance-roadmap.md) — conformance-test
  strategy (the in-process harness pattern H2 tests should follow).
