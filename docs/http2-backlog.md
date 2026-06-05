# HTTP/2 — build plan + hardening backlog

Last updated 2026-06-01. **Status: happy path landed.** Server-role
HTTP/2 is implemented in `crates/proto/http2` and selected by ALPN over
the existing TLS/TCP path; real `curl --http2` and browsers negotiate
`h2` and multiplex the test page's assets (validated by the HVF
integration test: `test_h2_curl_get`, `test_h2_curl_multiplexed_pages`,
`test_https_alpn_prefers_h2`, `test_https_alpn_http11_fallback`). HTTP/1.1
remains the golden path and the ALPN fallback; H3 is untouched. The
remaining P1–P2 conformance / interop tail (and the deferred DoS
rate-limits) is tracked below.

For *why* H2 (the first-visit/TCP-path multiplexing win, the H3 fallback
that keeps multiplexing) and *how it relates to H1.1/H3* see the strategic
notes in [`roadmap.md`](roadmap.md). H2 does **not** supersede H1.1 — they
coexist, selected per-connection by ALPN.

## Crate structure (built)

- New crate **`crates/proto/http2`** (`lib.rs` / `frame.rs` / `hpack.rs`
  / `static_table.rs` / `server.rs` / `diag.rs`), mirroring `proto/http3`.
  Depends on `proto/http` (the transport-agnostic shared HTTP core) and is
  **generic over the byte stream** (`http::HttpStream`), so it carries
  *no* tls/tcp/quic dep — exactly like `proto/http`'s `serve_conn`.
- **Did not merge** h1/h2/h3 into one `http` lib (it would pull
  `proto/quic` + all transports into every plain-H1.1 consumer). The
  shared semantics ride `proto/http` without that coupling.
- Extracted `proto/http3/src/huffman.rs` into the shared leaf crate
  **`crates/proto/field-huffman`** (`crate_name = field_huffman`); both
  `http2` (HPACK) and `http3` (QPACK) depend on it — the RFC 7541 Huffman
  table is identical. `http3/src/huffman.rs` is now a thin re-export so
  existing `crate::huffman::…` call sites are unchanged. The static tables
  differ (HPACK 61 entries vs QPACK 99) and stay per-crate.
- **The listener lives in `proto/http2` (`http2::listen`), and `proto/tls`
  is pure TLS.** Naming follows the ALPN tokens: `h2` *is* HTTP/2-over-TLS
  (RFC 7540 §3.1; cleartext is `h2c`, a non-goal), so the HTTP/2 server is
  an HTTPS server — and, because ALPN mandates an HTTP/1.1 fallback, it
  necessarily serves h1.1 too. So `http2` owns the `TlsStream: HttpStream`
  adapter, the conn pool, and `http2::listen`, which drives the handshake,
  reads the negotiated `AlpnProtocol`, then runs `serve_conn` (h2) or
  `http::serve_conn` (h1.1). This parallels `proto/http3` (which bundles
  its QUIC listener): `http` / `http2` / `http3` are each "the server for
  that HTTP version over its transport" (plaintext TCP, TLS/TCP, QUIC/UDP).
  `proto/tls` keeps **no `http`/`http2` dep** (sans-io state machine only);
  it exposes `AlpnProtocol` + `is_established`/`is_terminated`/
  `negotiated_alpn` so the listener can drive the handshake and branch
  without reaching into TLS internals. `http2`'s protocol half
  (`serve_conn`) stays generic over `http::HttpStream`; only `listen`
  pulls TLS/TCP.

  *(History: a first cut put the listener in `proto/tls`, then in a
  `proto/https` crate scoped to TCP/TLS; both were superseded — `tls`
  shouldn't depend on HTTP, and a TCP-only crate named "https" wrongly
  excludes h3. Folding the listener into `http2` is the resolution.)*
- **`proto/https` is the optional all-transports facade.** Since `http2`
  (TCP) and `http3` (QUIC) are the two HTTPS transports, "serve all of
  HTTPS in one call" is a composition: `https::serve(port, service, cert,
  key)` binds both + wires `Alt-Svc` + degrades gracefully if the UDP/QUIC
  bind fails. It takes one handler via the `https::Service` trait, whose
  **stream-generic `handle<S>` method** is what lets a single value drive
  both transports (the TCP path monomorphizes `handle::<TlsStream>`, the
  QUIC path `handle::<NullStream>`) — a plain `async fn` can't, since one
  value can't be two stream-monomorphizations at once. The facade is
  buildable today (no `ByteStream`/Contract-3 unification needed); the
  `Service` trait's generic method *is* the polymorphism mechanism. The
  webserver app routes all of HTTPS through one `https::serve`.
- ALPN selection is **server-preference** (`h2` over `http/1.1`); a client
  that offers no `h2` still gets `http/1.1` — the fallback the golden path
  depends on.

## Reuse map (don't reinvent)

| Need | Reuse |
|---|---|
| HTTP semantics, handler API, body streaming | `proto/http` (h3 already rides it) |
| Huffman (HPACK == QPACK table) | `proto/http3/src/huffman.rs` → shared leaf |
| HPACK reference | `proto/http3/src/qpack.rs` — HPACK is the simpler cousin (same Huffman + integer/string primitives; a different static table; a dynamic table **without** QPACK's encoder/decoder-stream reordering dance) |
| ALPN negotiation | `proto/tls/src/handlers.rs` (~line 249) — already negotiates ALPN, selects `http/1.1` today; add `"h2"` and surface the choice to the serve dispatch |
| Per-conn async task + multiplexing pattern | the h3 server's stream-dispatch shape (`proto/http3/src/server.rs`) |

## Build scope — first session (happy path) — DONE

A working server-role H2 that real `curl --http2` and a browser use:

- [x] **HPACK** encode/decode (`hpack.rs`): shared Huffman, 61-entry
  static table, full dynamic-table **decoder** (insert / evict /
  size-update — the correctness-critical half, exercised by the RFC 7541
  §C.3 first/second-request vectors); stateless **encoder** (static-indexed
  + literal-without-indexing, H=0, names lowercased — never uses a dynamic
  table, the same simplification QPACK makes).
- [x] **Frame codec** (`frame.rs`): the 9-byte header + SETTINGS, HEADERS,
  DATA, WINDOW_UPDATE, RST_STREAM, GOAWAY, PING, PRIORITY (parse-and-ignore),
  CONTINUATION assembly.
- [x] **Connection preface** + SETTINGS exchange (server SETTINGS first,
  client 24-byte magic validated, SETTINGS ACK).
- [x] **Multiplexing serve loop** (`server.rs`): per-stream assembly,
  **connection- and stream-level flow control** (the `min(stream_window,
  conn_window)` discipline, stacked on TCP's own window), responses
  interleaved by a single cooperative writer (`next_output_frame` draining
  the out-queue + WINDOW_UPDATE-driven re-flush — the design favoured over
  a task per stream).
- [x] Wire each stream's request + body to the `proto/http` handler API.
  Request bodies are **buffered** before dispatch and served via a prebuf
  `BodyReader` (matching the h3 server); streaming request bodies through
  `BodyReader` over live DATA frames is a tail item (see H2-10).
- [x] **ALPN dispatch** in `proto/tls`.

## Hardening backlog (the tail — track here as found)

### Security / DoS — required before any public deploy (P0)

HTTP/2's framing opens DoS vectors that H1.1 doesn't have; a public
server **must** bound them. The cheap caps that fell out of the build
landed this session; the rate-limit-flood guard is still open.

- [x] **H2-1 — Rapid Reset (CVE-2023-44487).** Cumulative RST_STREAM
  count per connection; past `RST_FLOOD_CAP` (200) the connection is torn
  down with `GOAWAY(ENHANCE_YOUR_CALM)`. *Partial* — a cumulative cap, not
  yet a rate/ratio over time; revisit alongside H2-3.
- [x] **H2-2 — HPACK bomb / decompression ratio.** The decoder enforces
  `SETTINGS_MAX_HEADER_LIST_SIZE` (64 KiB) on the decompressed list and
  bounds the dynamic table at the advertised `SETTINGS_HEADER_TABLE_SIZE`
  (4 KiB).
- **H2-3 — Frame floods.** SETTINGS flood, PING flood, empty-DATA flood,
  WINDOW_UPDATE flood, 0-length-HEADERS flood. **Still open:** no
  rate-limit on control frames yet (we ACK/answer each as it arrives).
  Bound outstanding control frames / per-RTT churn. The CONTINUATION-flood
  half is covered by `HEADER_BLOCK_CAP` (see H2-5).
- [x] **H2-4 — `MAX_CONCURRENT_STREAMS` enforcement.** Advertised (100)
  and enforced — a new stream past `active_count()` (pending bodies +
  in-flight responses) is refused with `RST_STREAM(REFUSED_STREAM)`.

### Conformance / interop (P1–P2)

- [x] **H2-5 — CONTINUATION handling.** Header blocks split across
  CONTINUATION frames are assembled (`header_asm`), interleaving is
  rejected (only CONTINUATION on the same stream may follow a HEADERS
  without END_HEADERS), and the "CONTINUATION flood" (CVE-2024-27316) is
  bounded by `HEADER_BLOCK_CAP` (64 KiB) on the accumulated block.
- **H2-6 — Full SETTINGS surface.** *Partial.* We honor peer
  `INITIAL_WINDOW_SIZE` (for new streams), `MAX_FRAME_SIZE` (caps DATA we
  emit), and validate `ENABLE_PUSH`/`MAX_FRAME_SIZE` ranges. **Still open:**
  applying a mid-connection `INITIAL_WINDOW_SIZE` change **retroactively**
  to already-open streams' send windows (RFC 7540 §6.9.2 — the tricky
  one; peers send it before opening streams in practice, so it's low-risk
  but non-conformant). `HEADER_TABLE_SIZE`/`MAX_HEADER_LIST_SIZE` from the
  peer bound *our* encoder, which uses no dynamic table and emits tiny
  header blocks, so nothing to honor there.
- [x] **H2-7 — HPACK dynamic-table eviction.** Entry overhead = 32 B/entry
  (RFC 7541 §4.1), eviction on insert and on size-update, table-clear when
  a single entry exceeds the max — implemented + unit-tested.
- **H2-8 — Error handling completeness.** *Partial.* Connection errors
  emit `GOAWAY(code, last-stream-id)`; stream errors emit `RST_STREAM` with
  a code (PROTOCOL_ERROR / REFUSED_STREAM / FLOW_CONTROL_ERROR /
  ENHANCE_YOUR_CALM). **Open:** a full audit of RFC 7540 §7 code choices,
  graceful two-GOAWAY drain, and malformed-request edge cases (we do a
  minimal pseudo-header check — response pseudo / unknown pseudo →
  RST_STREAM — but not the full §8.1.2 validation).
- **H2-9 — h2spec.** Run the h2spec conformance suite; track failures here.
  Not yet run.

### Tail items discovered during the build

- **H2-10 — Streaming request bodies. DONE.** Request bodies now stream;
  the 256 KiB whole-body buffer / `RST_STREAM`-on-overflow is gone. All
  transports stream uniformly (h1.1 always did; h3 via `H3BodySource` +
  the QUIC receive-flow-control extension; h2 here).

  Approach taken: **per-stream handler tasks** (option 2 below) — but
  *without* a stream split. The demux task stays the single TLS-stream
  owner doing both read and write; it `select`s on `(read_frame,
  handler-wakeup)` each iteration (the `select` polls the read first and
  only drops it while pending, so no inbound bytes are lost on the wakeup
  branch — that's what makes a split unnecessary). A body-bearing request
  spawns a handler task fed by a shared `StreamBody` channel; bodyless
  GETs still dispatch inline (no task-arena hit). Responses funnel back
  through `resp_sink` → `queue_response` so HPACK encode + send-window
  framing stay in the one owner. Receive flow control credits the stream
  window on consume (backpressure) and the conn window on arrival.

  The three shapes that were weighed, for the record:

  1. **Reentrant body source** — the body source itself calls `read_frame`
     and buffers other streams' frames for after the handler. Smallest
     diff but tangled: HPACK ordering across deferred HEADERS, CONTINUATION
     spanning frames, flow-control crediting mid-reentrancy.
  2. **Per-stream handler tasks** *(chosen)* — demux routes DATA to
     per-stream channels; handlers run concurrently. True multiplexing.
     The feared read/write **split** turned out unnecessary given
     `select`'s cancel-safe read.
  3. **Cooperative `select` on one handler future** — no spawn, but one
     in-flight handler (gives up multiplexing).
- **H2-11 — DATA framing / send batching. *Batching done; zero-copy
  deferred.*** The **one-send-per-frame** half is fixed: `flush` now
  frames all sendable frames into one `IOBufChain` and emits a single
  `stream.send`, so a small response's HEADERS + DATA ride one TLS
  record / one TCP send instead of two (measured on HVF: TCP sends and
  TLS encrypt-records per `/health` request 2.0 → 1.0, i.e. H1.1 parity;
  closed the bulk of the h2-vs-h1.1 small-response gap — h2 went from
  ~0.65× h1.1 throughput to ~parity). Per-response allocations were also
  trimmed (header list stack-allocated; the DATA chunk `Vec` folded into
  the frame `Vec` — `/health` allocs/req 7.3 → 5.4). **Still copies** the
  DATA payload into a per-frame `Vec` (forfeiting H1.1's zero-copy TX).
  A true zero-copy rewrite (frame DATA directly from the body's own
  IOBufs via narrowed/shared views, or coalesce into one reused buffer)
  was prototyped and **reverted**: it intermittently corrupted large
  single-stream transfers (~40% h2load failure on `/static-256k`, the
  multi-flush window-blocked path) with the server-side frame/flow
  counters clean — a latent hazard in the TLS-seal / TX path triggered
  by emitting non-frame-shaped (oversized or refcount-shared) buffers.
  Needs that path investigated first; the remaining alloc delta isn't
  worth the corruption risk until then.
- **H2-12 — Pre-dispatch WINDOW_UPDATE.** A WINDOW_UPDATE that arrives for
  a stream before its response is queued (no `StreamOut` yet) is dropped.
  Harmless for the request/response shape (clients grow the window in
  response to our DATA), but it should be stashed and applied at dispatch.
- **H2-13 — True concurrent handlers.** Handlers run **inline** when a
  stream completes — correct multiplexing at the frame layer (many streams
  on one connection, interleaved responses), but a slow handler stalls the
  whole connection rather than yielding to sibling streams. The single
  cooperative writer is in place; running handlers concurrently on the
  executor (and feeding their outputs into the same writer) is the next
  step toward the backlog's "N streams mapped onto the executor".
- **H2-14 — Connection receive-window enforcement.** We replenish the
  connection/stream receive windows (WINDOW_UPDATE crediting consumed
  bytes) but don't strictly track-and-reject a peer that overruns our
  advertised window. A conformant peer never does; strict enforcement is a
  hardening item.

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
