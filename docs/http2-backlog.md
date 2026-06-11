# HTTP/2 — build plan + hardening backlog

Last updated 2026-06-10. **Status: happy path landed.** Server-role
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

## Build scope — first session (happy path) — ✅ done

A working server-role H2 that real `curl --http2` and a browser use. The
shipped capabilities (don't re-propose):

- **HPACK** encode/decode (`hpack.rs`): shared Huffman, 61-entry static
  table, full dynamic-table decoder (insert/evict/size-update); stateless
  encoder (static-indexed + literal-without-indexing, H=0, names
  lowercased — never uses a dynamic table, like QPACK).
- **Frame codec** (`frame.rs`): 9-byte header + SETTINGS, HEADERS, DATA,
  WINDOW_UPDATE, RST_STREAM, GOAWAY, PING, PRIORITY (parse-and-ignore),
  CONTINUATION assembly.
- **Connection preface** + SETTINGS exchange (server SETTINGS first,
  24-byte client magic validated, SETTINGS ACK).
- **Multiplexing serve loop** (`server.rs`): per-stream assembly,
  connection- and stream-level flow control (`min(stream_window,
  conn_window)`, stacked on TCP's window), responses interleaved by a
  single cooperative writer — chosen over a task per stream.
- Each stream's request + body wired to the `proto/http` handler API
  (request bodies now stream — see H2-10).
- **ALPN dispatch** in `proto/tls`.

## Hardening backlog (the tail — track here as found)

### Security / DoS — required before any public deploy (P0)

HTTP/2's framing opens DoS vectors that H1.1 doesn't have; a public
server **must** bound them. The cheap caps landed; a rate/ratio-over-time
flood guard is still open (see H2-1).

### H2-1 — Rapid Reset (CVE-2023-44487) — ✅ done (cumulative cap)

Cumulative RST_STREAM count per connection; past `RST_FLOOD_CAP` (200) the
connection is torn down with `GOAWAY(ENHANCE_YOUR_CALM)`.

Open: this is a cumulative cap, not yet a rate/ratio over time — revisit
alongside any H2-3 rate-limit-flood work.

### H2-2 — HPACK bomb / decompression ratio — ✅ done

### H2-3 — Frame floods — ✅ done

`ctrl_since_progress` consecutive-control-frame counter; past
`CONTROL_FLOOD_CAP` (1024) with no request, shed with
`GOAWAY(ENHANCE_YOUR_CALM)`. Checked before dispatch (also bounds
`ctrl_out`). CONTINUATION-flood half covered by `HEADER_BLOCK_CAP` (H2-5).

### H2-4 — `MAX_CONCURRENT_STREAMS` enforcement — ✅ done

Advertised (100) and enforced; a stream past `active_count()` is refused
with `RST_STREAM(REFUSED_STREAM)`.

### Conformance / interop (P1–P2)

### H2-5 — CONTINUATION handling — ✅ done

CONTINUATION-flood (CVE-2024-27316) bounded by `HEADER_BLOCK_CAP` (64 KiB)
on the accumulated block; cross-stream interleaving rejected.

### H2-6 — Full SETTINGS surface — ✅ done

Mid-connection `INITIAL_WINDOW_SIZE` change applied **retroactively** to
every open stream's send window across both emission paths (RFC 7540
§6.9.2); the delta may drive a window negative, overflow past 2^31−1 is a
connection `FLOW_CONTROL_ERROR`. Peer `HEADER_TABLE_SIZE`/
`MAX_HEADER_LIST_SIZE` bound *our* encoder, which uses no dynamic table —
nothing to honor.

### H2-7 — HPACK dynamic-table eviction — ✅ done

32 B/entry overhead (RFC 7541 §4.1); table-clear when a single entry
exceeds the max.

### H2-8 — Error handling completeness — ✅ mostly done

Connection errors emit `GOAWAY(code, last-stream-id)`; stream errors emit
`RST_STREAM`. §8.1.2 malformed-request validation enforced (field-name
case, pseudo ordering/duplication, required pseudos, forbidden
connection-specific headers, `te`≠`trailers`) and §8.1.2.6 Content-Length
vs DATA (over/under-delivery, content-length on a bodyless request).

Open: a §7 error-code-choice audit and a graceful two-GOAWAY drain.

### H2-9 — h2spec

Run the h2spec conformance suite; track failures here. Not yet run.

### Tail items discovered during the build

- **H2-10 — Streaming request bodies — ✅ done.** All transports now
  stream uniformly. Approach: per-stream handler tasks (no read/write
  split — the demux task `select`s read-first/cancel-safe, so a single
  TLS-stream owner does both read and write); bodyless GETs dispatch
  inline. (The reentrant-body-source and single-`select`-handler
  alternatives were rejected as tangled / non-multiplexing.)
- **H2-11 — DATA framing / send batching — ✅ batching done; zero-copy
  open.** `flush` frames all sendable frames into one `IOBufChain` and
  emits a single `stream.send` (HEADERS + DATA ride one TLS record / TCP
  send → H1.1 small-response parity).

  Open (zero-copy TX): the DATA payload is still copied into a per-frame
  `Vec`, forfeiting H1.1's zero-copy TX. **Do not just re-do the obvious
  rewrite:** framing DATA directly from the body's own IOBufs (narrowed/
  shared views or a reused coalesce buffer) was prototyped and **reverted**
  — it intermittently corrupted large single-stream transfers (~40% h2load
  failure on `/static-256k`, the multi-flush window-blocked path) with the
  server-side frame/flow counters clean, i.e. a latent hazard in the
  TLS-seal / TX path triggered by emitting non-frame-shaped (oversized or
  refcount-shared) buffers. That path must be investigated first; the
  alloc delta isn't worth the corruption risk until then.
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
- **H2-14 — Receive-window enforcement.** ✅ closed 2026-06-10 (client-arc
  D / S1): each `StreamSlot` tracks the advertised stream receive window
  (debited on DATA arrival, credited with the consume-driven
  WINDOW_UPDATE); an overrun is RST_STREAM(FLOW_CONTROL_ERROR) at the
  `process_data` site instead of riding up to the 1 MiB defensive buffer
  cap. Connection-level overrun stays untrackable by construction — the
  conn window is re-credited on arrival, so its in-flight exposure is one
  ≤ MAX_FRAME_SIZE frame, always inside the 64 KiB initial window; making
  it enforceable would mean crediting the conn window on consume, a
  backpressure-behaviour change, not a bounds check. The h2 CLIENT
  (`client.rs`) enforces both levels symmetrically.

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
