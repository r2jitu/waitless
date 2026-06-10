# Streaming response bodies (write-as-you-read)

> **Status: shipped** (Phases 0–3, 2026-06). This is the design
> reference — the handler API, the per-transport backpressure model, and
> the one rejected alternative worth not re-trying. The phase-by-phase
> build narrative was collapsed into the ledger at the end (the detail is
> in git log); the handler-API *contract* lives in
> [`stack-architecture.md`](stack-architecture.md) "One handler API".

## Problem

Per-connection peak memory is bounded on the **read** side but not the
**write** side:

- **RX (request body): bounded.** The handler streams the request body
  through `BodyReader` (`H2BodySource` / `recv_chunk`), and h2 enforces
  `STREAM_RECV_BUF_CAP = 1 MiB` of unconsumed buffered body per stream —
  past it the stream resets, and WINDOW_UPDATE credit is only emitted as
  the handler consumes. h3 has the analogous QUIC recv-window cap.
- **TX (response body): unbounded.** The handler returns a complete
  `Response { body: IOBufChain }`; the whole body is materialised before
  it is framed (h1 iterates `into_parts`, h2 holds it in `StreamOut`).

So a handler that echoes an *N*-byte upload reads it with ~1 MiB of
backpressure but accumulates the echoed copy into a `Response` →
**peak ≈ O(N)**. There is no way to write a memory-bounded large echo,
proxy, or transform today.

## Goal

A **streaming response**: the handler writes body chunks *as it reads
them*, each `write().await` applying backpressure against the transport
send window, so peak memory is `O(chunk + flow-control windows)` rather
than `O(response size)`. The motivating use case is a streaming echo
for large payloads; the general case is any proxy / transform / large
generated body.

## API — symmetric in-message / out-message objects

### Why not "split both sides symmetrically"

The asymmetry between the prior request-only API's `(&Request, &mut
BodyReader)` (split) and a single response writer is **intrinsic to HTTP
message ordering**, not arbitrary:

- A **request** is *received* head-first then body, so the head is a
  complete value to read (`&Request`) and the body streams in after
  (`&mut BodyReader`). Splitting is natural.
- A **response** is *sent* head-first then body, and **the head must be
  on the wire before the first body byte** — so it cannot be a value the
  handler *returns after* streaming the body. The response head is
  therefore coupled to the body writer: set the head, then write the
  body through the same object.

You can't give the response a head-as-return-value *and* stream its
body. So the coherent move is to combine **both** sides into one
in-message and one out-message object:

```rust
// one handler, every transport
async fn handle(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()>
```

### `Request` — inbound message (head + streaming body)

```rust
req.method() / req.path() / req.header(b"host") / req.headers()
req.content_length() -> Option<usize>
async req.read_chunk() -> Option<Chunk<'_>>   // body, ≤1 MiB / QUIC-window backpressure
```

The streaming body-read (today on `BodyReader`) moves onto `Request`;
`Request` becomes `&mut` because the read advances a cursor. A bodyless
GET simply never calls `read_chunk`.

### `Response` — outbound message (head + buffered or streaming body)

```rust
res.status(200); res.content_type(b"..."); res.header(n, v);  // head (chainable)
res.ok(b"text/plain", body);                 // one-shot buffered body (common case)
async res.write(&[u8]) -> Result;            // stream a chunk — BACKPRESSURE here
async res.finish() -> Result;                // end stream
```

The head flushes **lazily on the first `write`** (or with the buffered
body at handler return), so streaming needs no explicit `start()` and
the head stays editable until the first body byte. **No
`Response::streamed()` sentinel** — the response *is* `res`; at handler
return the transport sends whatever the handler left:

```rust
// transport, after the handler returns:
//   - handler streamed (called write) → head+body already on the wire, nothing to do
//   - handler set a buffered body (res.ok / res.status+body) → send head + buffered body
//   - handler set nothing → empty 200 / 500
res.finish_on_drop_or_return();
```

Echo (and any proxy / transform) reads `&mut req` and writes `&mut res`
in one loop — this is **plain handler code**, no framework echo mode:

```rust
res.content_type(b"application/octet-stream");
while let Some(chunk) = req.read_chunk().await {   // RX backpressure
    res.write(chunk.data()).await?;                // TX backpressure
}
res.finish().await
```

`req` and `res` are distinct values, but on h1 they draw on the **same
connection** — the read and the write both need the stream. The serve
loop resolves that without a read/write split (unsound on TLS): it wraps
the borrowed stream in a per-connection `RefCell` shared by the body
source and the response sink (the `CellSource`/`CellSink` duplex,
phase 1d in the ledger below). The handler uses them
sequentially — `read_chunk` returns *owned* bytes, releasing the stream
before `res.write` re-borrows it — so the two never overlap, and a
single per-conn task is the cell's only borrower. Bounded `O(chunk)`
over plaintext and TLS. h3 streams every response through a live sink,
and h2 streams bodied requests through a spawned per-stream sink (Phases
2–3); the lone unbounded case is a *bodyless* h2 GET, which h2 dispatches
inline with a sink-less `Response` (see Phase 2).

### Transport seam (unchanged in spirit)

`Response<'s>` holds `Option<&'s mut dyn ResponseSink>` (the TX mirror
of `BodySource`); `res.write` routes straight to it when wired, and the
head goes out lazily on the first chunk. Per-transport sinks below.

```rust
pub trait ResponseSink {
    fn send_head(&mut self, status: i32, content_type: &[u8],
                 extra_headers: &[(&[u8], &[u8])])
        -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
    fn write_chunk(&mut self, buf: &[u8])
        -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
    fn finish(&mut self) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
}
```

The head is passed as loose parts (status / content-type / extra
headers) rather than a `ResponseHead` struct — `Response`'s fields are
disjoint borrows, so the sink can read them while `self.sink` is
borrowed `&mut`, with no intermediate value.

### Migration cost

Bigger than a bolt-on writer, but it's the right seam: `Request` becomes
`&mut`, the body-read moves onto it, `Response` becomes an out-param,
and handlers change `return Response::ok(..)` → `res.ok(..)` (≈ same
terseness). Touches `https::serve` + all three `serve_conn`s + both
apps. This *is* the doc's [Contract 3] handler-API unification, done
once. (Lighter alternative considered + rejected: keep `(&Request, &mut
BodyReader, &mut ResponseWriter) -> Response` + a `streamed()` sentinel —
smaller diff but keeps the asymmetry and the sentinel.)

## Backpressure — per transport

| transport | `write().await` does | backpressure source | bounded? |
|---|---|---|---|
| **h1** | chunked-transfer-encoding write to `TcpStream` | TCP cwnd/rwnd (`async_try_send_chain` parks when full) | ✅ TCP |
| **h2** | push chunk to a per-stream TX queue the demux drains into DATA frames | conn+stream send window; queue cap → park handler, woken via `demux_wake` | ✅ window + cap |
| **h3** | QUIC stream write | QUIC stream flow control | ✅ |

h2's TX queue is the structural mirror of the RX `StreamBody`: a bounded
chunk queue the single-writer demux drains, with the producer (handler
task) parking when it's full. The demux machinery (single writer,
per-stream flow control, `demux_wake`) already exists.

## Shipped phases (ledger — detail in git log)

| phase | what landed | commit |
|---|---|---|
| 0 | `(&mut Request, &mut Response) -> Result` handler shape; `write` buffers (no behaviour change) | `cbb80fb` |
| 1 / 1c | h1 in-handler push model (`res.write().await`/`finish`); `/stream` 1 GiB generated, GCE bounded `O(chunk)` | `cb9ad8f` → `38582f2`/`380cb08` |
| 1d | app-written duplex echo via per-conn `RefCell<&mut S>` (`CellSource`+`CellSink`); retired `echo_request`/`is_echo`; one `serve_conn` dispatch. GCE: 256 MiB TLS echo sha256-perfect, heap +~25 KB | `815c954` |
| 2 | h2 bounded streaming — per-stream `StreamTx` the demux drains under flow control, `res.write` parks on `STREAM_SEND_BUF_CAP` (256 KiB). GCE: 256 MiB h2/TLS echo bounded | `a139b4c` |
| 3 | h3 bounded streaming — `H3Sink` frames onto the QUIC stream, parks on `H3_SEND_BUF_CAP` (256 KiB) via `stream_drain_below`; no bodyless residual. GCE: 256 MiB h3 `/stream` heap +731 KB | `a6d4591` |

Residuals worth knowing (detail in the commits): a *bodyless* h2 GET
that generates a large streamed body stays inline + buffered `O(body)`
(spawning every GET regresses the hot path — see below); a mid-stream h3
handler error FINs the partial stream rather than RESET_STREAM (the h3
layer doesn't surface a reset).

## Per-stream task spawn — explored, not shipped

The two remaining seams — h2's bodyless-generated-streaming residual and
h3's inline request serialization — would both be closed by giving every
request stream its own task (the per-stream-task model). Built and
measured on GCE; **reverted** — neither pays off as-is:

- **h2: spawn bodyless GETs too.** Routing bodyless requests through the
  same spawned-task path as body-present ones (an `eof_now`-seeded body
  channel) bounds a generated streamed GET. Cost, measured on GCE
  (c3-highcpu-4, h2 `/health`, `/obs` `heap_total_allocation_count` ÷
  `responses_sent`): **3.08 allocs/req inline → 5.09 spawned, +~2.0
  allocs/req (+65%)** — the boxed future + the StreamBody/StreamTx `Rc`s.
  RPS was identical (≈236K) but **client-bound** (loadgen saturates the
  8-core kvm-vm), so server-throughput-neutrality couldn't be proven.
  Adding +65% allocator work to the single hottest path (every GET) to
  bound a *rare* case (a bodyless GET that generates a large body —
  downloads are normally static/buffered) is a poor trade, so bodyless
  GETs stay inline (`dispatch_bodyless`), the residual documented.

- **h3: spawn a task per request stream.** Would fix the inline
  serialization (a streaming/slow handler blocking the accept loop).
  **Blocked by the single-waiter `AsyncEvent`:** the conn's `progress`
  event parks exactly one waker (a second waiter overwrites the first).
  Inline, only one thing waits at a time; with per-stream tasks the
  accept loop **and** N concurrent request tasks all wait on the one
  shared `progress`, clobbering each other's wakers → lost wakeups →
  `test_h3_concurrent_uploads` stalls (a racy concurrency bug, worse than
  the serialization it replaces). Shipping it needs a **multi-waiter
  wakeup in the QUIC conn** (per-stream events the conn task fans out to,
  or a broadcast event) — a real change to the fragile, non-golden QUIC
  core; deferred rather than rushed. h3 stays inline.

Net: the streaming feature ships as Phases 0–3; the per-stream-task model
is a future option gated on (a) cheaper task/channel reuse for the h2 hot
path and (b) a multi-waiter conn wakeup for h3.

## Validation

The bounded-memory + large-transfer-correctness proof must run on GCE —
HVF's userspace TCP proxy lies about both. The standing recipe (used for
the bounded-stream phases, scriptable as `scripts/bounded-stream-validate.sh` driven from
`kvm-vm`): for the h1 path, stream/echo a payload far larger than any
per-request budget while sampling `/obs` `heap_allocated_bytes`
mid-transfer — a bounded path grows live heap by `O(chunk)` (kilobytes
to a megabyte), a buffering path by `O(payload)`; verify exact byte
count + `sha256` (echo) + `heap_oom=0` + the server still serving
`/health` after. Pair any hot-path-touching change with a `/health` TLS
A/B against `main` (wrk -c4000, ≥3 samples each, compare medians +
`/obs` per-request work counters — ranges overlap under SPOT noise, so
the work counters are the tie-breaker). h2/h3 bounded streaming
(Phases 2–3) await their per-transport sink; until then they materialise
(correct, `O(body)`), so don't point the >RAM `/stream` at them.

[Contract 3]: stack-architecture.md (One handler API)
