# Streaming response bodies (write-as-you-read)

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

The asymmetry in today's `(&Request, &mut BodyReader)` (split) vs a
single response writer is **intrinsic to HTTP message ordering**, not
arbitrary:

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

Echo reads `&mut req` and writes `&mut res` — distinct borrows, so the
simultaneous read+write the echo needs is clean:

```rust
res.content_type(b"application/octet-stream");
while let Some(chunk) = req.read_chunk().await {   // RX backpressure
    res.write(chunk.data()).await?;                // TX backpressure
}
res.finish().await
```

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

## Phased plan

- **Phase 0 — API + plumbing (no behaviour change). ✅ DONE (commit
  `cbb80fb`).** Introduced the `(&mut Request, &mut Response) -> Result`
  handler shape: `RequestHead` (parser storage) + `Request<'a>` facade
  (`Deref` to head + `read_chunk`); `Response` keeps value constructors
  (`*res = Response::ok(..)` for the buffered common case) + in-place
  `status`/`content_type`/`header`/`write`/`finish`. `write` **buffers**
  in Phase 0; the transport sends `res` at handler return —
  byte-identical to the old returned-`Response` path. Rippled through h1
  / h2 / h3 / https + both apps; all proto tests pass; HVF smoke
  (h1/h2/404/body-read/64K) green.

  > **Discovered cost for the on-wire phases:** real streaming needs the
  > `ResponseSink` *live during the handler* (not a post-return drive),
  > because an **echo** reads the request body and writes the response
  > body **concurrently** on the same connection. That requires (a)
  > `Response<'a>` holding `&'a mut dyn ResponseSink` (a second handler-
  > signature touch), and (b) a **per-transport read/write split** so the
  > body reader and the response sink can hold the stream at once. The
  > split is easy for plaintext `TcpStream` (disjoint RX/TX waker slots),
  > harder for `TlsStream` (shared TLS state — though RX/TX keys +
  > sequence numbers are per-direction) and for h2/h3 (the demux/QUIC
  > stream is the single writer). A *generated* streaming body (no
  > concurrent request read) avoids the split but does not satisfy the
  > echo use case.
- **Phase 1 — h1 streaming (generated path). ✅ DONE (commit `cb9ad8f`);
  mechanism later reshaped in Phase 1c.** First cut used a *pull*-model
  `ResponseBodyProducer` (TX counterpart of `BodySource`) +
  `res.stream_body(ct, producer)`; the transport drove `next()`
  chunk-by-chunk, awaiting its own `send` between pulls (TCP
  backpressure) → peak memory `O(chunk)`. h1 streamed close-delimited
  (no Content-Length, `Connection: close`); h2/h3 fell back to
  `Response::materialize()` (drain producer → buffered body; correct,
  not bounded). `/stream` serves a 1 GiB generated body. (The producer
  was replaced by the in-handler `res.write()` push model in Phase 1c;
  see there for the current mechanism + GCE re-validation.)

- **Phase 1b — streaming echo (write-as-you-read). ✅ DONE (commit
  `3771910`).** `res.echo_request(ct)` splices the request body straight
  back out, bounded `O(chunk)`. The two-object `(&mut Request, &mut
  Response)` API can't hand a handler the read + write halves of one
  stream at once (two `&mut`), so the **serve loop** does the splice: it
  owns the stream and runs `recv_chunk → into_owned → send`
  sequentially (`into_owned` drops the read borrow before `send`
  re-borrows) — **no read/write split needed**. Generic over `S:
  HttpStream`, so h1 streams the echo bounded over **both plaintext and
  TLS**; h2/h3 drain the request body into the response (materialise —
  correct, not yet bounded). `/echo` endpoint added. **Validated on HVF
  (512 MiB RAM): small echo correct over h1/h1-TLS/h2; a 256 MiB POST to
  /echo over h1 echoed back exactly 268,435,456 bytes with the heap flat
  at 3.4 MB** (256 MiB req + 256 MiB resp = 512 MiB would OOM).

  > The serve-loop splice covers pure echo/proxy (the asked-for case). A
  > *transforming* handler that interleaves its own `read_chunk` +
  > `write` chunk-by-chunk would still need the in-handler sink +
  > read/write split (Response<'a>); deferred — the splice delivers the
  > bounded large-payload echo without it.

- **Phase 1c — push-model reshape (remove `ResponseBodyProducer`). ✅
  DONE (commits `38582f2` + `380cb08`).** Replaced the pull-model producer
  with the in-handler push model the API section above describes:
  `Response<'s>` owns `Option<&'s mut dyn ResponseSink>`, the handler
  generates a streamed body with `res.write(chunk).await` (head flushed
  lazily on the first chunk, each chunk awaited → backpressure) and ends
  it with `res.finish()`. h1 wires a live `H1Sink` for a **bodyless**
  request (read half idle → the sink can hold the stream; generic over
  `S`, so it streams over plaintext *and* TLS); a request with a body
  buffers (read half busy) and bounded echo stays the Phase 1b splice.
  `res.set(Response::ok(..))` installs a buffered response without
  disturbing the invariant `&'s mut` sink borrow. The four near-identical
  head writers collapsed to two (`*_parts`) with the `&Response` writers
  delegating. h2/h3 still buffer (their streaming sink is Phase 2–3); the
  obsolete `materialize()` drains are gone (`res.write` buffers directly).
  `/stream` is now an in-handler `res.write()` loop; the `ZeroStream`
  producer is deleted.

  > **Re-validated on GCE (c3-highcpu-4, gVNIC, production datapath —
  > HVF lies about large transfers):**
  > - `/health` TLS A/B (wrk -t4 -c4000 -d15s, 3 samples each):
  >   branch median **283.5K rps** (279.4/285.7/283.5) vs main median
  >   **287.9K rps** (285.6/287.9/288.1) — ~1.5%, ranges overlap,
  >   **identical per-request work (~1 send/req)** → the universal
  >   bodyless fork is perf-neutral on the golden hot path.
  > - `/stream` 1 GiB over h1: exactly 1,073,741,824 bytes, all-zero,
  >   live heap grew **~1.3 MB** across the whole transfer, `heap_oom=0`.
  > - `/echo` 256 MiB over h1: exactly 268,435,456 bytes, **sha256
  >   byte-perfect**, live heap grew **~41 KB** across the echo,
  >   `heap_oom=0`, server live after. Bounded `O(chunk)` confirmed.

- **Phases 2–3 — native h2/h3 bounded streaming (optimisation).** h2/h3
  currently *materialise* a streamed/echoed body (correct output,
  `O(body)` memory). Bounding them needs the per-transport streaming
  sink: h2 = a TX chunk queue the demux drains with conn+stream
  flow-control backpressure (mirror of the RX `StreamBody`); h3 = QUIC
  stream writes with FC. Deferred — not the core ask (which is
  delivered + bounded on h1).
- **Phase 2 — h2 streaming.** Per-stream TX queue + demux integration +
  window/cap backpressure. The correctness-sensitive part — GCE-validate
  large transfers (byte-perfect + bounded peak).
- **Phase 3 — h3 streaming.** QUIC stream writes + flow control.

## Validation

The bounded-memory + large-transfer-correctness proof must run on GCE —
HVF's userspace TCP proxy lies about both. The standing recipe (used for
Phase 1c above, scriptable as `/tmp/bounded_validate.sh` driven from
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
