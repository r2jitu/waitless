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

`Response` holds `&mut dyn ResponseSink` (the TX mirror of
`BodySource`); the head + buffered-body path and the streaming
`write_chunk` path both go through it. Per-transport sinks below.

```rust
pub trait ResponseSink {
    fn send_head(&mut self, head: &ResponseHead<'_>)
        -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
    fn write_chunk(&mut self, buf: &[u8])
        -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
    fn finish(&mut self) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
}
```

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
- **Phase 1 — h1 streaming (generated/producer path). ✅ DONE (commit
  `cb9ad8f`).** `ResponseBodyProducer` (TX counterpart of `BodySource`)
  + `res.stream_body(ct, producer)`; the transport drives `next()`
  chunk-by-chunk, awaiting its own `send` between pulls (TCP
  backpressure) → peak memory `O(chunk)`. h1 streams close-delimited
  (`write_streaming_head_into_iobuf`: no Content-Length, `Connection:
  close`); h2/h3 fall back to `Response::materialize()` (drain producer
  → buffered body; correct, not bounded). `/stream` endpoint serves a
  1 GiB generated body. **Validated on HVF (512 MiB RAM): GET /stream
  over h1 returned exactly 1,073,741,824 bytes, all-zero, and the kernel
  heap stayed flat at ~3.4 MB across the whole 1 GiB transfer** —
  buffering would OOM. (This is the generated/computed path; the
  interleaved *echo* below is the remaining variant.)

- **Phase 1b — interleaved echo (read-while-write).** Needs the
  in-handler `write` path live (Response<'a> + `&mut dyn ResponseSink`)
  **and** a per-transport read/write split so the body reader + the
  response sink can hold the stream at once. Plaintext `TcpStream` split
  is straightforward (disjoint RX/TX waker slots); `TlsStream` + the
  generic `HttpStream` seam are the harder part. Not yet started.
- **Phase 2 — h2 streaming.** Per-stream TX queue + demux integration +
  window/cap backpressure. The correctness-sensitive part — GCE-validate
  large transfers (byte-perfect + bounded peak).
- **Phase 3 — h3 streaming.** QUIC stream writes + flow control.

## Validation

For each streaming transport: a large payload (e.g. 100 MB) echoes
**byte-perfect** (GCE, `curl`/loadgen — HVF's toy proxy lies about
large-transfer correctness) **and** the server's peak heap watermark
stays bounded (`O(chunk)`, not `O(payload)`) — read off `/obs`
`heap_*` — A/B against the materialised path.

[Contract 3]: stack-architecture.md (One handler API)
