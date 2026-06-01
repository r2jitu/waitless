# HTTP/3 (RFC 9114) + QPACK (RFC 9204) — conformance backlog

Last updated 2026-05-31.

This tracks the **HTTP/3 application layer** — the RFC 9114 framing /
control-stream / request mapping and the RFC 9204 QPACK header
compression in `crates/proto/http3/`. The **QUIC transport** underneath
(RFC 9000/9001/9002 — streams, flow control, loss detection, the
unbuilt congestion controller, frame retransmission) is tracked
separately in [`conformance-roadmap.md`](conformance-roadmap.md) Part 3;
this doc cross-refs it rather than duplicating it.

H3 is the **differentiator still under construction** (IPv6 + QUIC + H3),
not the golden path — see [`stack-architecture.md`](stack-architecture.md).
It works end-to-end against real browsers today (`dev.r2jitu.com`), but
several RFC 9114/9204 corners are deliberately minimal.

## Current state

Implemented in `proto/http3` (server-role): the unidirectional **control
stream** + an (empty) **SETTINGS** frame, **HEADERS**/**DATA** request and
response framing (`frame.rs`), **QPACK** encode/decode (`qpack.rs`,
static-table-only), the RFC 9204 static table (`static_table.rs`) and the
RFC 7541 Huffman codec (`huffman.rs`). The request/response/body types and
handler API are the shared `proto/http` core. Validated live against
Chrome/Safari/Firefox over `udp:443`.

## Gaps — priority order

### H3-1 — QPACK is static-table-only (no dynamic table) — P2

**What.** `qpack.rs` advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`,
which prohibits dynamic-table references and lets us skip the
encoder/decoder-stream machinery (a deliberate simplification, RFC-legal).

**Cost.** Headers that repeat across requests on a connection (cookies,
user-agent, accept-*) are re-encoded with literals every time instead of
a 1–2 byte dynamic index → larger header blocks, less of H3's compression
win realized.

**Fix.** Add the QPACK encoder + decoder unidirectional streams, a dynamic
table, and insert-count / base accounting (RFC 9204 §3–4). The reordering
handshake (Required Insert Count, blocked streams) is the complexity QUIC
makes necessary that HPACK avoids — see [`http2-backlog.md`](http2-backlog.md)
H2-7 for the simpler HPACK cousin. **Effort: L.**

### H3-2 — Lost STREAM/CRYPTO frames are never re-queued — P1 (correctness)

**What.** `detect_loss` declares packets lost but the lost STREAM/CRYPTO
frames aren't replayed (`SendStream.send_offset` advances irreversibly;
the PTO probe is a bare PING). Recovery leans on client retransmits.

**Where tracked.** This is a QUIC-transport gap owned by
[`conformance-roadmap.md`](conformance-roadmap.md) Part 3 (RFC 9002) and
flagged in [`stack-architecture.md`](stack-architecture.md) (any
`SendStream` redesign must leave room for replay-from-offset). Listed here
only so the H3 picture is complete; **fix it on the transport side.**

### H3-3 — Peer SETTINGS are ignored — P2

**What.** The server emits its own (empty) SETTINGS and **ignores** the
client's control-stream SETTINGS frame. Fine for the values we don't act
on, but `SETTINGS_MAX_FIELD_SECTION_SIZE` (the peer's header-list limit)
and any QPACK capacity (once H3-1 lands) must be honored.

**Fix.** Parse + apply the inbound SETTINGS frame. **Effort: S.**

### H3-4 — Error codes, GOAWAY, and stream-error discipline — P2

**What.** Audit RFC 9114 §8 error codes and the §5.2 connection-shutdown
GOAWAY (graceful drain with `last-stream-id`); confirm malformed requests
produce the right `H3_*` error rather than a generic close.

**Fix.** Map failure paths to RFC 9114 error codes; implement GOAWAY for
shutdown. Pairs with the cooperative-drain shutdown item in
[`roadmap.md`](roadmap.md). **Effort: M.**

### H3-5 — Request/response semantics conformance — P2

**What.** Audit the RFC 9114 §4 request mapping: pseudo-header validation
(`:method`/`:scheme`/`:authority`/`:path` presence + ordering), the
content-length policy (the nit flagged in
[`stack-architecture.md`](stack-architecture.md)), and connection-specific
header rejection (`Connection`, `Transfer-Encoding` are illegal in H3).

**Fix.** Tighten the HEADERS→`Request` path with the §4.1.1/§4.2 checks.
Shares the version-agnostic HTTP-semantics gaps with H1/H2 (chunked
rejection already done — see rx-path item E). **Effort: M.**

### H3-6 — Multi-buffer RX accumulator (unblocks RSC) — P2

**What.** Hardware RSC (gVNIC `enable_rsc`) emits multi-buffer coalesced
super-frames our single-EOP DQO RX drops. Tracked as rx-path item I; it's
an RX/driver gap, not strictly H3, but it's the prerequisite for the H3
upload/download throughput win on c3. **Where**: rx-path-optimizations.md.

## Non-goals

- **Server push (`PUSH_PROMISE` / MAX_PUSH_ID)** — dead (Chrome removed
  it). We already don't initiate push; just keep `MAX_PUSH_ID` at 0.
- **Datagram / WebTransport (RFC 9297 / 9220)** — out of scope.

## Validation

- `quic_test` for QPACK round-trips + frame codec (host-testable, additive
  to the existing harness).
- Live interop: browsers over `udp:443` (the current bar); `curl --http3`
  / `nghttp3` for scripted checks.
- The QUIC-transport conformance harness work is in
  [`conformance-roadmap.md`](conformance-roadmap.md) Part 3.

## References

- [`conformance-roadmap.md`](conformance-roadmap.md) — QUIC transport
  (9000/9001/9002), incl. the frame-retx + congestion-controller gaps.
- [`http2-backlog.md`](http2-backlog.md) — sibling app layer; HPACK is the
  QPACK cousin, shared Huffman lives between them.
- [`stack-architecture.md`](stack-architecture.md) — H3's place in the
  two-stacks convergence; the `SendStream` replay-from-offset constraint.
