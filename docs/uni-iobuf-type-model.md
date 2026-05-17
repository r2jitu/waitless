# uni-iobuf type model — split borrowed (`!Send`) from owned (`Send`)

**Status:** **Landed 2026-05-16.** Three commits: `fb755a3` (prep —
deleted the dead `Shared` variant + `split_at` / `split_off`),
`409b5dd` (additive — the per-variant storage structs + `OwnedIOBuf`
/ `IOBufRead` / generic `Chain<B>`; the whole workspace still
builds), and `d8b4c1e` (the atomic flip — `wrap_owned` /
`IOBufPool::alloc` now return `OwnedIOBuf`, and the `NicOps` RX
callback + all three drivers + net dispatch are typed
`Chain<OwnedIOBuf>`). RX-path **item C** then built its cross-core
`RxInbox<T: Send>` on top — `Send` by derivation, no `unsafe impl
Send`, no human-maintained "no `Borrowed` parts" invariant.
[`rx-path-optimizations.md`](rx-path-optimizations.md) has the plan.

## Problem

`IOBuf` is one type with two ownership models. `Inner` has five
variants — four owning (`Heap`, `Shared`, `Static`, `ExternalOwned`)
and one borrowing (`Borrowed`). `Borrowed` carries a
`PhantomData<*const ()>`, which makes the **whole enum `!Send`** — so
`ExternalOwned`'s `unsafe impl Send` is dead weight: `IOBuf` as a
type is `!Send` regardless.

Every cross-core use therefore needs a manual `unsafe impl Send` on
the *container* plus a human-maintained invariant — "no `Borrowed`
part reaches here." RX-path item C's `RxInbox` is exactly that
shape. Manual invariants are where the next found-by-luck bug lives
(cf. the net-tcp window-update bug, commit `171c68e`, found only
because a bench anomaly got chased into a packet capture).

## Spike findings (against the tree, 2026-05-16)

- **`Borrowed` is minted at exactly 3 sites** — all TX-path, all
  single-core synchronous, each pushes the borrowed buffer into a
  chain built → sent → dropped within one function: `uni-tls`
  (TLS record scratch), `uni-http` (response header array),
  `uni-runtime` (`send_bytes` borrowing a `&[u8]`). None cross a
  core.
- **Chains genuinely mix** borrowed and owned parts — `uni-http`'s
  response chain holds a `Borrowed` header + `Static`/`Heap` body.
- **`Shared` is dead code** — `IOBuf::split_at` /
  `IOBufChain::split_off`, its only producers, have zero callers.
- **TX never crosses a core.** `async_try_send_chain` serializes
  the chain on the connection's owning core; Tier 2 shares only the
  TX descriptor ring (under `TX_LOCK`) and a deferred doorbell — no
  `IOBuf` moves between cores. Only RX crosses (the Tier 2
  distributor → `RxInbox`).
- **Churn is RX-path-bounded.** Owned-side consumers are the
  item-B file set (drivers + net dispatch) + item C's kernel file.
  The TX-heavy crates (uni-http, uni-http3, uni-tls, uni-quic) keep
  `IOBuf`.

## Why keep `Borrowed` at all

The split's whole cost exists to *preserve* `Borrowed`, so the
honest first fork is whether to keep it:

- **Delete `Borrowed`.** The 3 mint sites copy into a `HeapStorage`
  (or draw from a per-worker pool). `IOBuf` then has only owning
  variants → uniformly `Send`, and the split is unnecessary.
- **Keep `Borrowed`** (recommended). Those 3 sites are TX
  zero-copy — a TLS record in per-conn scratch, headers rendered
  into a per-conn array, a caller's `&[u8]`, each wrapped without a
  copy. Deleting `Borrowed` reintroduces a per-response copy on the
  TX hot path that the TX design deliberately removed.

The split is justified *only because* `Borrowed`'s TX zero-copy is
worth keeping. If a future TX redesign eliminated the borrow sites,
the split would dissolve — re-check then.

## Recommended design

Promote each ownership variant to its own struct — data *and* logic
defined once — then build two flat enums over those structs.

**Per-variant structs.** Each owns its storage and carries its own
offset/len arithmetic, `prepend`/`append`/`consume`, and `Drop`:
`HeapStorage`, `ExternalOwned` (already a struct), `StaticView`,
`BorrowedView` (the raw pointer + `PhantomData<*const ()>` that
makes it `!Send`). The per-variant *logic* is written once on the
struct; the two enums below each *forward* to it (dispatch is
written twice — thin, mechanical, macro-able — but only dispatch).

- **`IOBuf`** — a flat `!Send` enum over all four structs. `Inner`
  stays private; `IOBuf`'s public surface is preserved, so the
  TX-path diff is near-zero. The TX path keeps `IOBuf` — including
  `IOBufWriter`, the `fmt::Write` render adapter, which stays
  `IOBuf`-typed.
- **`OwnedIOBuf`** — a flat enum over **`{Heap, External}`** only;
  `Send` **auto-derives** (no `Borrowed`). `Static` is excluded as
  a modelling choice, *not* a `Send` requirement (`Static` is
  itself `Send`): a `&'static [u8]` is an *immortal borrow*, not
  owned storage, so it stays in `IOBuf` with the other non-owning
  view. Both remaining variants happen to be writable, so
  `OwnedIOBuf` could later expose an infallible `data_mut()` — but
  treat that as a latent affordance, not a motivation: it would
  require tightening `wrap_owned`'s safety contract from
  "exclusively-owned" to "exclusively-owned **and writable**"
  (exclusive ≠ writable), and no RX-path site mutates an
  `OwnedIOBuf` today.
- **`Static` lives only in `IOBuf`.** Static bodies (HTML literals,
  the QPACK table) are TX-path; no cross-core path carries a
  `Static`, so excluding it from the owned type costs that path
  nothing.

**Conversions are one-way.**

- **Widening — `From<OwnedIOBuf> for IOBuf`.** The only conversion
  the split adds, exercised at the **app RX API boundary**: a
  `BodyReader` spans RX-buffer-backed chunks (`OwnedIOBuf`) and
  prebuf-backed chunks (`Borrowed`) *within one body*, so it holds
  `IOBuf`; RX buffers widen in. Infallible, and applied
  **per-chunk** — as each `OwnedIOBuf` surfaces from `recv_chunk`,
  O(1) each. It must *not* be applied eagerly to a whole
  `Chain<OwnedIOBuf>`: that would be an O(parts) re-tag + `VecDeque`
  realloc on the RX hot path.
- **No narrowing.** Nothing converts `IOBuf → OwnedIOBuf`. The
  cross-core path is *born* `OwnedIOBuf` — `wrap_owned` /
  `IOBufPool::alloc` produce it, and it stays `OwnedIOBuf` through
  the `NicOps` callback, net dispatch, and `RxInbox`. Compile-time
  cross-core safety is that **native typing**, not a conversion
  gate: a `Borrowed` buffer can't enter the path because the path's
  type is `OwnedIOBuf` and no constructor of `OwnedIOBuf` takes a
  borrow. `From<IOBuf> for OwnedIOBuf` is not built.

- **`into_owned` is unchanged** — it stays item A's `IOBuf → IOBuf`
  (copy `Borrowed` to `Heap`, others untouched). It is *not* the
  cross-core gate; it is a cross-*time* tool — a handler retaining
  body bytes past the point the parse-buf / `pt_buf` is overwritten
  materializes the borrow so it outlives its source. Orthogonal to
  the split.

- **`IOBufChain → Chain<B>`** — a `VecDeque<B>` + cached length;
  `B: IOBufRead` throughout (maintaining the cached `total_len`
  alone needs `B::len()`). `Chain<OwnedIOBuf>` is `Send` by
  derivation; `Chain<IOBuf>` is `!Send`. Keep `type IOBufChain =
  Chain<IOBuf>` for a near-zero TX-path diff.
- **`IOBufRead` trait** — the **read** surface (`data`, `len`,
  `headroom`, `tailroom`), implemented by `IOBuf`, `OwnedIOBuf`,
  and the structs. It is the bound *read-only* chain consumers are
  generic over: `fn consume<B: IOBufRead>(Chain<B>)` accepts both
  `Chain<OwnedIOBuf>` (RX) and `Chain<IOBuf>` (TX). Caveats: (a) it
  is read-only — mutating consumers (TLS seal appends an AEAD tag,
  partial-send `consume`, a re-framing proxy) need more; RX-path
  consumers happen to be read-only so `IOBufRead` suffices there,
  and TX mutation stays concrete-typed. (b) The "consumers are
  generic, no rewrap" bridge covers read-only consumption and
  *verbatim* relay; a proxy that **re-frames** (prepends fresh
  outbound headers) needs front-part headroom or a `Chain<IOBuf>`
  rewrap — it is not rewrap-free.
- **Naming by ownership, never by role.** Not `RxBuf`/`TxBuf`:
  `Send`-ness is an ownership fact, while "RX path"/"TX path" is an
  architecture items C–J reshape. A path-named type mis-describes a
  proxy's forwarded buffer and turns every path refactor into a
  rename.
- **Delete `Shared` / `split_at` / `split_off`** — dead code;
  removes the `Rc` from uni-iobuf.

The cross-core guarantee is the RX path being *typed* `OwnedIOBuf`.
Promoting the variants to structs enables the clean factoring; it
is not itself the enforcement.

## Deferred complement — a lifetime on `BorrowedView`

`BorrowedView<'a>` would make `IOBuf::borrow` a *safe* fn and
obviate item F's `RecvChunkGuard`. But a lifetime is orthogonal to
`Send` (auto-traits ignore lifetimes) and viral. Decide it at the
**item-F session**; this split leaves `BorrowedView` lifetime-free.

## Cross-core TX — future, not now

TX is single-core today, both tiers. If TX ever went cross-core
(a work-stealing executor, a dedicated TX core), the type machinery
already covers it — a cross-core TX chain is just `Chain<OwnedIOBuf>`
— and the only addition is the narrowing this design omits
(`Chain<IOBuf> → Chain<OwnedIOBuf>`, materializing `Borrowed`/
`Static` parts to `Heap`). Strategy then mirrors the DQO/GQI split:
*convert-at-crossing* (rare) vs *owned-from-origin pool* (common).
Note `Borrowed` parts must copy at the crossing — re-opening the
"Why keep `Borrowed`" fork — and `Static` parts too, even though
`Static` is already `Send`: the tell that cross-core TX wants a
*`Send` superset* (`{Heap, External, Static}`), distinct from
`OwnedIOBuf`'s *owned* set.

## What this buys

- `RxInbox` (item C) holding `Chain<OwnedIOBuf>` is `Send` **by
  derivation** — the `unsafe impl Send` and the "no Borrowed parts"
  invariant both **delete**.
- A `Borrowed` buffer physically cannot reach a cross-core path: a
  compile error, not silent UB.
- The only `unsafe impl Send` left is on `ExternalOwned` — the
  genuine leaf where a raw region + drop_fn's thread-safety is
  asserted per the `wrap_owned` contract. One localized, documented
  `unsafe`, replacing scattered container-level `unsafe impl`s.

## Why not the alternatives

- *Generic `IOBuf<O>` over an ownership marker* — a marker cannot
  make a *variant* conditionally absent.
- *`OwnedIOBuf` as a newtype over `IOBuf`* — still contains a
  `!Send` `IOBuf`; needs `unsafe impl Send` anyway.
- *Lifetime `IOBuf<'a>` instead of the split* — auto-traits ignore
  lifetimes; it cannot give `Send`.
- *`IOBuf` as the sum `enum { Owned(OwnedIOBuf), Borrowed(..) }`* —
  works, but nests two dispatch levels. The per-variant-struct
  factoring keeps `IOBuf` a flat enum: one dispatch.
- *Keep one `!Send` `IOBuf`, gate the cross-core path with a
  runtime variant check* — runtime, not static; also forces
  `Inner` public, freezing the representation as API.

## Sequencing, effort, risk

- **Nothing hard-requires this split.** Item C works with an
  `unsafe impl Send for RxInbox` + the documented invariant; item
  F's guard needs *owned* (not `Send`) bytes. The split converts
  `unsafe`+invariant into a compiler-checked guarantee — a
  safety-quality refactor, motivated by item C's cross-core inbox.
- **Sequence:** precede item C, so its inbox is born
  `Send`-by-derivation. (If C ships first it carries the documented
  `unsafe impl`, which this work deletes — acceptable, wasteful.)
- **Two code commits, not one.** The uni-iobuf *internal* refactor
  — extract the variant structs, add `OwnedIOBuf` / `IOBufRead` /
  generic `Chain<B>`, keep `IOBuf`'s API and `IOBufChain =
  Chain<IOBuf>` — is **additive**: `wrap_owned` still returns
  `IOBuf`, the whole workspace builds. It lands as its own
  reviewable commit. Only the *flip* (`wrap_owned`/`alloc →
  OwnedIOBuf`, the `NicOps` callback, the RX-path port) is atomic.
  Docs separate.
- **Effort:** medium. `IOBuf`'s public surface and the TX path are
  preserved.
- **Risk:** low–medium — it re-touches freshly-landed item B driver
  code; the item-B test suite (`test_hvf`, the mock-driver test,
  the on-demand-VM GCE flow) is the safety net.
