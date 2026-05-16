# uni-iobuf type model — split borrowed (`!Send`) from owned (`Send`)

**Status:** spike / design note — 2026-05-16. Not yet implemented.
Sequence: a safety-quality refactor that should precede RX-path
**item C** — nothing hard-requires it (see Sequencing below).
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
shape. `into_owned()` does **not** rescue this: it returns `IOBuf` —
same type, no transition the compiler can see — so it is a runtime
copy with zero static guarantee. Manual invariants are where the
next found-by-luck bug lives (cf. the net-tcp window-update bug,
commit `171c68e`, found only because a bench anomaly got chased into
a packet capture).

## Spike findings (against the tree, 2026-05-16)

- **`Borrowed` is minted at exactly 3 sites** — all TX-path, all
  single-core synchronous, each pushes the borrowed buffer into a
  chain that is built → sent → dropped within one function:
  `uni-tls/src/lib.rs` (TLS record scratch), `uni-http/src/lib.rs`
  (response header array), `uni-runtime/src/net/tcp.rs`
  (`send_bytes` borrowing a `&[u8]`). None cross a core.
- **Chains genuinely mix** borrowed and owned parts — `uni-http`'s
  response chain holds a `Borrowed` header + `Static`/`Heap` body.
- **`Shared` is dead code.** `IOBuf::split_at` /
  `IOBufChain::split_off` — the only `Shared` producers — have
  **zero callers** outside uni-iobuf. The `Rc`-vs-`Arc` worry the
  old comment raises is moot.
- **Churn is RX-path-bounded.** Owned-side consumers are the
  item-B file set (drivers + net dispatch) plus item C's kernel
  file. The TX-heavy crates (uni-http ~66 IOBuf refs, uni-http3
  ~40, uni-tls, uni-quic) keep `IOBuf`, untouched.

## Why keep `Borrowed` at all

The split's entire cost exists to *preserve* the `Borrowed`
variant, so the honest first fork is whether to keep it:

- **Delete `Borrowed`.** The 3 mint sites copy into a `HeapStorage`
  (or draw from a per-worker pool) instead of borrowing. `IOBuf`
  then has only owning variants → uniformly `Send`, and the whole
  split is unnecessary.
- **Keep `Borrowed`** (recommended). Those 3 sites are TX
  zero-copy: a TLS record built in per-conn scratch, response
  headers rendered into a per-conn array, a caller's `&[u8]` — each
  wrapped without a copy. Deleting `Borrowed` reintroduces a
  per-response copy/alloc on the TX hot path, which the TX design
  deliberately removed.

So this split is justified *only because* `Borrowed`'s TX zero-copy
is worth keeping. It is today. If a future TX redesign eliminated
the borrow sites, the split would dissolve — worth re-checking then.

## Recommended design

Promote each ownership variant to its own struct — data *and* logic
defined once — then build two flat enums over those structs: one
permissive (`!Send`), one restricted (`Send`).

**Per-variant structs.** Each owns its storage and carries its own
offset/len arithmetic, `prepend`/`append`/`consume`, and `Drop`:
`HeapStorage`, `ExternalOwned` (already a struct), `StaticView`,
`BorrowedView` (the raw pointer + `PhantomData<*const ()>` that
makes it `!Send`). No logic is duplicated — it lives on the struct,
once.

- **`IOBuf`** — a flat enum over all four structs
  (`Heap`/`External`/`Static`/`Borrowed`), kept `!Send` by
  `BorrowedView`. `Inner` stays private; `IOBuf`'s public surface
  and behaviour are preserved, so the TX-path diff is near-zero.
  The TX path keeps using `IOBuf`.
- **`OwnedIOBuf`** — the *parallel* flat enum over the owning
  subset only (`Heap`/`External`/`Static`). No borrowing variant,
  so `Send` **auto-derives**. `wrap_owned` and `IOBufPool::alloc`
  return this; the RX path and every cross-core container traffic
  in `OwnedIOBuf`.
- Both enums are thin — each method matches and forwards to the
  struct method. `IOBuf::data()` is a *single* match, not the
  two-level dispatch a `IOBuf = enum { Owned(OwnedIOBuf),
  Borrowed(..) }` sum would have cost.
- **`into_owned(self: IOBuf) -> OwnedIOBuf`** — the typed gate.
  Match the four `IOBuf` variants: the three owning ones re-slot
  their struct into `OwnedIOBuf` (no copy); `Borrowed` copies its
  view to a `HeapStorage`. The type changes, so the compiler tracks
  it — a `Send` container's slot is `OwnedIOBuf`, the only way to
  fill it is `into_owned()`, forgetting it is a compile error, the
  copy cost is visible at the call site. `From<OwnedIOBuf> for
  IOBuf` is a 3-arm rewrap (free widening — a proxy feeds an RX
  buffer into a TX chain).
- **`IOBufChain` → generic `Chain<B>`** — a `VecDeque<B>` + cached
  length. `Chain<OwnedIOBuf>` is `Send` by derivation;
  `Chain<IOBuf>` is `!Send`.
- **`IOBufRead` trait** — the read surface (`data`, `len`,
  `headroom`, `tailroom`), implemented by `IOBuf`, `OwnedIOBuf`,
  and the structs. More than a de-dup convenience: it is the bound
  **chain consumers are generic over** — `fn consume<B: IOBufRead>(
  Chain<B>)` accepts both `Chain<OwnedIOBuf>` (RX) and `Chain<IOBuf>`
  (TX), so a proxy forwarding inbound bytes outbound needs no
  per-part rewrap. Owned and permissive are not walled-off worlds;
  the trait is the bridge.
- **Naming is by ownership, never by role.** Not `RxBuf`/`TxBuf`:
  `Send`-ness is an ownership fact, while "RX path"/"TX path" is an
  architecture items C–J are actively reshaping. A type named for a
  path mis-describes `into_owned`'s output and a proxy's forwarded
  buffer (owned, but not "from RX"), and turns every path refactor
  into a rename.
- **Delete `Shared` / `split_at` / `split_off`** — dead code;
  removes the `Rc` from uni-iobuf.

The cross-core guarantee comes from the RX path being *typed*
`OwnedIOBuf` / `Chain<OwnedIOBuf>` — a type whose value set excludes
`Borrowed`. Promoting the variants to structs enables this clean
factoring; it is not itself the enforcement. (Exposing the variant
*enum* for runtime inspection would be the opposite — a runtime
check guarding an `unsafe impl`, the discipline this split exists
to remove.)

### Deferred complement — a lifetime on `BorrowedView`

`BorrowedView<'a>` (holding the borrow's lifetime) would make
`IOBuf::borrow` a *safe* fn and obviate item F's `RecvChunkGuard`
(the RX-path doc says the guard exists *because* "IOBuf has no
lifetime parameter"). But a lifetime is **orthogonal to `Send`** —
auto-traits ignore lifetimes, so it cannot substitute for this
split — and it is viral (`IOBuf<'a>`, `Chain<'a>`, every TX-path
signature). Its payoff concentrates at item F, so decide it at the
**item-F session**, not here. This split deliberately leaves
`BorrowedView` lifetime-free.

## What this buys

- `RxInbox` (item C) holding `Chain<OwnedIOBuf>` is `Send` **by
  derivation** — the `unsafe impl Send` and the "no Borrowed parts"
  invariant both **delete**.
- A `Borrowed` buffer physically cannot reach a cross-core path: a
  compile error, not silent UB.
- The only `unsafe impl Send` left is on `ExternalOwned` — the
  genuine leaf where a raw region + drop_fn's thread-safety is
  asserted per the `wrap_owned` contract. One localized, documented
  `unsafe` at the real boundary, replacing scattered container-level
  `unsafe impl`s guarded by human invariants.

## Why not the alternatives

- *Generic `IOBuf<O>` over an ownership marker* — does not work: a
  marker cannot make a *variant* conditionally absent, so
  `IOBuf<Owned>` could still be constructed borrowed. (The *chain*
  can be generic — it is a plain container — the IOBuf enum cannot.)
- *`OwnedIOBuf` as a newtype over `IOBuf`* — still *contains* an
  `IOBuf`, which is `!Send`, so it needs `unsafe impl Send` anyway.
  No compiler-derived `Send`.
- *Lifetime parameter `IOBuf<'a>` instead of the split* — does not
  give `Send`. Auto-traits ignore lifetimes: every `IOBuf<'a>` has
  identical `Send`-ness, and a raw pointer in the borrowing struct
  makes all of them `!Send`. A lifetime tracks borrow *validity*, a
  different axis — see the deferred complement.
- *`IOBuf` as the sum `enum { Owned(OwnedIOBuf), Borrowed(..) }`* —
  works, but nests two levels (`IOBuf::data()` → `OwnedIOBuf` →
  variant). The per-variant-struct factoring keeps `IOBuf` a flat
  enum: one dispatch, and `IOBuf`'s shape barely changes.
- *Keep one `!Send` `IOBuf`, gate the cross-core path with a
  runtime variant check* — a runtime guarantee, not a static one
  (the class rejected for `into_owned`); also forces `Inner` public,
  freezing uni-iobuf's representation as API.

## Sequencing, effort, risk

- **Nothing hard-requires this split.** Item C works today with an
  `unsafe impl Send for RxInbox` + the documented "no Borrowed
  parts" invariant; item F's guard needs *owned* bytes (no dangling
  borrow), which `into_owned -> IOBuf` already gives — F is
  per-conn, per-core, so it does not need `Send`. The split's value
  is converting that `unsafe`+invariant into a compiler-checked
  guarantee. It is a *safety-quality* refactor, motivated by item
  C's genuinely cross-core inbox.
- **Sequence:** precede item C, so C's inbox is born
  `Send`-by-derivation rather than `unsafe`-with-invariant. (If C
  ships first it carries the documented `unsafe impl`, which this
  work later deletes — acceptable, just wasteful.)
- **Atomic, like item B.** `wrap_owned` / `IOBufPool::alloc` / the
  `NicOps` callback all change signature across crate boundaries,
  so the uni-iobuf change and the RX-path port land in one commit
  (the workspace will not build between them); docs separate.
- **Effort:** medium. Extract the variant structs, add `OwnedIOBuf`
  + `IOBufRead` + generic `Chain<B>`, port the RX path (drivers +
  net + kernel — the item-B file set). `IOBuf`'s public surface and
  the TX path are preserved.
- **Risk:** low–medium — but it re-touches freshly-landed item B
  driver code; the item-B test suite (`test_hvf`, the mock-driver
  test, the on-demand-VM GCE flow) is the safety net.
