# util/iobuf type model — split borrowed (`!Send`) from owned (`Send`)

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
  chain built → sent → dropped within one function: `proto/tls`
  (TLS record scratch), `proto/http` (response header array),
  `runtime/executor` (`send_bytes` borrowing a `&[u8]`). None cross a
  core.
- **Chains genuinely mix** borrowed and owned parts — `proto/http`'s
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
  The TX-heavy crates (proto/http, proto/http3, proto/tls, proto/quic) keep
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

> **As-landed delta (current code).** This section captures the
> *original* proposal; the type model below it has the few places
> the landed-and-evolved code diverged folded in. Three deltas
> matter:
> 1. **`OwnedIOBuf` is a four-variant enum `{Heap, External, Shared,
>    Static}`** (`OwnedStorage` in `owned.rs`), not the proposed
>    `{Heap, External}`. `Shared` was *added* (refcounted, the
>    TCP-rtx / TLS-RX-share idiom — see below); `Static` was pulled
>    *in* rather than
>    left in `IOBuf` (a `&'static [u8]` is `Send`, so it costs the
>    owned type nothing and lets the cross-core path carry static
>    parts). All four are `Send`, so the auto-derivation holds.
> 2. **`IOBuf` is a *two-tier* enum, not a flat four-struct enum** —
>    `Owned(OwnedIOBuf)` for every owning shape + `Borrowed { view,
>    .. }` for the lone non-owning view. Every owning method forwards
>    into `OwnedIOBuf`, so the per-variant dispatch is written *once*,
>    not twice.
> 3. **Fallible narrowing exists** — `TryFrom<IOBuf> for OwnedIOBuf`
>    (errors on `Borrowed`, zero-copy for every `Owned(_)`), plus
>    `From<Vec<u8>> for OwnedIOBuf`. The *infallible* `From<IOBuf>`
>    the proposal forbade is still absent.

The landed shape promotes each *non-trivial* storage variant to its
own struct — data *and* logic defined once — then builds the two
enums above over those structs (`&'static [u8]` rides directly in an
`OwnedStorage::Static` arm, with no wrapper struct).

**Per-variant structs** (`storage.rs`). Each owns its bytes — the
visible `(offset, len)` window lives on the outer `IOBuf` /
`OwnedIOBuf`, so one storage can feed many views: `HeapStorage`,
`ExternalOwned`, `SharedRegion` (the refcounted backing the `Shared`
variant wraps in an `Arc`), and `BorrowedView` (the raw pointer +
`PhantomData<*const ()>` that makes it `!Send`). The mutating logic
(`prepend` / `append_slice` / `extend_uninit` / `data_mut`) lives on
`OwnedIOBuf`; `IOBuf` forwards into it for the owning case.

- **`IOBuf`** — the `!Send` **two-tier** enum: `Owned(OwnedIOBuf)`
  (every owning shape) + `Borrowed { view, offset, len }`. `Inner`
  stays private; `IOBuf`'s public surface is preserved, so the
  TX-path diff is near-zero. The TX path keeps `IOBuf` — including
  `IOBufWriter`, the `fmt::Write` render adapter, which stays
  `IOBuf`-typed.
- **`OwnedIOBuf`** — a flat enum over **`{Heap, External, Shared,
  Static}`**; `Send` **auto-derives** (no `Borrowed`). A latent
  `data_mut()` is *not* on the public surface: the public surface is
  read-only (the cross-core RX path doesn't mutate through
  `OwnedIOBuf`); the mutators are `pub(crate)` so `IOBuf` can forward
  to them. Exposing an infallible owned `data_mut()` would mean
  tightening `wrap_owned`'s contract from "exclusively-owned" to
  "exclusively-owned **and writable**" (exclusive ≠ writable) — which
  is exactly why `IOBufPool::alloc` owns the slab fill rather than a
  generic owned mutator.
- **`Static` rides in *both* tiers.** Static bodies (HTML literals,
  the QPACK table) are TX-path, but `&'static [u8]` is `Send`, so
  there is no reason to keep it out of the owned tier — it lives in
  `OwnedStorage::Static` and widens into `IOBuf` like any other
  owning shape.

**Conversions.** Widening is infallible; the one narrowing is
*fallible* (it refuses to silently drop a borrow).

- **Widening — `From<OwnedIOBuf> for IOBuf`.** Exercised at the **app
  RX API boundary**: a `BodyReader` spans RX-buffer-backed chunks
  (`OwnedIOBuf`) and prebuf-backed chunks (`Borrowed`) *within one
  body*, so it holds `IOBuf`; RX buffers widen in. Infallible, and
  applied **per-chunk** — as each `OwnedIOBuf` surfaces from
  `recv_chunk`, O(1) each. It must *not* be applied eagerly to a
  whole `Chain<OwnedIOBuf>`: that would be an O(parts) re-tag +
  `VecDeque` realloc on the RX hot path.
- **Fallible narrowing — `TryFrom<IOBuf> for OwnedIOBuf`** (landed;
  the proposal's "no narrowing" was superseded). Succeeds zero-copy
  for every `Owned(_)` shape; the `Err` arm hands the original
  `IOBuf` back untouched for the sole `Borrowed` variant — it
  *refuses* to make a borrow `Send` by copying behind the caller's
  back (that is what `into_owned()` is for). The canonical caller is
  the **TLS RX plaintext queue** (`proto/tls/src/server.rs`): every
  chunk it queues was `into_owned()`'d in `pump_rx` first, so the
  conversion is total there and the `Err` arm is unreachable by
  construction. There is deliberately **no** *infallible* `From<IOBuf>
  for OwnedIOBuf`. The cross-core path is still *born* `OwnedIOBuf` —
  `wrap_owned` / `IOBufPool::alloc` produce it, and it stays
  `OwnedIOBuf` through the `NicOps` callback, net dispatch, and
  `RxInbox` — so this narrowing is a *convenience for reusing the
  owned-only refcount primitives* on an already-owned `IOBuf`, not
  the cross-core safety gate (that gate is the native typing).
- **`From<Vec<u8>> for OwnedIOBuf`** — builds a `Heap`-backed
  `OwnedIOBuf`, reusing the allocation. Lets the TLS RX straddler
  path push a freshly-decrypted plaintext copy straight into the
  owning queue without round-tripping through `IOBuf`.

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
  `headroom`, `tailroom`), implemented by `IOBuf`, `OwnedIOBuf`, and
  `&[u8]` (the storage structs themselves do *not* implement it — the
  visible window lives on the outer types, not the bytes-only
  storage). It is the bound *read-only* chain consumers are generic
  over: `fn consume<B: IOBufRead>(Chain<B>)` accepts both
  `Chain<OwnedIOBuf>` (RX) and `Chain<IOBuf>` (TX). Caveats: (a) it
  is read-only — mutating consumers (TLS seal appends an AEAD tag,
  partial-send `consume`, a re-framing proxy) need more; RX-path
  consumers happen to be read-only so `IOBufRead` suffices there,
  and TX mutation stays concrete-typed. (b) The "consumers are
  generic, no rewrap" bridge covers read-only consumption and
  *verbatim* relay; a proxy that **re-frames** (prepends fresh
  outbound headers) needs front-part headroom or a `Chain<IOBuf>`
  rewrap — it is not rewrap-free.
  - The `impl IOBufRead for &[u8]` (lets `Chain<&'a [u8]>` hold raw
    slices with no `unsafe` borrow mint) currently has **no
    production consumer** — it is a latent affordance for a future
    read-only generic chain pass. See *Dead / latent surface* below.
- **Naming by ownership, never by role.** Not `RxBuf`/`TxBuf`:
  `Send`-ness is an ownership fact, while "RX path"/"TX path" is an
  architecture items C–J reshape. A path-named type mis-describes a
  proxy's forwarded buffer and turns every path refactor into a
  rename.
- **Deleted the *old* `Shared` / `split_at` / `split_off`** — the
  pre-split `Rc`-backed `Shared` variant and its split producers were
  dead code at the time and were removed (prep commit `fb755a3`).
  **`Shared` was then reintroduced**, deliberately and differently:
  an `Arc<SharedRegion>` owning variant of `OwnedIOBuf`, minted by
  `share()` and cloned by `clone_shared()` (see below). Refcounting
  is now opt-in (`Heap` / `External` stay exclusively-owned and
  atomic-free until a caller `share()`s), and `Arc` not `Rc` so the
  variant stays `Send`.

The cross-core guarantee is the RX path being *typed* `OwnedIOBuf`.
Promoting the variants to structs enables the clean factoring; it
is not itself the enforcement.

## Refcounted sharing — `share` / `clone_shared` / `narrow`

The `Shared` variant and its primitives landed for **zero-copy
shadow retention** — keeping a refcounted view of bytes a caller
already owns, without a memcpy. The set is opt-in: an unshared
`Heap` / `External` `OwnedIOBuf` is exclusively owned and pays no
atomics; a caller promotes only when it needs the shadow.

- **`share(self) -> Self`** — *move-only*, no byte copy: lifts the
  existing `HeapStorage` / `ExternalOwned` into a fresh
  `Arc<SharedRegion>`. Idempotent on `Shared` / `Static` (a static
  borrow is already immortal — clones just copy the `&'static [u8]`).
  One small `Arc` allocation.
- **`clone_shared(&self) -> Result<Self, IOBufError>`** — bumps the
  `Arc` strong count (or copies the `&'static` slice) and carries the
  same `(offset, len)` view; `Err(NotShared)` on an unshared
  non-static buffer. Mutating an aliased `Shared` CoWs into a fresh
  `Heap` (`cow_if_shared_aliased`); a uniquely-held `Arc` writes in
  place via `Arc::get_mut`.
- **`narrow(&mut self, offset, len)`** — clamps the visible window to
  an inner sub-range (`consume` then `trim_end`). Backing region and
  drop callback are **untouched**, so a narrowed buffer still reposts
  its *full* device buffer on drop — the RX L4-segment narrow (frame
  buffer → TCP segment, `net/stack/src/rx.rs`, `net/tcp/src/receive.rs`).

Both `IOBuf` and `OwnedIOBuf` expose `share` / `clone_shared`;
`IOBuf::share` first `into_owned()`s a `Borrowed` (the one-copy
path). **Canonical callers:** the TCP rtx queue
(`net/tcp/src/state.rs` — a refcounted shadow of each sent segment,
`share()` then `clone_shared()` for a boundary split) and the TLS RX
plaintext queue (`proto/tls/src/server.rs` — `OwnedIOBuf::try_from`
the chunk, `share()`, then `clone_shared()` + `narrow()` per view).

## Dead / latent surface (audit, current code)

An audit found public iobuf API with **zero production consumers** —
exercised only by the crate's own unit tests. `stack-architecture.md`
delegates the deletion decision here ("freeze the core, trim the
edges"). This is a doc-only inventory; **no code is deleted by this
review**. Verified by grep across `crates/` (matches landing only in
`iobuf/src/*.rs` tests, or on unrelated `Vec`/slice/timer-wheel
types):

- `Chain::{pull, push_with_reserve, push_string, bump_total_len,
  iter_mut, back_mut, pop_back}`
- `Cursor::{advance, position, next_chunk}`
- `impl IOBufRead for &[u8]`

Each was added speculatively (e.g. `pull` for `pskb_may_pull`-style
header coalescing; `back_mut` + `bump_total_len` for an AEAD-tag
append that the TLS path does differently; the `&[u8]` impl for a
future read-only generic chain pass). They are sound and tested, just
unused. The *load-bearing* chain/cursor surface that **does** have
production callers — `push_back`, `push_front`, `pop_front`,
`front_mut`, `shrink_total_len`, `prepend_in_place`, `push_static`,
`push_owned`, `into_parts`, `clear`, `cursor().read()`, `remaining()`
— stays. When trimming, drop the dead set and its tests together; do
not touch the live set.

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
- The only `unsafe impl Send` on a **buffer storage type** is on
  `ExternalOwned` — the genuine leaf where a raw region + drop_fn's
  thread-safety is asserted per the `wrap_owned` contract (plus a
  matching `unsafe impl Sync` so `Arc<SharedRegion>`, and thus the
  `Shared` variant, stays `Send`). One localized, documented
  `unsafe`, replacing scattered container-level `unsafe impl`s.
  (`pool.rs`'s `PoolInner` carries its own `unsafe impl Send + Sync`
  — but that is the *pool's* inner state, not an IOBuf, and its
  pointer is used only for address arithmetic + a single `Drop`-time
  `Box::from_raw`; every mutated field is an atomic.)

## Why not the alternatives

- *Generic `IOBuf<O>` over an ownership marker* — a marker cannot
  make a *variant* conditionally absent.
- *`OwnedIOBuf` as a newtype over `IOBuf`* — still contains a
  `!Send` `IOBuf`; needs `unsafe impl Send` anyway.
- *Lifetime `IOBuf<'a>` instead of the split* — auto-traits ignore
  lifetimes; it cannot give `Send`.
- *`IOBuf` as a flat enum over all four storage structs* — the
  original proposal (above), to keep `IOBuf` one dispatch level. The
  landed code chose the opposite — *`IOBuf` as the sum
  `enum { Owned(OwnedIOBuf), Borrowed { view, .. } }`* — accepting a
  second dispatch level for the owning case in exchange for writing
  the per-variant owning logic *once* (on `OwnedIOBuf`) instead of
  twice. The owning hop is a thin forward (`o.prepend(..)` etc.); the
  de-duplication won.
- *Keep one `!Send` `IOBuf`, gate the cross-core path with a
  runtime variant check* — runtime, not static; also forces
  `Inner` public, freezing the representation as API.

## Sequencing, effort, risk

*(Original-proposal planning, retained for the record — the split
landed 2026-05-16 per the Status header; the `Shared` variant and the
`TryFrom` / `From<Vec<u8>>` conversions landed after, see the
As-landed delta above.)*

- **Nothing hard-requires this split.** Item C works with an
  `unsafe impl Send for RxInbox` + the documented invariant; item
  F's guard needs *owned* (not `Send`) bytes. The split converts
  `unsafe`+invariant into a compiler-checked guarantee — a
  safety-quality refactor, motivated by item C's cross-core inbox.
- **Sequence:** precede item C, so its inbox is born
  `Send`-by-derivation. (If C ships first it carries the documented
  `unsafe impl`, which this work deletes — acceptable, wasteful.)
- **Two code commits, not one.** The util/iobuf *internal* refactor
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

## See also

- [`stack-architecture.md`](stack-architecture.md) — the inter-layer
  contracts doc; names this doc as the owner of the buffer-currency
  core (`OwnedIOBuf` / `Chain` / `Cursor`) and cites the
  `Send`-by-derivation model as the foundation to **freeze**.
- [`rx-path-optimizations.md`](rx-path-optimizations.md) — the
  cross-core RX plan (`RxInbox`, the NIC RX item set) this split was
  built to serve.
- [`high-concurrency-perf.md`](high-concurrency-perf.md) — the
  `share()`-based TCP rtx (`tcp/rtx-share`) and TLS plaintext-queue
  (`tls/rx-share-queue`) idioms that drive the `Shared` variant.
