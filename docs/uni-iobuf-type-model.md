# uni-iobuf type model — split borrowed (`!Send`) from owned (`Send`)

**Status:** spike / design note — 2026-05-16. Not yet implemented.
Sequence: land before RX-path **item F** (see
[`rx-path-optimizations.md`](rx-path-optimizations.md)).

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
  So `IOBufChain` cannot simply "become `Send`."
- **`Shared` is dead code.** `IOBuf::split_at` /
  `IOBufChain::split_off` — the only `Shared` producers — have
  **zero callers** outside uni-iobuf. The comment justifying
  `Shared`'s `Rc` ("`Rc` not `Arc` because `IOBuf` is `!Send`") is
  optimizing dead code, so the `Rc`-vs-`Arc` question is **not a
  blocker**.
- **Two chain roles, cleanly separable by use:**
  - *TX send-chains* — ephemeral, single-core, may hold `Borrowed`
    parts, dropped at function exit. `!Send` is correct and fine.
  - *RX delivery chains* — produced by the driver, all
    `ExternalOwned`, cross cores from item C onward. Need `Send`.
- **Churn is RX-path-bounded.** Owned-side consumers are the
  item-B file set (drivers + net dispatch) plus item C's kernel
  file. The TX-heavy crates (uni-http ~66 IOBuf refs, uni-http3
  ~40, uni-tls, uni-quic) stay on `IOBuf`, untouched.

## Recommended design

Asymmetric split — add a *restricted* owned type; keep the existing
type as the *permissive* one.

- **`OwnedIOBuf`** — `enum { Heap, Static, ExternalOwned }`, no
  `Borrowed` variant, so `Send` **auto-derives** (no `unsafe impl`).
  Drivers' `wrap_owned` and `IOBufPool::alloc` return this; the RX
  path and every cross-core container traffic in `OwnedIOBuf` only.
- **`IOBuf`** — unchanged: permissive, `!Send`, keeps `Borrowed`.
  The TX path keeps using it.
- **`into_owned(self: IOBuf) -> OwnedIOBuf`** — now a *typed gate*.
  The type changes, so the compiler tracks it: a `Send` container's
  slot is `OwnedIOBuf`, the only way to fill it is `into_owned()`,
  forgetting it is a compile error, and the copy cost is visible at
  the call site. `From<OwnedIOBuf> for IOBuf` gives free widening
  (a proxy can feed an RX buffer into a TX chain).
- **`IOBufChain` → generic `Chain<B>`.** A chain is just a
  `VecDeque<B>` + cached length — genericity works cleanly here
  (unlike the `IOBuf` enum, where a variant cannot be conditionally
  absent). `Chain<OwnedIOBuf>` is `Send` by derivation;
  `Chain<IOBuf>` is `!Send`. RX delivers `Chain<OwnedIOBuf>`; TX
  builds `Chain<IOBuf>`. One chain impl, two `Send` outcomes.
- **Shared read surface** via an `IOBufRead` trait (`data`, `len`,
  `headroom`, `tailroom`) implemented by both. `OwnedIOBuf` is
  restricted, so it needs little beyond construct + read + `Drop`.
- **`Shared` / `split_at` / `split_off`:** dead today. At
  implementation time either delete them (YAGNI) or, if kept for a
  future copy-free split, back `Shared` with `Arc`. No live perf
  cost either way — nothing calls them.

### What this buys

- `RxInbox` (item C) holding `Chain<OwnedIOBuf>` is `Send` **by
  derivation** — the `unsafe impl Send` *and* the "no Borrowed
  parts" invariant both **delete**. Same for the item F/G
  `RecvChunkGuard`.
- A `Borrowed` buffer physically cannot reach a cross-core path: a
  compile error, not silent UB.

### Why not the alternatives

- *Generic `IOBuf<O>` over an ownership marker* — does not work: a
  marker cannot make the `Borrowed` *variant* conditionally absent,
  so `IOBuf<Owned>` could still be constructed borrowed. (The
  *chain* can be generic — it is a plain container — the IOBuf enum
  cannot.)
- *`OwnedIOBuf` as a newtype over `IOBuf`* — still *contains* an
  `IOBuf`, which is `!Send`, so it needs `unsafe impl Send` anyway.
  No compiler-derived `Send`. Same disease.

## Sequencing, effort, risk

- **Must land before item F** — F's `RecvChunkGuard::into_owned()`
  is a real gate (not discipline) only with the typed conversion.
- **Relative to item C:** ideally before C, so C's inbox is born
  `Send`-by-derivation. Acceptable after C — C ships with the
  documented `unsafe impl Send for RxInbox`, and this work then
  deletes it. Do not reorder C for this.
- **Effort:** medium. New `OwnedIOBuf` (~150 LOC), generic-ize the
  chain, port the RX path (drivers + net + kernel — the item-B file
  set). TX path untouched.
- **Risk:** low–medium. The split is mechanical; the soundness it
  *adds* is the point. Main care: the `IOBufRead` trait surface,
  and not regressing TX-path ergonomics.
