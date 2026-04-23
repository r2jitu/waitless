// uni-runtime/src/select.rs — `join`, `select`, and their macros.
//
// Small `!Send`-friendly combinators over `Future`. Implemented as
// plain futures (no executor hooks) so they work unchanged on both
// native and bare-metal. The polling strategy is dumb-but-correct:
// on each outer poll, walk the children in order and poll whichever
// are still live. The Waker delivered to each child is the outer
// Context's Waker — wakes propagate naturally through our
// slot-bitmap executor with no per-combinator bookkeeping.
//
// Size: each combinator's future is essentially a tuple of
// `Option<Fut>` (for join — we replace with None once Ready so the
// next poll skips it) or raw pinned children (select — drops all
// on Ready).

use core::future::Future;
use core::pin::pin;
use core::task::Poll;

/// Two-way selection — returns whichever future completes first,
/// dropping the other. Left/Right biased in poll order.
#[derive(Debug, PartialEq, Eq)]
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

/// Three-way selection for code that wants a drop-in without
/// wrapping in nested `Either`s. Returns which arm fired.
#[derive(Debug, PartialEq, Eq)]
pub enum Three<A, B, C> {
    A(A),
    B(B),
    C(C),
}

/// Await two futures concurrently; resolve when both complete.
/// Poll order is fixed (a, then b); the executor handles wake-ups
/// so neither side starves.
pub async fn join<A, B>(a: A, b: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut ra: Option<A::Output> = None;
    let mut rb: Option<B::Output> = None;
    core::future::poll_fn(move |cx| {
        if ra.is_none() {
            if let Poll::Ready(v) = a.as_mut().poll(cx) {
                ra = Some(v);
            }
        }
        if rb.is_none() {
            if let Poll::Ready(v) = b.as_mut().poll(cx) {
                rb = Some(v);
            }
        }
        match (ra.take(), rb.take()) {
            (Some(av), Some(bv)) => Poll::Ready((av, bv)),
            (a_opt, b_opt) => {
                ra = a_opt;
                rb = b_opt;
                Poll::Pending
            }
        }
    })
    .await
}

/// Await three futures concurrently; resolve when all three
/// complete. Slightly wider workhorse for fan-out patterns.
pub async fn join3<A, B, C>(a: A, b: B, c: C) -> (A::Output, B::Output, C::Output)
where
    A: Future,
    B: Future,
    C: Future,
{
    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut c = pin!(c);
    let mut ra: Option<A::Output> = None;
    let mut rb: Option<B::Output> = None;
    let mut rc: Option<C::Output> = None;
    core::future::poll_fn(move |cx| {
        if ra.is_none() {
            if let Poll::Ready(v) = a.as_mut().poll(cx) {
                ra = Some(v);
            }
        }
        if rb.is_none() {
            if let Poll::Ready(v) = b.as_mut().poll(cx) {
                rb = Some(v);
            }
        }
        if rc.is_none() {
            if let Poll::Ready(v) = c.as_mut().poll(cx) {
                rc = Some(v);
            }
        }
        match (ra.take(), rb.take(), rc.take()) {
            (Some(av), Some(bv), Some(cv)) => Poll::Ready((av, bv, cv)),
            (a_opt, b_opt, c_opt) => {
                ra = a_opt;
                rb = b_opt;
                rc = c_opt;
                Poll::Pending
            }
        }
    })
    .await
}

/// Race two futures; return whichever completes first. The loser
/// is dropped at the point the winner resolves — any cleanup lives
/// in its `Drop` impl (e.g. `TcpRecv::drop` would clear a parked
/// waker there if we add one).
pub async fn select<A, B>(a: A, b: B) -> Either<A::Output, B::Output>
where
    A: Future,
    B: Future,
{
    let mut a = pin!(a);
    let mut b = pin!(b);
    core::future::poll_fn(move |cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

/// Race three futures. Common for "data or timer or shutdown"
/// loops without nesting Eithers.
pub async fn select3<A, B, C>(a: A, b: B, c: C) -> Three<A::Output, B::Output, C::Output>
where
    A: Future,
    B: Future,
    C: Future,
{
    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut c = pin!(c);
    core::future::poll_fn(move |cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Three::A(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Three::B(v));
        }
        if let Poll::Ready(v) = c.as_mut().poll(cx) {
            return Poll::Ready(Three::C(v));
        }
        Poll::Pending
    })
    .await
}

/// Add a timeout to a future. Resolves to `Some(v)` if the inner
/// future completes within `us` microseconds, or `None` on timeout.
pub async fn timeout_us<F>(us: u64, fut: F) -> Option<F::Output>
where
    F: Future,
{
    match select(fut, crate::sleep_us(us)).await {
        Either::Left(v) => Some(v),
        Either::Right(()) => None,
    }
}

