# Networking dispatch

Two dispatch modes, picked at NIC bring-up based on `num_queue_pairs`:

**Tier 1 (multi-queue).** Each core polls its own RX queue pair
directly. No distributor, no `RX_LOCK`, no inbox. TX goes through
per-core queue pairs with deferred kick. Activated when the NIC
negotiates `num_queue_pairs > 1`.

**Tier 2 (single-queue).** A rotating distributor — any idle core that
wins the `RX_LOCK` CAS, not a fixed core 0 — polls the NIC, classifies
frames by flow hash, and routes each to its owning core: a frame the
distributor itself owns is delivered inline; one owned by another core
is moved into that core's RX inbox. The owning core drains its inbox
and processes the frame. TX from a non-distributor core goes through
staging buffers that the distributor flushes. Activated when the NIC
negotiates `num_queue_pairs == 1` on a multi-core boot.

See the `WAKEUP` / `RX_LOCK` / `JUST_DISTRIBUTED` statics in
[`crates/net/stack/src/sched.rs`](../crates/net/stack/src/sched.rs)
for the Tier 2 coordination primitives (`sched` owns RX poll
scheduling; the RX pipeline itself is `rx`).

See also [`stack-architecture.md`](stack-architecture.md) for the
inter-layer API/contract lens (buffer currency, stream trait, handler
API) — that doc proposes future contracts; this one describes dispatch
as it works today.
