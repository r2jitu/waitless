# Networking dispatch

Two dispatch modes, picked at NIC bring-up based on `num_queue_pairs`:

**Tier 1 (multi-queue).** Each core polls its own RX queue pair
directly. No distributor, no `RX_LOCK`, no inbox. TX goes through
per-core queue pairs with deferred kick. Activated when the NIC
negotiates `num_queue_pairs > 1`.

**Tier 2 (single-queue).** Core 0 polls the NIC, classifies frames by
flow hash, and distributes to per-core RX inboxes. APs drain their
inbox and process packets. TX from APs goes through staging buffers
that core 0 flushes.

See the `WAKEUP` / `RX_LOCK` / `JUST_DISTRIBUTED` statics in
[`net/lib.rs`](../net/lib.rs) for the Tier 2 coordination primitives.
