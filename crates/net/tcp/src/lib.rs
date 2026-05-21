// net/tcp — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.
//
// Module shape:
//   * [`state`]      — per-conn TCB (`TcpConnection`), the on-wire
//                      [`state::TcpHeader`], TCP-flag/MSS/RTO constants,
//                      and the RFC 6298 retransmission methods that
//                      live on the TCB.
//   * [`pool`]       — segmented per-core slot pool, the 4-tuple
//                      open-addressed hash index, connection-handle
//                      encoding, allocate/free, diagnostic counters.
//   * [`send`]       — outbound segment assembly: the unified
//                      ETH+IP+TCP frame builder, `send_segment`,
//                      `send_rst`, TSO super-segments, and the
//                      `async_try_send_chain` send-side reactor hook.
//   * [`receive`]    — `tcp_receive` — the inbound entry point and
//                      state-machine driver.
//   * [`retransmit`] — RFC 6298 per-core tick (`on_rtx_tick`) +
//                      `has_armed_rtx_timers` idle gate.
//   * [`listener`]   — the rest of the public TCP API the
//                      `executor::reactor::tcp` backend wires into:
//                      `init`, `listen_on_core`, `accept_on_port`,
//                      `close`, `shutdown_all`, the recv/send waker +
//                      buffer-slot hooks, `do_recv_chunk`.
//   * [`tests`]      — `#[cfg(test)]` packetdrill-style conformance
//                      harness. Same compilation unit as the rest of
//                      the crate so the bazel `rust_test(crate = ":tcp")`
//                      target picks it up.

#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate net_checksum as checksum;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

mod listener;
mod pool;
mod receive;
mod retransmit;
mod send;
mod state;

#[cfg(test)]
mod tests;

// Public API — preserves the pre-split surface so consumers (`net_stack`,
// `executor::reactor::tcp` backend, `waitless_backend::bare`) compile
// unchanged.
pub use listener::{
    accept_on_port, async_recv, clear_chunk_buf_slot, clear_recv_buf_slot, clear_recv_waker,
    clear_send_waker, close, do_recv_chunk, init, is_readable_or_closed, listen_on_core,
    register_recv_waker, register_send_waker, set_chunk_buf_slot, set_recv_buf_slot, shutdown_all,
};
pub use pool::{RX_CHUNK_RING_DRAIN, RX_CHUNK_STASH_HITS, TCP_SYN_RX, TCP_SYNACK_TX};
pub use receive::tcp_receive;
pub use retransmit::{has_armed_rtx_timers, on_rtx_tick};
pub use send::{async_try_send_chain, try_send_tso};
pub use state::{TcpConnection, TcpState};

// Surface the crate-internal items the `#[cfg(test)]` harness reaches
// for via `use super::*;`. None of these are part of the published
// public API — `pub(crate)` re-exports keep them visible to the
// tests file (which lives a level below this) without widening the
// real surface.
#[cfg(test)]
pub(crate) use pool::{conn_ptr, encode_handle, pool_capacity};
#[cfg(test)]
pub(crate) use send::TCP_HDR_LEN;
#[cfg(test)]
pub(crate) use state::{
    RTO_INITIAL_MS, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpHeader,
};
