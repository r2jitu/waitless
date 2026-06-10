// Core-affine ephemeral-port allocation for active opens.
//
// PRIMARY rule: walk candidate ports in the IANA dynamic range and
// take the first whose inbound 4-tuple maps to the CALLING core under
// `net_classify::flow_owner` — the SAME software flow hash Tier-2 RX
// classify routes with (`net_classify::owner`). The peer's replies
// then land on the connecting core on every software-distributed
// (single-queue) path — HVF, kvm-virtio — with zero cross-core
// machinery.
//
// Limitation (A3): on Tier-1 multi-queue NICs the hardware RSS hash
// is the NIC's own (Toeplitz etc.), not this software hash, so the
// reply can still be delivered to a sibling core and drop at its
// conn-lookup miss — counted there as `client_wrong_core_drops` for
// the steering phase's observability.
//
// The per-core slice of the range (49152–65535 partitioned by core
// count) is only the FALLBACK, for the pathological case where no
// candidate hashes home (can't happen with a well-mixed hash, kept as
// a defensive floor so connect never spins the full range twice).

use crate::pool::{conn_ptr, tcp_hash_find, tcp_hash_key};
use crate::state::TcpState;
use core::sync::atomic::{AtomicU16, Ordering};
use types::IpAddr;

/// First port of the IANA dynamic/private range (RFC 6335 §6).
const EPHEMERAL_LO: u16 = 49152;
/// Range size: 49152..=65535.
const EPHEMERAL_COUNT: u32 = 16384;

/// Per-core rotating cursor into the range, so consecutive connects
/// spread across ports instead of re-probing from the bottom (and a
/// just-closed port isn't immediately reused into TIME-WAIT
/// ambiguity). Single-writer per core — Relaxed is enough; the array
/// shape mirrors `receive.rs`'s challenge-ACK buckets.
static NEXT_OFFSET: [AtomicU16; obs::MAX_CORES] =
    [const { AtomicU16::new(0) }; obs::MAX_CORES];

/// Pick an ephemeral local port for a connect from `local_ip` to
/// `remote_ip:remote_port` on `core`. Skips ports whose full 4-tuple
/// is already live in this core's conn hash. `None` only if every
/// port in the range is taken for this destination.
pub(crate) fn alloc_ephemeral_port(
    core: u32,
    local_ip: IpAddr,
    remote_ip: IpAddr,
    remote_port: u16,
) -> Option<u16> {
    let num_cores = kernel_core::percpu::num_cores();
    let cursor = if (core as usize) < obs::MAX_CORES {
        NEXT_OFFSET[core as usize].load(Ordering::Relaxed) as u32
    } else {
        0
    };
    for i in 0..EPHEMERAL_COUNT {
        let off = (cursor + i) % EPHEMERAL_COUNT;
        let port = EPHEMERAL_LO + off as u16;
        if tuple_in_use(core, remote_ip, remote_port, port) {
            continue;
        }
        // The affinity test: the tuple as the peer's reply will carry
        // it — src = the remote end, dst = us — must hash to the
        // calling core. ONE hash, shared with RX classify.
        if net_classify::flow_owner(remote_ip, local_ip, remote_port, port, num_cores) == core {
            if (core as usize) < obs::MAX_CORES {
                NEXT_OFFSET[core as usize]
                    .store(((off + 1) % EPHEMERAL_COUNT) as u16, Ordering::Relaxed);
            }
            return Some(port);
        }
    }
    // Fallback: this core's slice of the range, affinity unchecked.
    // Reaching here means the flow hash never mapped ANY free port
    // home — effectively impossible with `fmix32` mixing; kept so a
    // hash pathology degrades to "may need A3 steering" instead of
    // "connect always fails".
    let slice = EPHEMERAL_COUNT / num_cores.max(1);
    let base = (core % num_cores.max(1)) * slice;
    for i in 0..slice {
        let port = EPHEMERAL_LO + (base + i) as u16;
        if !tuple_in_use(core, remote_ip, remote_port, port) {
            return Some(port);
        }
    }
    None
}

/// Is the full 4-tuple `(remote_ip, remote_port, local=port)` already
/// live on this core? Probes the per-core conn hash (the same index
/// both passive and active conns publish into) and re-verifies the
/// tuple fields, exactly as the RX lookup does. A conn past the
/// 32K-entry hash overflow is invisible here — at that point port
/// collisions are the least of the box's problems, and the SYN-time
/// stale-twin scan still keeps one conn per tuple.
fn tuple_in_use(core: u32, remote_ip: IpAddr, remote_port: u16, port: u16) -> bool {
    tcp_hash_find(core, tcp_hash_key(remote_ip, remote_port, port)).is_some_and(|s| {
        // SAFETY: per-core ownership — the connecting core probes its
        // own pool.
        let c = unsafe { &*conn_ptr(core, s) };
        c.state != TcpState::Closed
            && c.remote_ip == remote_ip
            && c.remote_port == remote_port
            && c.local_port == port
    })
}
