// drivers/net.rs — NIC dispatch shim.
//
// There are now two drivers in this crate (virtio-net and gVNIC).
// Only one can be active on a given boot: virtio-net when the
// instance was launched with a virtio NIC, gVNIC when it was
// launched with `--network-interface=nic-type=GVNIC`. The rest of
// the system (net/, boot/, uni/) shouldn't care which — it just
// wants `poll`, `send`, `get_mac`, etc. to do the right thing.
//
// This module is that "which" decision in one place. Each public
// function checks `gvnic::probe_ok()` (which flips to `true` at
// the end of `gvnic::init()` on a successful bring-up) and
// dispatches; virtio-net wins by default when gVNIC didn't come
// up. Everything is inlined so the extra branch is a one-cycle
// tax on the hot path.
//
// Virtio-specific knobs (MSI-X, TX staging, NAPI idle) become
// no-ops when gVNIC is the active driver — gVNIC is polling-only
// in Phase 2 and has no TX staging pool, so the callers' contracts
// are already satisfied.

use crate::{gvnic, virtio_net};

#[inline]
fn use_gvnic() -> bool {
    gvnic::probe_ok()
}

// ---- Init / lifecycle -----------------------------------------------------

/// Probe both drivers. Tries gVNIC first (the preferred NIC on
/// GCE — native RSS multi-queue). Falls back to virtio-net, which
/// is what kvm-vm, HVF, and default-GCE instances expose.
/// Returns `true` if either driver came up.
pub fn init() -> bool {
    if gvnic::init() {
        return true;
    }
    virtio_net::init()
}

pub fn get_mac(mac_out: *mut u8) {
    if use_gvnic() {
        gvnic::get_mac(mac_out)
    } else {
        virtio_net::get_mac(mac_out)
    }
}

pub fn num_queue_pairs() -> u16 {
    if use_gvnic() {
        gvnic::num_queue_pairs()
    } else {
        virtio_net::num_queue_pairs()
    }
}

pub fn activate_multi_queue() {
    // gVNIC has a different multi-queue model (CONFIGURE_RSS +
    // per-core queues are set up at driver init, Phase 4). On the
    // virtio-net path this triggers the legacy ctrl-vq MQ dance.
    if !use_gvnic() {
        virtio_net::activate_multi_queue();
    }
}

pub fn enable_irq() {
    // Virtio-net registers MSI-X vectors here. gVNIC is polling-only
    // for now — if interrupt support lands later it'll be wired up
    // inside `gvnic::init()` instead.
    if !use_gvnic() {
        virtio_net::enable_irq();
    }
}

// ---- RX / TX datapath -----------------------------------------------------

pub fn poll(callback: fn(&[u8])) -> i32 {
    if use_gvnic() {
        gvnic::poll(callback)
    } else {
        virtio_net::poll(callback)
    }
}

pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    if use_gvnic() {
        gvnic::poll_qp(qp, callback)
    } else {
        virtio_net::poll_qp(qp, callback)
    }
}

pub fn send(data: &[u8]) {
    if use_gvnic() {
        gvnic::send(data);
    } else {
        virtio_net::send(data)
    }
}

// ---- Virtio-only knobs — no-op on gVNIC ----------------------------------

pub fn flush_tx_staging() {
    if use_gvnic() {
        // gVNIC has no staging queue; the doorbell-coalesced path
        // may have dirty queues across cores, so flush everything.
        gvnic::flush_all_tx_kicks();
    } else {
        virtio_net::flush_tx_staging();
    }
}

pub fn flush_tx_kick_if_dirty() -> bool {
    if use_gvnic() {
        gvnic::flush_tx_kick_if_dirty()
    } else {
        virtio_net::flush_tx_kick_if_dirty()
    }
}

pub fn irq_idle_supported() -> bool {
    // gVNIC does not (yet) support NAPI-style idle: the event loop
    // keeps polling. Return false here so the caller's idle-path
    // fallback stays engaged.
    if use_gvnic() {
        false
    } else {
        virtio_net::irq_idle_supported()
    }
}

pub fn arm_rx_interrupts() {
    if !use_gvnic() {
        virtio_net::arm_rx_interrupts();
    }
}

pub fn has_pending_rx() -> bool {
    if use_gvnic() {
        false
    } else {
        virtio_net::has_pending_rx()
    }
}

pub fn has_pending_tx() -> bool {
    if use_gvnic() {
        false
    } else {
        virtio_net::has_pending_tx()
    }
}

pub fn rearm_rx_napi(core_id: u32) -> bool {
    if use_gvnic() {
        false
    } else {
        virtio_net::rearm_rx_napi(core_id)
    }
}

pub fn enable_deferred_tx_kick() {
    if use_gvnic() {
        gvnic::enable_deferred_tx_kick();
    } else {
        virtio_net::enable_deferred_tx_kick();
    }
}

pub fn poke_interrupt_status() {
    if !use_gvnic() {
        virtio_net::poke_interrupt_status();
    }
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    if use_gvnic() {
        gvnic::rx_counts()
    } else {
        virtio_net::rx_counts()
    }
}

pub fn rx_used_cursors() -> [(u16, u16); 8] {
    if use_gvnic() {
        gvnic::rx_used_cursors()
    } else {
        virtio_net::rx_used_cursors()
    }
}
