// drivers/net.rs — NIC dispatch shim.
//
// Two drivers live in this crate: `virtio_net` and `gve` (Google's
// Virtual Ethernet driver, the product of which is branded "gVNIC"
// at the GCE layer — the driver is `gve` in Linux, Google's own
// codebase, and now ours). Only one can be active on a given boot:
// virtio-net when the instance was launched with a virtio NIC,
// `gve` when it was launched with `--network-interface=nic-type=GVNIC`.
// The rest of the system (net/, boot/, uni/) shouldn't care which —
// it just wants `poll`, `send`, `get_mac`, etc. to do the right
// thing.
//
// This module is that "which" decision in one place. Each public
// function checks `gve::probe_ok()` (which flips to `true` at the
// end of `gve::init()` on a successful bring-up) and dispatches;
// virtio-net wins by default when `gve` didn't come up. Everything
// is inlined so the extra branch is a one-cycle tax on the hot
// path.
//
// Virtio-specific knobs (MSI-X, TX staging, NAPI idle) become
// no-ops when `gve` is the active driver — `gve` is polling-only in
// Phase 2 and has no TX staging pool, so the callers' contracts
// are already satisfied.

// `gve` and `virtio_net` are external crates now (phase 5 step 4);
// bring them in as local aliases via the crate-level `extern crate`
// declarations in `lib.rs`.
use crate::{virtio_net, gve};

#[inline]
fn use_gve() -> bool {
    gve::probe_ok()
}

// ---- Init / lifecycle -----------------------------------------------------

/// Probe both drivers. Tries `gve` first (the preferred NIC on
/// GCE — native RSS multi-queue). Falls back to virtio-net, which
/// is what kvm-vm, HVF, and default-GCE instances expose.
/// Returns `true` if either driver came up.
pub fn init() -> bool {
    if gve::init() {
        return true;
    }
    virtio_net::init()
}

pub fn get_mac(mac_out: *mut u8) {
    if use_gve() {
        gve::get_mac(mac_out)
    } else {
        virtio_net::get_mac(mac_out)
    }
}

pub fn num_queue_pairs() -> u16 {
    if use_gve() {
        gve::num_queue_pairs()
    } else {
        virtio_net::num_queue_pairs()
    }
}

/// Short identifier of the active driver. Used by `uni::boot_info()`
/// to label the NIC entry and by diagnostic endpoints.
pub fn driver_name() -> &'static str {
    if use_gve() { "gve" } else { "virtio-net" }
}

pub fn activate_multi_queue() {
    // `gve` has a different multi-queue model (CONFIGURE_RSS +
    // per-core queues are set up at driver init, Phase 4). On the
    // virtio-net path this triggers the legacy ctrl-vq MQ dance.
    if !use_gve() {
        virtio_net::activate_multi_queue();
    }
}

pub fn enable_irq() {
    // Virtio-net registers MSI-X vectors here. `gve` is polling-only
    // for now — if interrupt support lands later it'll be wired up
    // inside `gve::init()` instead.
    if !use_gve() {
        virtio_net::enable_irq();
    }
}

// ---- RX / TX datapath -----------------------------------------------------

pub fn poll(callback: fn(&[u8])) -> i32 {
    if use_gve() {
        gve::poll(callback)
    } else {
        virtio_net::poll(callback)
    }
}

pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    if use_gve() {
        gve::poll_qp(qp, callback)
    } else {
        virtio_net::poll_qp(qp, callback)
    }
}

pub fn send(data: &[u8]) {
    if use_gve() {
        gve::send(data);
    } else {
        virtio_net::send(data)
    }
}

// ---- Virtio-only knobs — no-op on gve ------------------------------------

pub fn flush_tx_staging() {
    if use_gve() {
        // `gve` has no staging queue; the doorbell-coalesced path
        // may have dirty queues across cores, so flush everything.
        gve::flush_all_tx_kicks();
    } else {
        virtio_net::flush_tx_staging();
    }
}

pub fn flush_tx_kick_if_dirty() -> bool {
    if use_gve() {
        gve::flush_tx_kick_if_dirty()
    } else {
        virtio_net::flush_tx_kick_if_dirty()
    }
}

pub fn irq_idle_supported() -> bool {
    // `gve` does not (yet) support NAPI-style idle: the event loop
    // keeps polling. Return false here so the caller's idle-path
    // fallback stays engaged.
    if use_gve() {
        false
    } else {
        virtio_net::irq_idle_supported()
    }
}

pub fn arm_rx_interrupts() {
    if !use_gve() {
        virtio_net::arm_rx_interrupts();
    }
}

pub fn has_pending_rx() -> bool {
    if use_gve() {
        false
    } else {
        virtio_net::has_pending_rx()
    }
}

pub fn has_pending_tx() -> bool {
    if use_gve() {
        false
    } else {
        virtio_net::has_pending_tx()
    }
}

pub fn rearm_rx_napi(core_id: u32) -> bool {
    if use_gve() {
        false
    } else {
        virtio_net::rearm_rx_napi(core_id)
    }
}

pub fn enable_deferred_tx_kick() {
    if use_gve() {
        gve::enable_deferred_tx_kick();
    } else {
        virtio_net::enable_deferred_tx_kick();
    }
}

pub fn poke_interrupt_status() {
    if !use_gve() {
        virtio_net::poke_interrupt_status();
    }
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    if use_gve() {
        gve::rx_counts()
    } else {
        virtio_net::rx_counts()
    }
}

pub fn rx_used_cursors() -> [(u16, u16); 8] {
    if use_gve() {
        gve::rx_used_cursors()
    } else {
        virtio_net::rx_used_cursors()
    }
}
