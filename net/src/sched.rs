//! RX poll scheduling — the Tier 1 / Tier 2 dispatch. Decides which
//! core drives the NIC: single-core polls inline; Tier 1 gives each
//! core its own RX queue pair; Tier 2 elects a rotating distributor
//! via `RX_LOCK`. Also owns the kernel event-loop callbacks.
//!
//! This module decides *who* runs the receive path; the pipeline
//! itself — what happens to a frame — is `crate::rx`.

use crate::rx;
use uni_kernel::percpu;

/// Whether multi-core distribution has been initialized.
static MULTICORE_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Wakeup flags — set during distribution, cleared each poll cycle. The
/// distributor is single-threaded (only the lock holder writes), but
/// every core wakes up afterwards and reads the flags, so atomic load/
/// store removes the language-level data race.
pub(crate) static WAKEUP: uni_kernel::percpu::PerWorker<core::sync::atomic::AtomicBool> =
    uni_kernel::percpu::PerWorker::new();

/// RX poll lock: 0 = free, 1 = held. CAS-based; only one core wins
/// the right to drain the RX queue at a time.
static RX_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Per-core "just distributed" fairness flag. Set after a core wins the
/// distributor role and releases the lock. On the next `net_poll_cb`
/// the same core checks this flag: if set, it clears it and yields the
/// cycle so another core gets first shot at the lock. If no other core
/// actually took over, this core reclaims the role naturally on the
/// cycle after (no stall: the yield is a single iteration, and we still
/// wake on the next RX interrupt).
///
/// Without this flag, the core that happens to spend more time idle
/// wins the `try_lock` CAS race consistently (because it's first to
/// try after each release), so the "rotating distributor" never
/// actually rotates under asymmetric load.
pub(crate) static JUST_DISTRIBUTED: uni_kernel::percpu::PerWorker<core::sync::atomic::AtomicBool> =
    uni_kernel::percpu::PerWorker::new();

/// Per-core poll counter — gates the RFC 6298 retransmission tick.
/// Walking the TCP pool (and reading the millisecond clock) on every
/// event-loop iteration would be a measurable hot-path cost; gating
/// on the low bits of this counter runs the tick roughly once per
/// `RTX_TICK_INTERVAL` polls instead. A few hundred polls is a
/// fraction of a millisecond and the RTO floor is 1 s, so the
/// resolution is far finer than it needs to be, while the per-poll
/// cost is a single owned-cache-line `fetch_add`.
///
/// Sized to the tree-wide 8-core ceiling (`MAX_CORE_STATS`,
/// `MAX_QUEUE_PAIRS`); each core touches only its own slot, so the
/// counters never share a contended line across cores.
static RTX_POLL_COUNT: [core::sync::atomic::AtomicU32; 8] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 8];

/// Mask selecting how often the retransmission tick runs — once per
/// 1024 polls. A power-of-two mask keeps the gate a single `and`.
const RTX_TICK_MASK: u32 = 0x3FF;

/// Run the TCP retransmission tick for this core at a coarse cadence.
fn rtx_tick_if_due() {
    let core = uni_kernel::cpu_id() as usize;
    if core >= RTX_POLL_COUNT.len() {
        return;
    }
    let n = RTX_POLL_COUNT[core].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n & RTX_TICK_MASK == 0 {
        crate::tcp::on_rtx_tick();
    }
}

/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-core mode, all processing happens here.
/// In Tier 1 multi-queue mode, each core polls its own RX queue pair
/// directly — no distributor, no RX_LOCK, no inbox.
/// In Tier 2 single-queue mode, any idle core can become the distributor
/// by acquiring the RX lock.
/// Returns true if any network work was done.
pub fn poll() -> bool {
    // Drive RFC 6298 retransmission timers before the RX work — a
    // lost outbound segment is resent here, not on an RX event.
    rtx_tick_if_due();

    let num_cores = percpu::num_cores();

    if num_cores <= 1 {
        return nic::poll(rx::net_receive) > 0;
    }

    // Tier 1: multi-queue — each core polls its own RX queue pair.
    if nic::num_queue_pairs() > 1 {
        return poll_tier1();
    }

    // Tier 2: single-queue with software distribution.
    poll_tier2(num_cores)
}

/// Tier 1 poll: each core polls its own RX queue pair directly.
/// No distributor, no RX_LOCK, no inbox.
fn poll_tier1() -> bool {
    if !MULTICORE_INIT.load(core::sync::atomic::Ordering::Relaxed) {
        MULTICORE_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        let nqp = nic::num_queue_pairs();
        // One write_fmt holds SERIAL_TX_LOCK for the whole line so a
        // concurrent klog! on another core can't slip in mid-message.
        uni_kernel::serial::write_fmt(format_args!(
            "[net] Tier 1: per-core RX queues ({} queue pairs)\n",
            nqp
        ));
    }
    let core = uni_kernel::cpu_id();
    let nqp = nic::num_queue_pairs() as u32;
    // Pre-`set_ready` (boot-task window): only the BSP is polling;
    // APs are still idling at the top of `eventloop::run`. If a
    // multi-queue NIC hashes inbound traffic to a queue >0 (e.g.
    // vhost-net routes a DHCP OFFER to queue 1 by 4-tuple hash),
    // no AP is draining it and DHCP retries time out. While in
    // that window the BSP polls every queue. Once `set_ready` has
    // fired we fall back to the per-core scheme — APs are then
    // polling their own queues, and double-polling would race on
    // the per-queue cursor atomics.
    if core == 0 && !uni_kernel::eventloop::is_ready() {
        let mut total = 0;
        for q in 0..nqp as usize {
            total += nic::poll_qp(q, rx::net_receive);
        }
        return total > 0;
    }
    // Only cores with `core < nqp` poll RX — two cores hammering the
    // same queue race on the cursor atomics and double-deliver /
    // miss packets. Cores beyond nqp still do service work (they
    // run handlers for connections whose RX landed on a polling
    // core); they just don't drive the NIC directly.
    if core >= nqp {
        return false;
    }
    let count = nic::poll_qp(core as usize, rx::net_receive);
    count > 0
}

fn poll_tier2(num_cores: u32) -> bool {
    if !MULTICORE_INIT.load(core::sync::atomic::Ordering::Relaxed) {
        MULTICORE_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        uni_kernel::serial::write_fmt(format_args!(
            "[net] Tier 2: software distribution ({} cores)\n",
            num_cores
        ));
    }

    let my_core = uni_kernel::cpu_id();

    // Cooperative yield for fair rotation: if we just distributed on the
    // previous cycle, skip this attempt so another (presumably busier)
    // core has first shot at the lock. We still wake on the next RX
    // interrupt and will reclaim the role on the cycle after if no one
    // else takes over.
    if num_cores > 1
        && JUST_DISTRIBUTED
            .at(my_core)
            .swap(false, core::sync::atomic::Ordering::Relaxed)
    {
        return false;
    }

    // Try to become the distributor.
    let got_lock = RX_LOCK
        .compare_exchange(
            0,
            1,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok();
    if !got_lock {
        return false;
    }

    // Flush TX staging first — responses from previous cycle.
    nic::flush_tx_staging();

    // Poll VirtIO RX and distribute directly (no batch buffer copy).
    for i in 0..num_cores {
        WAKEUP
            .at(i)
            .store(false, core::sync::atomic::Ordering::Relaxed);
    }

    let count = nic::poll(rx::distribute_frame);

    // Mark ourselves as "just distributed" — our next poll attempt will
    // yield, giving other cores first shot at the lock.
    if num_cores > 1 {
        JUST_DISTRIBUTED
            .at(my_core)
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    // Release lock.
    RX_LOCK.store(0, core::sync::atomic::Ordering::Release);

    let had_frames = count > 0;
    if had_frames {
        // Wake only the specific cores that received inbox data.
        // Broadcast wake_cores() is expensive on HVF: each SGI causes
        // a WFI wake (~5µs) on every core, even if it has no work.
        for i in 1..num_cores {
            if WAKEUP.at(i).load(core::sync::atomic::Ordering::Relaxed) {
                #[cfg(target_arch = "aarch64")]
                uni_kernel::aarch64::smp::send_sgi_to(i);
                #[cfg(target_arch = "x86_64")]
                uni_kernel::send_ipi(i);
            }
        }
    }

    // Flush TX (APs may have responded during distribution).
    nic::flush_tx_staging();

    had_frames
}

// ============================================================================
// Event loop integration
// ============================================================================

/// Register network callbacks with the kernel event loop.
/// Called during boot after virtio-net is initialized.
pub fn init_eventloop() {
    uni_kernel::eventloop::set_net_poll(net_poll_cb);
    uni_kernel::eventloop::set_net_drain(net_drain_cb);
    uni_kernel::eventloop::set_net_flush(net_flush_cb);
    // NAPI re-arm: right before the event loop HLTs, re-enable RX
    // notifications on this core's queue pair and re-check the ring.
    uni_kernel::eventloop::set_net_rearm_rx(nic::rearm_rx_napi);
    // RFC 6298: a core with an armed retransmission timer must not
    // sleep past the deadline. The event loop bounds its idle when
    // this reports true (the connection awaiting a lost segment's
    // ACK gets no RX event to wake it otherwise).
    uni_kernel::eventloop::set_net_has_timers(crate::tcp::has_armed_rtx_timers);
    // Batch TX kicks: defer MMIO writes until `net_flush_cb` fires at
    // the end of each event-loop tick. Correct for the whole boot
    // because DHCP now runs as an async task polled by the event loop
    // — so the flush hook fires between DISCOVER/REQUEST sends and
    // the next `dhcp_await` poll.
    nic::enable_deferred_tx_kick();
}

fn net_poll_cb(_core_id: u32) -> bool {
    // Tier 1 (multi-queue): every core polls its own queue — no lock.
    if nic::num_queue_pairs() > 1 {
        return poll();
    }
    // Tier 2: any core can become the rotating distributor; the RX_LOCK CAS
    // in poll_tier2 picks one winner per cycle.
    if RX_LOCK.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return false;
    }
    poll()
}

fn net_drain_cb(core_id: u32) -> bool {
    // SAFETY: the kernel event loop only calls this callback with the
    // current core's id; we threaded that id through, so it matches
    // `cpu_id()` at this exact moment without needing a second TLS read.
    let cc = unsafe { percpu::CurrentWorker::from_id_unchecked(core_id) };
    let core = percpu::percore(&cc);
    // Tier 2 cross-core delivery: the distributor parked received
    // frames in our inbox, each carrying the L2/L3 parse it already
    // computed. Drain them in arrival (FIFO) order — `rx::deliver`
    // skips straight to the L4 stack (no re-parse) and drops the
    // chain there, reposting its device buffers. No frame-byte copy
    // (item C).
    core.rx_inbox.drain_each(percpu::rx_node_pool(), |frame| {
        rx::deliver(frame.parsed, frame.chain)
    }) > 0
}

fn net_flush_cb() {
    let nqp = nic::num_queue_pairs();
    if nqp > 1 {
        // Tier 1: each core flushes its own TX queue pair. No staging needed.
        nic::flush_tx_kick_if_dirty();
    } else {
        nic::flush_tx_staging();
        // Only kick if new TX buffers were actually added. Skipping
        // redundant kicks saves ~7 MMIO exits/request at high concurrency.
        nic::flush_tx_kick_if_dirty();
    }
}
