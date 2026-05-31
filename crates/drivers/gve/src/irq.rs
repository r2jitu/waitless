// gve/src/irq.rs — MSI-X RX interrupts for wake-on-packet idle (T7).
//
// gve is polling-only by default (`idle: None`). This module layers
// interrupt-driven RX wake on top, used ONLY by the event loop's
// sustained-idle gate (`entry.rs idle_cb` → `nic::arm_rx_idle`): a deeply
// idle core unmasks its RX notification block's IRQ so the timer-bounded
// HLT wakes the instant a packet lands, instead of waiting for the ~1 ms
// timer backstop. A busy core never reaches the gate, so it never arms an
// interrupt — the polling fast path (and the c3 throughput headline) is
// untouched, with zero interrupt overhead under load.
//
// Fallback-safe: if MSI-X setup fails at any step, `GVE_IRQ_READY` stays
// false and `arm_rx_idle()` returns false, so `idle_cb` degrades to the
// proven timer-only HLT. No setup failure can stall RX.
//
// gve interrupt model (more involved than virtio's per-queue MSI-X): the
// device has notification blocks — TX blocks `0..num_qp`, RX blocks
// `num_qp..2*num_qp`. `CONFIGURE_DEVICE_RESOURCES` (init.rs) already hands
// the device the irq-db DMA array, the block count, and
// `ntfy_blk_msix_base_idx = 0`, so the device side is already
// MSI-X-ready (verified vs upstream `gve_main.c`: the mgmt vector sits at
// the END, `mgmt_msix_idx = num_ntfy_blks`, so blocks start at MSI-X
// entry 0). We only: enable MSI-X in PCI config, program each RX block's
// table entry (steered to the core that polls that queue), register the
// ISR, and read back each block's BAR2 IRQ-doorbell index (device-
// populated in the irq-db array, big-endian). The IRQ-doorbell encoding
// differs by queue format: GQI uses `GVE_IRQ_*` big-endian; DQO uses
// `GVE_ITR_*` little-endian (verified vs `gve_main.c` / `gve_dqo.h`).

/// Enable MSI-X RX interrupts. Called once from the boot path
/// (`nic::enable_irq`) after the device + queues are up. No-op on
/// non-x86 (gve is GCE/x86-only but the crate compiles for aarch64).
pub(crate) fn enable_irq() {
    #[cfg(target_arch = "x86_64")]
    x86::enable_irq();
}

/// Total gve RX MSI-X interrupts handled since boot (sum across cores).
/// Surfaced in the `/obs` `nic` block as `rx_irq` — nonzero confirms
/// wake-on-packet idle is firing; stays 0 on a busy server (which never
/// arms) and on MSI-X-less boots (timer-only idle).
pub(crate) fn rx_irq_count() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        x86::RX_IRQ_COUNT.load(core::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Arm the calling core's RX interrupt ahead of a sustained-idle HLT.
/// Returns `true` if work is already pending (caller skips the sleep);
/// `false` otherwise (caller sleeps, waking on the IRQ or timer
/// backstop) — including when MSI-X isn't ready, giving timer-only idle.
pub(crate) fn arm_rx_idle() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::arm_rx_idle()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use bus::{log, pci};

    use crate::{
        BAR2_VA, IRQ_DB_VA, MAX_QUEUE_PAIRS, NUM_QP, PCI_DEVICE_GVE, PCI_VENDOR_GVE,
        QUEUE_FORMAT_DQO,
    };

    // GQI irq-doorbell bits (big-endian on the wire; `gve_main.c`).
    const GVE_IRQ_ACK: u32 = 1 << 31;
    const GVE_IRQ_MASK: u32 = 1 << 30;
    const GVE_IRQ_EVENT: u32 = 1 << 29;
    // DQO irq-doorbell (ITR) encoding (little-endian; `gve_dqo.h`). The
    // doorbell word is `[enable:bit0][clear_pba:bit1][update_mode:bits3-4]
    // [interval:bits5-16]`. Bits 3-4 = 0b00 means "apply this write"
    // (update the interval + enable per bit 0); 0b11 (`NO_UPDATE`) means
    // "ignore the interval/enable, leave as-is" — which is why writing
    // `NO_UPDATE` alone can neither set the rate nor disable. The interval
    // counts in 2 µs units (Linux halves usecs). Matching
    // `gve_setup_itr_interval_dqo`:
    //   arm    = ENABLE | ((us>>1 & MASK) << SHIFT)   (set rate + enable)
    //   disable = 0                                    (update mode, enable 0)
    const GVE_ITR_ENABLE_BIT_DQO: u32 = 1 << 0;
    const GVE_ITR_INTERVAL_DQO_SHIFT: u32 = 5;
    const GVE_ITR_INTERVAL_DQO_MASK: u32 = (1 << 12) - 1;
    /// RX interrupt rate limit (µs) — same as Linux's
    /// `GVE_RX_IRQ_RATELIMIT_US_DQO`. A coalescing-interval backstop: the
    /// device won't re-fire faster than this even if the per-fire disable
    /// (below) somehow misses, so a mis-step can't storm the way an
    /// interval-0 ITR did (~742 IRQ/req).
    const GVE_RX_IRQ_RATELIMIT_US_DQO: u32 = 20;
    /// DQO doorbell value to arm: enable + set the coalescing interval.
    #[inline]
    fn dqo_itr_arm() -> u32 {
        GVE_ITR_ENABLE_BIT_DQO
            | (((GVE_RX_IRQ_RATELIMIT_US_DQO >> 1) & GVE_ITR_INTERVAL_DQO_MASK)
                << GVE_ITR_INTERVAL_DQO_SHIFT)
    }
    // IDT vector base for gve RX MSI-X. Above the LAPIC timer (0xF0 is
    // the timer; we stay below it) and the PIC/APIC range, below the
    // spurious vector. gve and virtio-net never coexist (one NIC binds),
    // so overlapping virtio's 0x60 base would be harmless, but a distinct
    // base keeps the IDT map self-documenting. Room for MAX_QUEUE_PAIRS.
    const GVE_MSIX_IDT_BASE: u8 = 0x70;
    // irq-db array entry stride — one cache line, matching `IRQ_DB_STRIDE`
    // in init.rs and the value passed to `CONFIGURE_DEVICE_RESOURCES`.
    const IRQ_DB_STRIDE: u64 = 64;

    /// True once MSI-X is programmed and RX interrupts are usable. While
    /// false, `arm_rx_idle` is a no-op → timer-only idle.
    static GVE_IRQ_READY: AtomicBool = AtomicBool::new(false);

    /// Mapped MSI-X table base VA. Cached so `arm_rx_idle` can unmask the
    /// calling core's table entry. 0 = unset.
    static MSIX_TABLE_VA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    /// RX MSI-X interrupts handled since boot (all cores). Exposed via
    /// `super::rx_irq_count` for the `/obs` `nic` block.
    pub(super) static RX_IRQ_COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// Per-qp RX IRQ-doorbell byte offset into BAR2 (device-populated
    /// register index × 4). Cached at `enable_irq` so the arm/ISR paths
    /// don't re-read the DMA array. 0 = unset.
    static RX_IRQ_DB_OFF: [AtomicU32; MAX_QUEUE_PAIRS] =
        [const { AtomicU32::new(0) }; MAX_QUEUE_PAIRS];

    /// RX notification-block id for queue pair `qp` (TX blocks occupy
    /// `0..num_qp`, RX `num_qp..2*num_qp`). Equals the MSI-X table entry
    /// index because `ntfy_blk_msix_base_idx = 0`.
    #[inline]
    fn rx_block_id(num_qp: u32, qp: u32) -> u32 {
        num_qp + qp
    }

    /// Queue pair owned by the current core (Tier-1 per-core pinning;
    /// falls back to qp 0). Mirrors `tx::current_qp`.
    #[inline]
    fn qp_for_core() -> usize {
        let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
        if num_qp == 0 {
            return 0;
        }
        let core = kernel_bare::cpu_id();
        if core < num_qp { core as usize } else { 0 }
    }

    /// Enable the RX block's IRQ doorbell — format-specific encoding +
    /// endianness. After this, a fresh RX completion raises the block's
    /// MSI-X message. DQO sets a coalescing interval (update mode) rather
    /// than `NO_UPDATE`, so the rate is actually programmed (interval 0
    /// stormed); GQI acks + enables event delivery.
    #[inline]
    fn irq_enable(off: u32) {
        let bar2 = BAR2_VA.load(Ordering::Acquire);
        if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
            crate::dqo::doorbell_write_le(bar2, off, dqo_itr_arm());
        } else {
            crate::gqi::doorbell_write(bar2, off, GVE_IRQ_ACK | GVE_IRQ_EVENT);
        }
    }

    /// Disable (mask) the RX block's IRQ doorbell in the ISR so it fires
    /// once per arm. Both formats use the **same** mask bit `GVE_IRQ_MASK`
    /// (bit 30) — verified vs FreeBSD `gve_mask_all_queue_irqs`, which
    /// writes `GVE_IRQ_MASK` for GQI *and* DQO. (Writing `0` to a DQO ITR
    /// doorbell does NOT cleanly mask — it re-evaluates the whole register
    /// (enable+interval+update-mode) and disrupts the queue's RX→response
    /// path; the dedicated mask bit just suppresses delivery.) Only the
    /// endianness differs: GQI big-endian, DQO little-endian.
    #[inline]
    fn irq_disable(off: u32) {
        let bar2 = BAR2_VA.load(Ordering::Acquire);
        if QUEUE_FORMAT_DQO.load(Ordering::Relaxed) {
            crate::dqo::doorbell_write_le(bar2, off, GVE_IRQ_MASK);
        } else {
            crate::gqi::doorbell_write(bar2, off, GVE_IRQ_MASK);
        }
    }

    /// ISR for gve RX MSI-X vectors (both formats). Each vector is steered
    /// to the core that polls its queue, so the wake lands on the right
    /// core; the frame is drained by the event loop's next poll. We
    /// disable the block's IRQ here so it fires exactly once per arm —
    /// neither format is one-shot (GQI's event re-fires until masked; DQO
    /// re-fires per completion at its ITR rate) — and re-arm on the next
    /// idle via `arm_rx_idle`. APIC EOI is sent by the IDT dispatcher
    /// (vector ≥ 48).
    unsafe extern "C" fn gve_rx_isr(_frame: *mut kernel_bare::x86_64::idt::InterruptFrame) {
        RX_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        let qp = qp_for_core();
        let off = RX_IRQ_DB_OFF[qp].load(Ordering::Relaxed);
        if off != 0 {
            irq_disable(off);
        }
    }

    pub(crate) fn arm_rx_idle() -> bool {
        if !GVE_IRQ_READY.load(Ordering::Acquire) {
            return false;
        }
        let qp = qp_for_core();
        let off = RX_IRQ_DB_OFF[qp].load(Ordering::Relaxed);
        let table_va = MSIX_TABLE_VA.load(Ordering::Acquire);
        if off == 0 || table_va == 0 {
            return false;
        }
        let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
        let entry = rx_block_id(num_qp, qp as u32) as u16;
        // Open both gates for the sleep: unmask the MSI-X table entry
        // (kept masked at setup so a busy core — which never reaches this
        // gate — never receives an idle interrupt) and enable the device
        // IRQ doorbell. A fresh RX completion now wakes this core.
        // SAFETY: `table_va` is the mapped table base; `entry` was
        // bounds-checked when programmed in `enable_irq`.
        unsafe { pci::msix_set_mask(table_va, entry, false) };
        irq_enable(off);
        // Rely on the wake (IRQ, or the ~1 ms timer backstop) + the next
        // poll to pick up the frame; arming with an already-pending
        // completion raises the interrupt immediately on these devices,
        // so we don't separately peek. Always return false (sleep).
        false
    }

    pub(crate) fn enable_irq() {
        let idx = match pci::find_device(PCI_VENDOR_GVE, PCI_DEVICE_GVE) {
            Some(i) => i,
            None => return,
        };
        let dev = pci::pci_device(idx);
        let cap = match pci::find_msix_cap(&dev) {
            Some(c) => c,
            None => {
                log(b"[gvnic] no MSI-X capability; idle stays timer-only\n");
                return;
            }
        };
        let bar_phys = pci::read_bar64(&dev, cap.table_bar as usize);
        if bar_phys == 0 {
            log(b"[gvnic] MSI-X table BAR is zero; idle stays timer-only\n");
            return;
        }
        let table_va = kernel_bare::mm::phys_to_virt(bar_phys) as u64 + cap.table_offset as u64;

        let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
        let irq_db_va = IRQ_DB_VA.load(Ordering::Acquire);
        if num_qp == 0 || irq_db_va == 0 {
            return;
        }

        let topo = kernel_bare::x86_64::acpi::topology();

        // Enable MSI-X in PCI config. Per-entry masks govern delivery;
        // we program the RX entries MASKED below and unmask only from the
        // deep-idle gate (`arm_rx_idle`), so a busy core — which never
        // reaches the gate — never receives an idle interrupt. This keeps
        // the polling/throughput path interrupt-free by construction.
        pci::msix_enable(&dev, cap.cap_off, true);

        for qp in 0..num_qp {
            let block = rx_block_id(num_qp, qp);
            let entry = block as u16;
            if entry >= cap.table_size {
                // Device's table is smaller than expected — stop rather
                // than write past it. Earlier qps still got interrupts.
                break;
            }
            // Read back the device-populated BAR2 doorbell register index
            // for this block (big-endian at irq_db_va + block*stride);
            // byte offset into BAR2 = index × 4.
            let idx_addr = irq_db_va + (block as u64) * IRQ_DB_STRIDE;
            let db_index = u32::from_be(unsafe { ptr::read_volatile(idx_addr as *const u32) });
            RX_IRQ_DB_OFF[qp as usize].store(db_index * 4, Ordering::Relaxed);

            // Steer this RX queue's IRQ at the core that polls it.
            let target = qp as usize;
            let apic_id = topo.apic_ids.get(target).copied().unwrap_or(0) as u32;
            let idt_vector = GVE_MSIX_IDT_BASE + qp as u8;
            let addr = pci::msix_msg_addr(apic_id);
            // Program masked; `arm_rx_idle` unmasks per-core on demand.
            // SAFETY: `table_va` is the mapped MSI-X table base; `entry`
            // is bounds-checked against `cap.table_size` above.
            unsafe { pci::msix_write_entry(table_va, entry, addr, idt_vector as u32, true) };
            kernel_bare::x86_64::idt::register_handler(idt_vector, gve_rx_isr);
        }

        MSIX_TABLE_VA.store(table_va, Ordering::Release);
        GVE_IRQ_READY.store(true, Ordering::Release);
        log(b"[gvnic] MSI-X RX interrupts enabled (wake-on-packet idle)\n");
    }
}
