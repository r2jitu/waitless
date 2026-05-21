// IRQ wiring: the cross-arch IRQ handler, IRQ-pending flag,
// `enable_irq` (FDT/MSI-X discovery), and the x86_64 MSI-X
// trampoline + per-vector config. The poll path uses `IRQ_PENDING`
// to short-circuit the per-iteration ISR-read MMIO exit.

use core::sync::atomic::AtomicBool;

#[cfg(target_arch = "aarch64")]
use bus::virtio::{MMIO_INTERRUPT_ACK, MMIO_INTERRUPT_STATUS, vpci_read_isr};
#[cfg(target_arch = "aarch64")]
use bus::{virtio_read32, virtio_write32};
use bus::virtio::vpci_device;
#[cfg(target_arch = "x86_64")]
use bus::virtio::{
    VirtioPciDevice, vpci_msix_enable, vpci_msix_write_entry, vpci_select_queue,
    vpci_set_config_msix_vector, vpci_set_queue_msix_vector,
};
#[cfg(target_arch = "aarch64")]
use bus::pci::pci_device;
#[cfg(target_arch = "aarch64")]
use kernel_bare::aarch64::{exceptions, fdt};

use crate::{Transport, ndev, rx_q};

/// Set by the IRQ handler when SPI 35 fires with new RX frames.
/// The poll path checks this instead of doing an MMIO read every iteration.
pub(crate) static IRQ_PENDING: AtomicBool = AtomicBool::new(false);

/// Line-based IRQ handler for the aarch64 GIC SPI path. Registered
/// with `exceptions::register_irq`. The x86_64 MSI-X path uses
/// `msix_rx_isr_trampoline` instead, so this is aarch64-only.
#[cfg(target_arch = "aarch64")]
fn irq_handler(_irq: u32) {
    unsafe {
        // NAPI: disable notifications on entry
        (*rx_q(0)).disable_interrupts();

        // Acknowledge device interrupt
        match (*ndev()).transport {
            Transport::ModernPci { vpci_idx } => {
                let dev = vpci_device(vpci_idx);
                vpci_read_isr(&dev);
            }
            #[cfg(target_arch = "aarch64")]
            Transport::Mmio { base, .. } => {
                // Always read ISR and write INTERRUPT_ACK. The FDT
                // `interrupts` flag (edge vs level) describes how the
                // GIC samples the line, not how the virtio-mmio device
                // implements interrupt signalling on the other side —
                // QEMU's virtio-mmio sets the line via
                // `!!vdev->isr` and keeps it asserted until the guest
                // acks, so skipping the ACK (which commit 6d7d749
                // did for an HVF-specific edge-pulse extension) causes
                // an unending IRQ storm on stock QEMU.
                let isr = virtio_read32(base + MMIO_INTERRUPT_STATUS);
                if (*rx_q(0)).used_idx_mmio {
                    (*rx_q(0)).mmio_cached_used_idx = (isr >> 16) as u16;
                }
                IRQ_PENDING.store(true, core::sync::atomic::Ordering::Release);
                virtio_write32(base + MMIO_INTERRUPT_ACK, isr & 0xFFFF);
            }
            Transport::None => {}
        }
    }
}

pub(crate) fn enable_irq() {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            let fdt = fdt::info();

            match (*ndev()).transport {
                Transport::ModernPci { vpci_idx } if fdt.gic_dist_base != 0 => {
                    let slot = pci_device(vpci_device(vpci_idx).pci_idx).slot;
                    let intid = if (slot as usize) < 8 {
                        fdt.pci_irqs[slot as usize]
                    } else {
                        0
                    };
                    if intid != 0 {
                        (*rx_q(0)).enable_interrupts();
                        exceptions::register_irq(intid, irq_handler);
                        (*ndev()).irq_idle_available = true;
                    }
                }
                Transport::Mmio { base, .. } if fdt.gic_dist_base != 0 => {
                    for i in 0..fdt.virtio_count as usize {
                        if fdt.virtio_bases[i] == base && fdt.virtio_irqs[i] != 0 {
                            (*rx_q(0)).enable_interrupts();
                            exceptions::register_irq(fdt.virtio_irqs[i], irq_handler);
                            (*ndev()).irq_idle_available = true;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if let Transport::ModernPci { vpci_idx } = (*ndev()).transport {
                let dev = vpci_device(vpci_idx);
                if dev.msix_cap_off != 0 && dev.msix_table != 0 {
                    init_msix_x86(&dev, (*ndev()).num_queue_pairs as usize);
                    // Enable notifications on each RX queue pair so the
                    // first incoming packet triggers an MSI-X entry we
                    // unmasked in init_msix_x86.
                    let nqp = (*ndev()).num_queue_pairs as usize;
                    for qp in 0..nqp {
                        (*rx_q(qp)).enable_interrupts();
                    }
                    (*ndev()).irq_idle_available = true;
                }
            }
        }
    }
}

/// Wire MSI-X for ModernPCI on x86_64. One vector per RX queue pair;
/// each vector is steered to the owning vCPU's Local APIC so `arch::idle`
/// on that core wakes directly on its own RX queue. TX queues and the
/// config-change vector are set to VIRTIO_MSI_NO_VECTOR because the
/// driver polls TX completions itself.
///
/// Must be called with all queue pairs already enabled and before
/// DRIVER_OK is set (which the `enable_irq` caller arranges: in the
/// current flow enable_irq runs from the boot path after DRIVER_OK,
/// and QEMU's virtio-net happily accepts MSI-X vector updates then).
#[cfg(target_arch = "x86_64")]
fn init_msix_x86(dev: &VirtioPciDevice, num_pairs: usize) {
    const NO_VEC: u16 = 0xFFFF;
    // IDT base for virtio-net MSI-X vectors. Sits above the PIC/APIC
    // timer range and well under the spurious vector (0xFF). One
    // vector per RX queue pair — up to `num_pairs` (negotiated).
    const MSIX_IDT_BASE: u8 = 0x60;

    // Enable MSI-X in the device's PCI config.
    vpci_msix_enable(dev, true);

    // Config-change interrupt: unused.
    vpci_set_config_msix_vector(dev, NO_VEC);

    let topo = kernel_bare::x86_64::acpi::topology();
    let cpu_count = topo.cpu_count as usize;

    for qp in 0..num_pairs {
        // Steer each queue pair's RX IRQ at the vCPU that owns it.
        let target_cpu = if qp < cpu_count { qp } else { 0 };
        let apic_id = topo.apic_ids[target_cpu] as u64;
        let idt_vector = MSIX_IDT_BASE + qp as u8;
        // MSI address (Intel SDM 10.11.1): 0xFEE0_0000 | dest<<12.
        // MSI data: low byte = vector, rest zero (fixed delivery, edge).
        let addr = 0xFEE0_0000u64 | (apic_id << 12);
        let data = idt_vector as u32;
        vpci_msix_write_entry(dev, qp as u16, addr, data, false);

        // Install the IDT handler for this vector. All per-queue
        // handlers share one implementation that reads the current
        // core's id and sets the RX_PENDING flag for that core.
        kernel_bare::x86_64::idt::register_handler(idt_vector, msix_rx_isr_trampoline);

        // Point the RX queue at the vector; TX stays unvectored.
        let rx_qi = (qp * 2) as u16;
        let tx_qi = (qp * 2 + 1) as u16;
        vpci_select_queue(dev, rx_qi);
        vpci_set_queue_msix_vector(dev, qp as u16);
        vpci_select_queue(dev, tx_qi);
        vpci_set_queue_msix_vector(dev, NO_VEC);
    }

    // MSI-X enable is silent; the `nic:` line in the boot banner
    // already shows `qps=N` which encodes whether multi-queue and
    // therefore MSI-X is active.
    let _ = num_pairs;
}

/// ISR trampoline for all virtio-net MSI-X RX vectors.
/// Sets `IRQ_PENDING` so the event-loop poll drains the queue on the
/// next iteration. Fires on the target vCPU because the MSI address
/// was programmed with that vCPU's LAPIC id.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn msix_rx_isr_trampoline(_frame: *mut kernel_bare::x86_64::idt::InterruptFrame) {
    IRQ_PENDING.store(true, core::sync::atomic::Ordering::Release);
}

/// Read the virtio INTERRUPT_STATUS register. This is a no-op from the
/// kernel's perspective (the value is discarded), but on HVF it forces
/// an MMIO exit that lets the host inject pending RX frames. Called from
/// DHCP's poll-wait loop to ensure DHCP replies are delivered during the
/// tight polling window where no other MMIO exits occur.
pub(crate) fn poke_interrupt_status() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if let Transport::Mmio { base, .. } = (*ndev()).transport {
            let isr = virtio_read32(base + MMIO_INTERRUPT_STATUS);
            // Cache used_idx from upper 16 bits (HVF extension).
            if (*rx_q(0)).used_idx_mmio {
                (*rx_q(0)).mmio_cached_used_idx = (isr >> 16) as u16;
            }
        }
    }
}
