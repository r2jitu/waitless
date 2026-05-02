// kernel/entry.rs — Kernel entry point + boot shim (Rust)
//
// Called from boot.S after the processor is in 64-bit mode with a valid stack.
// On x86_64: RDI = multiboot2 info physical address.
// On aarch64: x0  = DTB physical address (QEMU or HVF runner).
//
// Initialises every subsystem in dependency order, then calls uni_init()
// which spawns the app's `#[uni::init]` body as a task on core 0's arena.

#![no_std]
#![allow(unused_imports)]

extern crate alloc;

use core::ptr;

extern crate uni_kernel;
extern crate uni_drivers;
extern crate uni_net_stack as net;
extern crate uni;

// Boot assembly — compiled by LLVM's integrated assembler via global_asm!.
//
// x86_64 boot.S contains 32-bit absolute relocations (R_X86_64_32)
// targeting .boot_bss that cannot be linked into a higher-half ELF
// (Limine boot), so it lives in a separate `boot_asm` crate that the
// .limine.elf target excludes. Limine enters at `limine_entry()`
// directly and does not need the multiboot/PVH stub.
//
// `idt_stubs.S` (PC-relative jumps + .quad table) and `ap_boot.S`
// (movabs + small absolute trampoline-relative offsets) are higher-half
// safe and stay here so SMP works under both boot paths.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("x86_64/idt_stubs.S"), options(att_syntax));
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("x86_64/ap_boot.S"), options(att_syntax));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("aarch64/boot.S"));


use uni_kernel::{types, serial, mm};
#[cfg(target_arch = "aarch64")]
use uni_kernel::aarch64::{fdt, mmu, exceptions, smp};
use types::{BootInfo, MemoryRegion, Protocol, MEM_AVAILABLE, MEM_RESERVED, MAX_MEMORY_REGIONS};

// ============================================================================
// Panic handler (required for rust_static_library)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    serial::puts(b"PANIC in entry\n");
    unsafe { arch_shutdown() }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// ============================================================================
// Architecture-specific code
// ============================================================================


/// Power off the machine. Never returns.
#[cfg(target_arch = "x86_64")]
unsafe fn arch_shutdown() -> ! {
    unsafe {
        // ACPI S5 sleep via PM1_CNT — try multiple ports/SLP_TYP values
        core::arch::asm!("out dx, ax", in("dx") 0x0604u16, in("ax") 0x2000u16, options(nomem, nostack));
        core::arch::asm!("out dx, ax", in("dx") 0x0604u16, in("ax") 0x3400u16, options(nomem, nostack));
        core::arch::asm!("out dx, ax", in("dx") 0xb004u16, in("ax") 0x2000u16, options(nomem, nostack));
        loop { core::arch::asm!("cli", "hlt", options(nomem, nostack)); }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn arch_shutdown() -> ! {
    unsafe {
        // PSCI SYSTEM_OFF (HVC #0, function 0x84000008)
        core::arch::asm!(
            "movz x0, #0x8400, lsl #16",
            "movk x0, #0x0008",
            "hvc #0",
            out("x0") _,
            options(nomem, nostack)
        );
        loop { core::arch::asm!("wfi", options(nomem, nostack)); }
    }
}

// ============================================================================
// Extern declarations — linker symbols and app entry point only
// ============================================================================

// App entry point. Rust ABI is fine: both sides are Rust and the
// function takes no args and returns nothing. The `#[no_mangle]` on
// the emitting side (the `#[uni::init]` macro output) gives us a
// stable symbol name for link resolution.
unsafe extern "Rust" {
    fn uni_init();
}

unsafe extern "C" {
    // Linker-generated symbols
    static __bss_start: u8;
    static __bss_end: u8;

    // Defined in boot/limine_entry.rs. Releases every non-BSP CPU
    // parked by Limine's MP request into the kernel's AP entry path
    // and returns the total CPU count Limine found.
    #[cfg(target_arch = "x86_64")]
    fn start_aps_via_limine_mp() -> u32;
}

// ============================================================================
// Formatted output helper
// ============================================================================

macro_rules! klog {
    ($($arg:tt)*) => { serial::write_fmt(core::format_args!($($arg)*)) };
}

// ============================================================================
// BSS zeroing and global constructors
// ============================================================================

unsafe fn zero_bss() {
    unsafe {
        let start = &raw const __bss_start as *mut u8;
        let end = &raw const __bss_end as *mut u8;
        let len = end as usize - start as usize;
        ptr::write_bytes(start, 0, len);
    }
}

// ============================================================================
// Boot shim — protocol-specific BootInfo population
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod boot_shim_x86 {
    use super::*;

    // Multiboot2 structures
    const MULTIBOOT_TAG_END: u32 = 0;
    const MULTIBOOT_TAG_MMAP: u32 = 6;
    const MULTIBOOT_TAG_ACPI_OLD: u32 = 14; // ACPI 1.0 RSDP copy
    const MULTIBOOT_TAG_ACPI_NEW: u32 = 15; // ACPI 2.0+ RSDP copy
    const MULTIBOOT_MEMORY_AVAILABLE: u32 = 1;

    // PVH (Xen HVM) — used by QEMU 10.x
    const HVM_START_MAGIC: u32 = 0x336ec578;
    const HVM_MEMMAP_TYPE_RAM: u32 = 1;

    #[repr(C)]
    struct HvmMemmapEntry {
        addr: u64,
        size: u64,
        mem_type: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct HvmStartInfo {
        magic: u32,
        version: u32,
        flags: u32,
        nr_modules: u32,
        modlist_paddr: u64,
        cmdline_paddr: u64,
        rsdp_paddr: u64,
        memmap_paddr: u64,
        memmap_entries: u32,
        reserved: u32,
    }

    pub unsafe fn shim(info: &mut BootInfo, boot_info_addr: u64) {
        unsafe {
        info.protocol = Protocol::Unknown;
        info.memory_map_count = 0;
        info.dtb_addr = 0;
        info.kernel_phys_base = 0;
        info.kernel_virt_base = 0;
        info.hhdm_offset = 0;
        info.rsdp_paddr = 0;

        if boot_info_addr == 0 {
            info.memory_map[0] = MemoryRegion {
                base: 0,
                length: 128 * 1024 * 1024,
                region_type: MEM_AVAILABLE,
                _pad: 0,
            };
            info.memory_map_count = 1;
            klog!("  Boot protocol: fallback (no boot info)\n");
            return;
        }

        let magic = ptr::read_volatile(boot_info_addr as *const u32);

        if magic == HVM_START_MAGIC {
            // PVH boot
            info.protocol = Protocol::Pvh;
            let hvm = &*(boot_info_addr as *const HvmStartInfo);
            let entries = hvm.memmap_paddr as *const HvmMemmapEntry;
            let mut count = 0;
            for i in 0..hvm.memmap_entries as usize {
                if count >= MAX_MEMORY_REGIONS {
                    break;
                }
                let e = &*entries.add(i);
                info.memory_map[count] = MemoryRegion {
                    base: e.addr,
                    length: e.size,
                    region_type: if e.mem_type == HVM_MEMMAP_TYPE_RAM {
                        MEM_AVAILABLE
                    } else {
                        MEM_RESERVED
                    },
                    _pad: 0,
                };
                count += 1;
            }
            info.memory_map_count = count as i32;
            info.rsdp_paddr = hvm.rsdp_paddr;
            klog!("  Boot protocol: PVH ({} memory regions)\n", count);
            return;
        }

        // Try Multiboot2
        let mb2_total_size = ptr::read_volatile(boot_info_addr as *const u32);
        if mb2_total_size >= 8 && mb2_total_size < 65536 {
            // Scan tags for memory map
            let mut tag_addr = boot_info_addr + 8;
            let mut mmap_addr: u64 = 0;
            loop {
                let tag_type = ptr::read_volatile(tag_addr as *const u32);
                let tag_size = ptr::read_volatile((tag_addr + 4) as *const u32);
                if tag_type == MULTIBOOT_TAG_END {
                    break;
                }
                if tag_type == MULTIBOOT_TAG_MMAP {
                    mmap_addr = tag_addr;
                }
                // Multiboot2 ACPI tags 14/15 embed a copy of the RSDP
                // starting at byte 8 of the tag (right after type+size).
                // We just need the address of that copy — the RSDP
                // parser reads the signature/revision/RSDT/XSDT fields
                // from there regardless of which tag carried it.
                if (tag_type == MULTIBOOT_TAG_ACPI_OLD || tag_type == MULTIBOOT_TAG_ACPI_NEW)
                    && info.rsdp_paddr == 0
                {
                    info.rsdp_paddr = tag_addr + 8;
                }
                tag_addr = (tag_addr + tag_size as u64 + 7) & !7;
            }

            if mmap_addr != 0 {
                info.protocol = Protocol::Multiboot2;
                // Mmap tag: type(4) + size(4) + entry_size(4) + entry_version(4) + entries...
                let tag_size = ptr::read_volatile((mmap_addr + 4) as *const u32);
                let entry_size = ptr::read_volatile((mmap_addr + 8) as *const u32);
                let entries_start = mmap_addr + 16;
                let entries_end = mmap_addr + tag_size as u64;

                let mut count = 0;
                let mut ea = entries_start;
                while ea < entries_end && count < MAX_MEMORY_REGIONS {
                    let addr = ptr::read_volatile(ea as *const u64);
                    let len = ptr::read_volatile((ea + 8) as *const u64);
                    let mem_type = ptr::read_volatile((ea + 16) as *const u32);
                    info.memory_map[count] = MemoryRegion {
                        base: addr,
                        length: len,
                        region_type: if mem_type == MULTIBOOT_MEMORY_AVAILABLE {
                            MEM_AVAILABLE
                        } else {
                            MEM_RESERVED
                        },
                        _pad: 0,
                    };
                    count += 1;
                    ea += entry_size as u64;
                }
                info.memory_map_count = count as i32;
                klog!(
                    "  Boot protocol: Multiboot2 ({} memory regions)\n",
                    count
                );
                return;
            }
        }

        // Fallback
        info.memory_map[0] = MemoryRegion {
            base: 0,
            length: 128 * 1024 * 1024,
            region_type: MEM_AVAILABLE,
            _pad: 0,
        };
        info.memory_map_count = 1;
        klog!("  Boot protocol: fallback (unrecognized boot info)\n");
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod boot_shim_fdt {
    use super::*;

    pub unsafe fn shim(info: &mut BootInfo, dtb_addr: u64) {
        unsafe {
        info.protocol = Protocol::Fdt;
        info.dtb_addr = dtb_addr;
        info.kernel_phys_base = 0;
        info.kernel_virt_base = 0;
        info.hhdm_offset = 0;

        let fdt = &*fdt::info_ptr();
        let ram_base = if fdt.ram_size != 0 {
            fdt.ram_base
        } else {
            0x4000_0000
        };
        let ram_size = if fdt.ram_size != 0 {
            fdt.ram_size
        } else {
            128 * 1024 * 1024
        };

        info.memory_map[0] = MemoryRegion {
            base: ram_base,
            length: ram_size,
            region_type: MEM_AVAILABLE,
            _pad: 0,
        };
        info.memory_map_count = 1;
        klog!(
            "  Boot protocol: FDT (RAM 0x{:x} + {} MB)\n",
            ram_base,
            ram_size / (1024 * 1024)
        );
        }
    }
}

// ============================================================================
// Shared boot sequence
// ============================================================================

// Scratch for the legacy entry's BootInfo — populated by the arch-
// specific shim, then handed to `kernel_boot` as an immutable ref.
struct BootInfoSlot(core::cell::UnsafeCell<BootInfo>);
// SAFETY: BSP-only during boot; the shim writes it and `kernel_boot`
// reads it, both on the same thread with no overlap.
unsafe impl Sync for BootInfoSlot {}

static G_BOOT_INFO: BootInfoSlot = BootInfoSlot(core::cell::UnsafeCell::new(BootInfo::zeroed()));

unsafe fn kernel_boot(info: &BootInfo) {
    unsafe {
    // Mark boot-start as early as possible — `serial::init` itself
    // takes a few hundred microseconds (UART config + FIFO drain) and
    // we want every subsequent log line's timestamp to include it.
    uni_kernel::time::mark_boot_start();
    serial::init();
    #[cfg(target_arch = "aarch64")]
    klog!("UniKernel v0.1.0 (aarch64)\n");
    #[cfg(target_arch = "x86_64")]
    klog!("UniKernel v0.1.0 (x86_64)\n");

    #[cfg(target_arch = "x86_64")]
    {
        uni_kernel::x86_64::gdt::init();
        uni_kernel::x86_64::idt::init();
    }
    #[cfg(target_arch = "aarch64")]
    exceptions::init();

    mm::init(info as *const BootInfo);
    klog!("Heap: {} / {} MB\n",
          mm::get_free_memory() / (1024 * 1024),
          mm::get_total_memory() / (1024 * 1024));

    #[cfg(target_arch = "x86_64")]
    uni_kernel::x86_64::apic::init();

    #[cfg(target_arch = "x86_64")]
    {
        // Seed the RSDP hint before `detect_cpus()` — under UEFI
        // (GCE's OVMF) the BIOS-area scan fallback fails, so without
        // this we'd silently boot 1 CPU.
        uni_kernel::x86_64::acpi::set_rsdp(info.rsdp_paddr);
    }

    // Detect actual core count, publish via `set_num_workers`, then
    // size every `PerWorker<T>`. Strict ordering: `mm::init` first
    // (heap up), then `acpi::set_rsdp` (x86 detect needs ACPI), then
    // `percpu::init`, then `init_tls` (which reads `percpu::get(0)`
    // for GS_BASE / TPIDR_EL1 — running it before `percpu::init`
    // points the TLS register at a null cell and every later
    // `cpu_id()` returns garbage).
    #[cfg(target_arch = "aarch64")]
    let cpu_count = uni_kernel::aarch64::fdt::info().cpu_count;
    #[cfg(target_arch = "x86_64")]
    let cpu_count = uni_kernel::x86_64::acpi::detect_cpus();
    uni_kernel::percpu::init(cpu_count);

    #[cfg(target_arch = "x86_64")]
    uni_kernel::x86_64::smp::init_tls(0);
    #[cfg(target_arch = "aarch64")]
    uni_kernel::aarch64::smp::init_tls(0);

    uni_drivers::pci::init();

    // NIC bring-up. `uni_drivers::net::init()` tries gVNIC first
    // (preferred on GCE — native RSS multi-queue) then falls back
    // to virtio-net (kvm-vm, HVF, default GCE instances).
    let net_ok = uni_drivers::net::init();
    if !net_ok {
        klog!("[WARN] no NIC found (neither gVNIC nor virtio-net)\n");
    } else {
        // Cache MAC address for multi-core safe access.
        net::ethernet::init_mac();
        let mut mac = [0u8; 6];
        uni_drivers::net::get_mac(mac.as_mut_ptr());
        klog!("NIC: {} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
              uni_drivers::net::driver_name(),
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // IP bring-up (DHCP / static) happens inside the app's
        // `#[uni::init]` task via `uni::net::Net::enable(...).await`.
        // Driver-level config like multi-queue activation is
        // self-contained in the driver's `init()`.

        net::tcp::init();
        // Populate the IP protocol-dispatch registry. After this
        // `net_receive` routes TCP/UDP packets through
        // `net::REGISTRY` instead of a hardcoded match.
        net::init_stack();
        uni_drivers::net::enable_irq();

        #[cfg(target_arch = "x86_64")]
        {
            // Serial RX interrupt (IRQ4 / vector 36) for Ctrl-C wakeup
            uni_kernel::x86_64::idt::register_handler(36, serial_rx_isr_trampoline);
            uni_kernel::x86_64::idt::enable_irq(4);
            serial::enable_rx_irq();
        }
    }

    // Idle-path infrastructure (timer IRQ + SGI handler + IRQ unmask) is
    // orthogonal to the NIC. Apps without networking still need
    // `uni_kernel::cpu::idle_bounded` to wake from WFI when the 1 ms
    // generic-timer fires — `uni_kernel::runtime`'s `Sleep` future depends
    // on it.
    #[cfg(target_arch = "aarch64")]
    {
        let fdt = &*fdt::info_ptr();
        if fdt.gic_dist_base != 0 {
            exceptions::enable_timer_wakeup();
            // Enable SGI 0 on core 0 so APs can wake it from WFI via wake_core0().
            // Without this, SGI 0 is pending in GICR but never forwarded to the
            // CPU interface (bit 0 of GICR_ISENABLER0 is 0), so WFI never returns.
            exceptions::register_irq(0, smp::sgi_handler);
            // Unmask IRQ only; leave FIQ masked since Apple hypervisors
            // reserve FIQ for themselves and unmasking it crashes the guest.
            core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));
        }
    }

    // ── SMP: detect and bring up all available cores ──────────────────────
    // Matches the native backend's behaviour of using every available
    // thread. Apps that want single-core determinism get it by running
    // on a single-CPU VM (or, on native, via `UNIKERNEL_CPUS=1`).
    // `percpu::init` already ran near the top of boot — that publishes
    // the worker count and sizes every `PerWorker<T>` to it; the
    // SMP layer below is only responsible for waking the secondaries.
    #[cfg(target_arch = "aarch64")]
    {
        if cpu_count > 1 {
            uni_kernel::aarch64::smp::start_secondary_cores(cpu_count);
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if cpu_count > 1 {
            match info.protocol {
                Protocol::Limine => {
                    // Limine MP releases APs into `ap_entry_via_limine`;
                    // they print their own `[SMP] core N online` lines
                    // and join the event loop on `READY`. No wait
                    // needed — see `aarch64::smp::start_secondary_cores`
                    // for the same rationale.
                    let _ = start_aps_via_limine_mp();
                }
                _ => {
                    uni_kernel::x86_64::smp::start_secondary_cores(cpu_count);
                }
            }
        }
    }

    // Register event-loop callbacks. `check_shutdown` reads the
    // serial port and is NIC-independent — always wire it. The
    // NIC-specific hooks (poll/drain/flush/rearm/idle) only make
    // sense when a NIC probed.
    uni_kernel::eventloop::set_check_shutdown(|| serial::check_shutdown());
    if net_ok {
        net::init_eventloop();
        uni_kernel::eventloop::set_idle(idle_cb);
    }

    // Publish the read-only boot snapshot to apps. Must run after
    // SMP and NIC init so `num_cpus` and `nics` are final.
    publish_boot_info(net_ok);

    // Register the bare-metal async runtime with `//uni-runtime`.
    // Must happen before `uni_init` so the app can `spawn` / `sleep_us`.
    uni_kernel::runtime::init();

    // `uni_init()` (generated by `#[uni::init]`) spawns the app's
    // init body on core 0's arena and returns immediately. The
    // event loop below polls that task, so DHCP / async setup /
    // `uni::run(app)` all run while `net_flush_cb`, `net_poll_cb`,
    // etc. are ticking — no separate pre-eventloop phase, no
    // deferred-TX-kick race.
    uni_init();

    if !uni_kernel::eventloop::is_shutdown() {
        uni_kernel::eventloop::run(0);
    }

    klog!("\n[SHUTDOWN] Powering off.\n");

    // Stop secondary cores before system poweroff
    #[cfg(target_arch = "aarch64")]
    uni_kernel::aarch64::smp::request_shutdown();

    arch_shutdown();
    }
}

/// Populate `uni::boot_info()` from kernel + driver state. Called
/// exactly once during `kernel_boot` after SMP and NIC init. Apps
/// read the resulting snapshot via `uni::boot_info()` to size
/// per-core buffers, log runtime identity, etc.
fn publish_boot_info(net_ok: bool) {
    use uni::boot_info::{BootInfoParams, NicInfo};
    use alloc::vec::Vec;

    let mut nics: Vec<NicInfo> = Vec::new();
    if net_ok {
        let mut mac = [0u8; 6];
        uni_drivers::net::get_mac(mac.as_mut_ptr());
        nics.push(NicInfo {
            name: uni_drivers::net::driver_name(),
            mac,
            num_queue_pairs: uni_drivers::net::num_queue_pairs(),
        });
    }

    uni::boot_info::init_boot_info(BootInfoParams {
        ram_bytes: uni_kernel::mm::get_total_memory(),
        num_cpus: uni_kernel::percpu::num_cores(),
        // No kernel command line plumbed through the boot shim yet —
        // expose an empty string so apps can still rely on the field.
        boot_args: "",
        nics,
        // RTC isn't queried at boot yet. Left `None`; a future phase
        // can plumb ACPI FADT CMOS / FDT rtc.
        rtc_epoch: None,
    });
}

/// Event loop idle callback. Core-aware:
/// - Core 0: arm VirtIO RX notifications + yield/WFI (wakes on data or interrupt)
/// - Other cores: yield/WFI (wakes when the IO thread or distributor sends data)
///   On the HVF runner, yield MMIO parks the thread at zero CPU cost.
///   We use WFI and not WFE: WFE wakes from any SEV (including spurious ones),
///   which starved the host-side TCP proxy thread on Apple hypervisors.
///   `wake_cores()` sends SGI so WFI wakes correctly.
fn idle_cb(core_id: u32) {
    // No wake-up source → busy-poll. (Happens when the transport
    // doesn't expose any IRQ path: aarch64 without GIC configured,
    // legacy PCI without an IRQ line, etc.)
    if !uni_drivers::net::irq_idle_supported() {
        return;
    }
    if core_id == 0 || uni_kernel::percpu::num_cores() <= 1 {
        uni::wait_for_events();
    } else {
        // AP idle. On aarch64 + HVF we write the core_id to the
        // yield register (vs the BSP's `write 0`) so the runner
        // knows which vCPU thread to park. Falls back to a plain
        // WFI/HLT when the yield register isn't present.
        #[cfg(target_arch = "aarch64")]
        {
            let yield_addr = uni_kernel::aarch64::fdt::info().yield_mmio_base;
            if yield_addr != 0 {
                unsafe { core::ptr::write_volatile(yield_addr as *mut u32, core_id); }
                return;
            }
        }
        uni_kernel::cpu::idle_unbounded();
    }
}

// x86_64: ISR trampoline for serial RX (ignores InterruptFrame pointer)
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn serial_rx_isr_trampoline(_frame: *mut uni_kernel::x86_64::idt::InterruptFrame) {
    serial::rx_isr();
}

// ============================================================================
// Public entry points — extern "C" for boot.S and limine_entry
// ============================================================================

/// Legacy entry point called from boot.S.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_main(boot_info_addr: u64) {
    unsafe {
    zero_bss();

    #[cfg(target_arch = "aarch64")]
    {
        // Parse DTB before serial::init() (PL011 address comes from FDT)
        fdt::init(boot_info_addr);

        // Map device MMIO regions before any access
        let fdt = &*fdt::info_ptr();
        if fdt.pcie_ecam_base != 0 && fdt.pcie_ecam_size != 0 {
            mmu::map_device_range(fdt.pcie_ecam_base, fdt.pcie_ecam_size);
        }
        if fdt.gic_dist_base != 0 {
            mmu::map_device_range(fdt.gic_dist_base, 0x10000);
        }
        if fdt.gic_redist_base != 0 {
            // Each CPU's redistributor frame is 0x20000 bytes; map all CPUs.
            let n = (fdt.cpu_count as u64).max(1);
            mmu::map_device_range(fdt.gic_redist_base, n * 0x20000);
        }

        // SAFETY: G_BOOT_INFO is touched only here during single-
        // threaded boot before any AP starts.
        boot_shim_fdt::shim(&mut *G_BOOT_INFO.0.get(), boot_info_addr);
    }

    #[cfg(target_arch = "x86_64")]
    boot_shim_x86::shim(&mut *G_BOOT_INFO.0.get(), boot_info_addr);

    kernel_boot(&*G_BOOT_INFO.0.get());
    }
}

/// Entry from Limine bootloader (BSS already zeroed, FDT/ECAM handled by limine_entry.rs).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_boot_from_bootinfo(info: *const BootInfo) {
    unsafe {
        kernel_boot(&*info);
    }
}
