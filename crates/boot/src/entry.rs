// boot/entry.rs — Kernel entry point + boot shim (Rust)
//
// Called from boot.S after the processor is in 64-bit mode with a valid stack.
// On x86_64: RDI = multiboot2 info physical address.
// On aarch64: x0  = DTB physical address (QEMU or HVF runner).
//
// Initialises every subsystem in dependency order, then calls waitless_init()
// which spawns the app's `#[waitless::init]` body as a task on core 0's arena.

#![no_std]

extern crate alloc;

use core::ptr;

extern crate net_stack as net;

// Boot assembly — compiled by LLVM's integrated assembler via global_asm!.
//
// x86_64 boot.S contains 32-bit absolute relocations (R_X86_64_32)
// targeting .boot_bss that cannot be linked into a higher-half ELF
// (Limine boot), so it lives in a separate `multiboot` crate that the
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

#[cfg(target_arch = "aarch64")]
use kernel_bare::aarch64::{exceptions, fdt, smp};
#[cfg(target_arch = "aarch64")]
use kernel_bare::mmu;
use kernel_bare::{mm, serial, types};
use types::{BootInfo, MEM_AVAILABLE, MemoryRegion, Protocol};
// `MAX_MEMORY_REGIONS` / `MEM_RESERVED` are used only by the
// multiboot/PVH memory-map scan in `boot_shim_x86`.
#[cfg(target_arch = "x86_64")]
use types::{MAX_MEMORY_REGIONS, MEM_RESERVED};

// ============================================================================
// Panic handler (required for rust_static_library)
// ============================================================================

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Capture into the in-band diag buffer first so the
    // `/diag-panic` HTTP endpoint can surface the message on
    // systems where serial-port-output isn't externally readable
    // (sandboxed GCE deploys).
    kernel_bare::diag::append(b"\n!!! PANIC on cpu ");
    kernel_bare::diag::append_u32(kernel_bare::cpu_id());
    kernel_bare::diag::append(b" !!!\n");
    if let Some(loc) = info.location() {
        kernel_bare::diag::append(b"  at ");
        kernel_bare::diag::append(loc.file().as_bytes());
        kernel_bare::diag::append(b":");
        kernel_bare::diag::append_u32(loc.line());
        kernel_bare::diag::append(b"\n");
    }
    use core::fmt::Write;
    struct DiagWriter;
    impl Write for DiagWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            kernel_bare::diag::append(s.as_bytes());
            Ok(())
        }
    }
    kernel_bare::diag::append(b"  message: ");
    let _ = write!(DiagWriter, "{}", info.message());
    kernel_bare::diag::append(b"\n");

    // Flush whatever early-boot lines are buffered through the
    // current (16550 / PL011) backend before printing PANIC, so
    // the operator sees the boot context that led up to the panic
    // even if the crash beat the post-PCI upgrade.
    serial::flush_early_buf();
    // Mirror the panic location + message that we just appended to
    // the diag ring to serial as well — the high-concurrency cliff
    // investigation (2026-05-24) revealed that under burst load all
    // 8 cores can panic on alloc failure simultaneously, and
    // `/diag-panic` is unreachable by then because the unikernel is
    // about to power off. A serial dump on every panic is the only
    // post-mortem channel that survives.
    //
    // Single `write_fmt` so the whole block goes out under one
    // `SERIAL_TX_LOCK` acquire — without that, multiple cores
    // panicking simultaneously would interleave at `write_str`-chunk
    // granularity, garbling both records. When location is None the
    // `"?":0` rendering is intentional and unambiguous (no real path
    // is `?` and no real source line is 0).
    let (file, line) = info
        .location()
        .map(|l| (l.file(), l.line()))
        .unwrap_or(("?", 0));
    serial::write_fmt(format_args!(
        "\n=== PANIC ===\n  at {}:{}\n  msg: {}\n==============\n",
        file,
        line,
        info.message(),
    ));
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
        loop {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
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
        loop {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

// ============================================================================
// Extern declarations — linker symbols and app entry point only
// ============================================================================

// App entry point. Rust ABI is fine: both sides are Rust and the
// function takes no args and returns nothing. The `#[no_mangle]` on
// the emitting side (the `#[waitless::init]` macro output) gives us a
// stable symbol name for link resolution.
unsafe extern "Rust" {
    fn waitless_init();
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
                return;
            }

            // Try Multiboot2
            let mb2_total_size = ptr::read_volatile(boot_info_addr as *const u32);
            if (8..65536).contains(&mb2_total_size) {
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
            let _ = (ram_base, ram_size);
        }
    }
}

// ============================================================================
// Shared boot sequence
// ============================================================================

// Scratch for the legacy entry's BootInfo — populated by the arch-
// specific shim, then handed to `kernel_boot` as an immutable ref.
struct BootInfoCell(core::cell::UnsafeCell<BootInfo>);
// SAFETY: BSP-only during boot; the shim writes it and `kernel_boot`
// reads it, both on the same thread with no overlap.
unsafe impl Sync for BootInfoCell {}

static G_BOOT_INFO: BootInfoCell = BootInfoCell(core::cell::UnsafeCell::new(BootInfo::zeroed()));

unsafe fn kernel_boot(info: &BootInfo) {
    unsafe {
        // Mark boot-start as early as possible — `serial::init` itself
        // takes a few hundred microseconds (UART config + FIFO drain) and
        // we want every subsequent log line's timestamp to include it.
        kernel_bare::time::mark_boot_start();
        serial::init();

        // Force TSC calibration BEFORE the first log line. On x86 without
        // CPUID 0x15/0x16 (which `-cpu host` masks out under standard KVM —
        // max basic leaf reads as 0xd) `cycles_per_us` falls back to a PIT
        // calibration; if that runs lazily inside the first `klog!`, the
        // elapsed cycles for that line's timestamp are captured before the
        // calibration delay, so the line shows `[0.000]` and every subsequent
        // line is offset by the calibration cost. Eager calibration here
        // keeps every timestamp truthful and lets us shorten the PIT window.
        let _ = kernel_bare::time::cycles_per_us();
        #[cfg(target_arch = "aarch64")]
        klog!("Waitless v0.1.0 (aarch64)\n");
        #[cfg(target_arch = "x86_64")]
        klog!("Waitless v0.1.0 (x86_64)\n");

        #[cfg(target_arch = "x86_64")]
        {
            kernel_bare::x86_64::gdt::init();
            kernel_bare::x86_64::idt::init();
        }
        #[cfg(target_arch = "aarch64")]
        exceptions::init();

        mm::init(info as *const BootInfo);

        #[cfg(target_arch = "x86_64")]
        kernel_bare::x86_64::apic::init();

        #[cfg(target_arch = "x86_64")]
        {
            // Seed the RSDP hint before `detect_cpus()` — under UEFI
            // (GCE's OVMF) the BIOS-area scan fallback fails, so without
            // this we'd silently boot 1 CPU.
            kernel_bare::x86_64::acpi::set_rsdp(info.rsdp_paddr);
        }

        // Detect actual core count, publish via `set_num_workers`, then
        // size every `PerWorker<T>`. Strict ordering: `mm::init` first
        // (heap up), then `acpi::set_rsdp` (x86 detect needs ACPI), then
        // `percpu::init`, then `init_tls` (which reads `percpu::get(0)`
        // for GS_BASE / TPIDR_EL1 — running it before `percpu::init`
        // points the TLS register at a null cell and every later
        // `cpu_id()` returns garbage).
        #[cfg(target_arch = "aarch64")]
        let cpu_count = kernel_bare::aarch64::fdt::info().cpu_count;
        #[cfg(target_arch = "x86_64")]
        let cpu_count = kernel_bare::x86_64::acpi::detect_cpus();
        kernel_bare::percpu::init(cpu_count);

        #[cfg(target_arch = "x86_64")]
        kernel_bare::x86_64::smp::init_tls(0);
        #[cfg(target_arch = "aarch64")]
        kernel_bare::aarch64::smp::init_tls(0);

        // ── Identity / platform / memory diagnostics ────────────────────
        {
            let mut buf = [0u8; 128];
            let n = kernel_bare::cpu_info::summary(&mut buf);
            // SAFETY: `summary` only writes ASCII chars produced via
            // `core::fmt::Write` over a `&str`-backed source.
            let cpu = core::str::from_utf8_unchecked(&buf[..n]);
            klog!("cpu: {} × {}\n", cpu_count, cpu);
        }
        klog!("platform: {}\n", kernel_bare::cpu_info::hypervisor());
        klog!(
            "mem: {} / {} MB heap\n",
            mm::free_memory() / (1024 * 1024),
            mm::total_memory() / (1024 * 1024)
        );
        #[cfg(target_arch = "x86_64")]
        klog!("irq: xAPIC online\n");
        #[cfg(target_arch = "aarch64")]
        klog!(
            "irq: GICv{} configured\n",
            kernel_bare::aarch64::fdt::info().gic_version
        );
        klog!("smp: {} workers\n", cpu_count);
        #[cfg(target_arch = "x86_64")]
        klog!("console: 16550 UART @ COM1\n");

        bus::pci::init();
        klog!("pci: {} devices on bus 0\n", bus::pci::device_count());
        bus::pci::log_devices();

        // Two-stage console: 16550 (x86) gives us early-boot output
        // before the PCI bus is scanned; once `pci::init` completes we
        // try to attach virtio-console-pci so subsequent log lines —
        // most of boot, and all of runtime — emit through the batched
        // virtio path (1 vmexit per ≤256-byte chunk vs 1 per byte for
        // 16550). No-op on aarch64; that path's `serial::aarch64::init`
        // already picks the best FDT-advertised backend.
        let upgraded = serial::upgrade_after_pci();
        if upgraded {
            klog!("console: upgraded to virtio-console-pci (batched, ≤256 B/vmexit)\n");
        }
        // Drain the early-boot buffer through the now-chosen backend.
        // If we just upgraded, every pre-PCI line gets flushed via
        // virtio-console (one batched ≤256 B emit). If we didn't, it
        // fans out through the 16550 at ~1 ms / line — same cost we
        // would have paid emitting inline, just deferred.
        serial::flush_early_buf();

        // NIC bring-up. `nic::init()` tries gVNIC first
        // (preferred on GCE — native RSS multi-queue) then falls back
        // to virtio-net (kvm-vm, HVF, default GCE instances).
        let net_ok = nic::init();
        if !net_ok {
            klog!("nic: none (no gVNIC, no virtio-net)\n");
        } else {
            // Cache MAC address for multi-core safe access.
            net::ethernet_send::init_mac();
            let mut mac = [0u8; 6];
            nic::get_mac(mac.as_mut_ptr());
            klog!(
                "nic: {} {} qps={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                nic::driver_name(),
                if nic::num_queue_pairs() > 1 {
                    "Tier-1"
                } else {
                    "Tier-2"
                },
                nic::num_queue_pairs(),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            // IP bring-up (DHCP / static) happens inside the app's
            // `#[waitless::init]` task via `waitless::net::Net::enable(...).await`.
            // Driver-level config like multi-queue activation is
            // self-contained in the driver's `init()`.

            net::tcp::init();
            // Initialise IPv4/IPv6 stack state (ARP cache, our local
            // addrs, NDP, etc.). `net_receive` matches on the IP
            // protocol byte directly.
            net::init_stack();
            nic::enable_irq();
            klog!("net: stack ready (Ethernet/ARP/IPv4/TCP/UDP)\n");

            #[cfg(target_arch = "x86_64")]
            {
                // Serial RX interrupt (IRQ4 / vector 36) for Ctrl-C wakeup
                kernel_bare::x86_64::idt::register_handler(36, serial_rx_isr_trampoline);
                kernel_bare::x86_64::idt::enable_irq(4);
                serial::enable_rx_irq();
            }
        }

        // Idle-path infrastructure (timer IRQ + SGI handler + IRQ unmask) is
        // orthogonal to the NIC. Apps without networking still need
        // `kernel_bare::cpu::idle_bounded` to wake from WFI when the 1 ms
        // generic-timer fires — `kernel_bare::runtime`'s `Sleep` future depends
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
        // on a single-CPU VM (or, on native, via `WAITLESS_CPUS=1`).
        // `percpu::init` already ran near the top of boot — that publishes
        // the worker count and sizes every `PerWorker<T>` to it; the
        // SMP layer below is only responsible for waking the secondaries.
        #[cfg(target_arch = "aarch64")]
        {
            if cpu_count > 1 {
                kernel_bare::aarch64::smp::start_secondary_cores(cpu_count);
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
                        kernel_bare::x86_64::smp::start_secondary_cores(cpu_count);
                    }
                }
            }
        }

        // Register event-loop callbacks. `check_shutdown` reads the
        // serial port and is NIC-independent — always wire it. The
        // NIC-specific hooks (poll/drain/flush/rearm/idle) only make
        // sense when a NIC probed.
        kernel_bare::eventloop::set_check_shutdown(serial::check_shutdown);
        if net_ok {
            net::init_eventloop();
            kernel_bare::eventloop::set_idle(idle_cb);
        }

        // Publish the read-only boot snapshot to apps. Must run after
        // SMP and NIC init so `num_cpus` and `nics` are final.
        publish_boot_info(net_ok);

        // Register the bare-metal async runtime with `//crates/runtime/executor`.
        // Must happen before `waitless_init` so the app can `spawn` / `sleep_us`.
        kernel_bare::runtime::init();
        klog!(
            "runtime: {} workers ready\n",
            kernel_bare::percpu::num_cores()
        );

        // `waitless_init()` (generated by `#[waitless::init]`) spawns the app's
        // init body on core 0's arena and returns immediately. The
        // event loop below polls that task, so DHCP / async setup /
        // `waitless::run(app)` all run while `net_flush_cb`, `net_poll_cb`,
        // etc. are ticking — no separate pre-eventloop phase, no
        // deferred-TX-kick race.
        waitless_init();

        if !kernel_bare::eventloop::is_shutdown() {
            kernel_bare::eventloop::run(0);
        }

        klog!("\n[SHUTDOWN] Powering off.\n");

        // Stop secondary cores before system poweroff
        #[cfg(target_arch = "aarch64")]
        kernel_bare::aarch64::smp::request_shutdown();

        arch_shutdown();
    }
}

/// Populate `waitless::boot_info()` from kernel + driver state. Called
/// exactly once during `kernel_boot` after SMP and NIC init. Apps
/// read the resulting snapshot via `waitless::boot_info()` to size
/// per-core buffers, log runtime identity, etc.
fn publish_boot_info(net_ok: bool) {
    use alloc::vec::Vec;
    use waitless::boot_info::{BootInfoParams, NicInfo};

    let mut nics: Vec<NicInfo> = Vec::new();
    if net_ok {
        let mut mac = [0u8; 6];
        nic::get_mac(mac.as_mut_ptr());
        nics.push(NicInfo {
            name: nic::driver_name(),
            mac,
            num_queue_pairs: nic::num_queue_pairs(),
        });
    }

    waitless::boot_info::init_boot_info(BootInfoParams {
        ram_bytes: kernel_bare::mm::total_memory(),
        num_cpus: kernel_bare::percpu::num_cores(),
        // Surface the kernel command line. On aarch64 this is
        // `chosen.bootargs` from the FDT (HVF runner's
        // `--bootargs=` flag, QEMU `-append`, …); on x86_64
        // (Limine boot) we don't yet plumb the Limine
        // KernelFile cmdline through, so it's an empty string.
        // Apps key configuration off it (e.g. `quic.log=events`
        // to flip the QUIC stack into verbose-event mode).
        boot_args: boot_args(),
        nics,
        // RTC isn't queried at boot yet. Left `None`; a future phase
        // can plumb ACPI FADT CMOS / FDT rtc.
        rtc_epoch: None,
    });
}

/// Per-arch boot-args resolver. Aarch64 reads from the FDT
/// (`chosen.bootargs`, written by HVF runner's `--bootargs=` /
/// QEMU `-append`); x86_64 reads from the static buffer that
/// `limine_entry` populates from Limine's
/// `ExecutableCmdlineRequest`. Both arches return `""` when no
/// cmdline was supplied — apps tolerate the empty string fine
/// (boot-arg toggles like `quic.log=events` just stay at their
/// defaults).
#[cfg(target_arch = "aarch64")]
fn boot_args() -> &'static str {
    kernel_bare::aarch64::fdt::info().boot_args()
}

#[cfg(target_arch = "x86_64")]
fn boot_args() -> &'static str {
    kernel_bare::x86_64::boot_args::boot_args()
}

/// Event loop idle callback. Core-aware:
/// - Core 0: arm VirtIO RX notifications + yield/WFI (wakes on data or interrupt)
/// - Other cores: yield/WFI (wakes when the IO thread or distributor sends data)
///   On the HVF runner, yield MMIO parks the thread at zero CPU cost.
///   We use WFI and not WFE: WFE wakes from any SEV (including spurious ones),
///   which starved the host-side TCP proxy thread on Apple hypervisors.
///   `wake_cores()` sends SGI so WFI wakes correctly.
/// Consecutive idle rounds (event-loop idle commits with no intervening
/// work) after which a polling NIC switches from busy-poll to a
/// timer-bounded HLT. The event loop only reaches `idle_cb` after a full
/// idle spin window, and `idle_rounds` resets on *any* work, so this is
/// only crossed during genuinely sustained idle — never under load. High
/// enough that a lightly-loaded server with sub-window traffic gaps keeps
/// busy-polling (no added latency); low enough that a truly idle core
/// stops monopolizing its vCPU within a few ms. Only the x86_64 polling
/// path (gve) consumes it; aarch64 idle uses the GIC/yield-register path.
#[cfg(target_arch = "x86_64")]
const DEEP_IDLE_ROUNDS: u32 = 32;

fn idle_cb(core_id: u32, idle_rounds: u32) {
    // No wake-up source → busy-poll. (Happens when the transport
    // doesn't expose any IRQ path: a polling NIC like gve `idle: None`,
    // aarch64 without GIC configured, legacy PCI without an IRQ line.)
    //
    // This `idle_cb` is only ever reached *after* the event loop has
    // spun a full (adaptive) idle window with no work, so under load it
    // is never entered — the busy-poll spin stays hot and returning here
    // (→ keep spinning) preserves the saturated-throughput path. Once a
    // core is *sustained*-idle (`idle_rounds >= DEEP_IDLE_ROUNDS`) a
    // polling NIC instead issues a timer-bounded HLT: each HLT is a
    // VMEXIT the hypervisor can use to schedule co-tenants (good citizen
    // on shared/oversubscribed shapes like e2-small), and a real sleep
    // on hosts where HLT blocks (qemu-TCG idle ~5%). The ~1 ms timer
    // re-polls RX, so no RX IRQ is needed; guarded on `timer_available()`
    // so a host without the timer can't sleep forever. On e2 HLT is a
    // near-NOP so CPU% doesn't drop (platform wall, see docs/gvnic.md
    // T7), but the VMEXITs still hand the host scheduling points. See
    // reference_idle_cpu_spin.
    if !nic::irq_idle_supported() {
        #[cfg(target_arch = "x86_64")]
        if idle_rounds >= DEEP_IDLE_ROUNDS && kernel_bare::x86_64::apic::timer_available() {
            // Arm this core's RX interrupt (for a polling driver that
            // supports it — gve via MSI-X) so the timer-bounded HLT wakes
            // on a packet instead of only the ~1 ms timer backstop. If a
            // packet already landed, skip the sleep and re-poll. Returns
            // false (→ timer-only idle, today's behaviour) when the driver
            // has no interrupt-arming surface.
            if !nic::arm_rx_idle() {
                kernel_bare::cpu::idle_bounded();
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = idle_rounds;
        return;
    }
    if core_id == 0 || kernel_bare::percpu::num_cores() <= 1 {
        waitless::wait_for_events();
    } else {
        // AP idle. On aarch64 + HVF we write the core_id to the
        // yield register (vs the BSP's `write 0`) so the runner
        // knows which vCPU thread to park. Falls back to a plain
        // WFI/HLT when the yield register isn't present.
        #[cfg(target_arch = "aarch64")]
        {
            let yield_addr = kernel_bare::aarch64::fdt::info().yield_mmio_base;
            if yield_addr != 0 {
                unsafe {
                    core::ptr::write_volatile(yield_addr as *mut u32, core_id);
                }
                return;
            }
        }
        kernel_bare::cpu::idle_unbounded();
    }
}

// x86_64: ISR trampoline for serial RX (ignores InterruptFrame pointer)
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn serial_rx_isr_trampoline(
    _frame: *mut kernel_bare::x86_64::idt::InterruptFrame,
) {
    serial::rx_isr();
}

// ============================================================================
// Public entry points — extern "C" for boot.S and limine_entry
// ============================================================================

/// Legacy entry point called from boot.S.
///
/// # Safety
///
/// Must be called exactly once, by the boot assembly, on the BSP before
/// any AP starts and with no other code running. The processor must be
/// in 64-bit mode (x86_64) / EL1 (aarch64) with a valid stack. BSS is
/// not yet zeroed — this function zeroes it. `boot_info_addr` is the
/// raw boot-protocol pointer (x86_64: multiboot2/PVH info physical
/// address, or 0 for none; aarch64: DTB physical address) and must
/// either be 0 or point to a valid structure for the active protocol.
/// Never returns.
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
///
/// # Safety
///
/// Must be called exactly once, by `limine_entry`, on the BSP before
/// any AP starts. `info` must point to a fully populated, valid
/// `BootInfo` that stays live for the rest of the kernel's lifetime.
/// Never returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_boot_from_bootinfo(info: *const BootInfo) {
    unsafe {
        kernel_boot(&*info);
    }
}
