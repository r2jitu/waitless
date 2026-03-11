// kernel/entry.cc — C++ kernel entry point
//
// Called from boot.S after the processor is in 64-bit mode with a valid stack.
// On x86_64: RDI = multiboot2 info physical address.
// On aarch64: x0  = DTB physical address (QEMU or VZ.framework).
//
// Initialises every subsystem in dependency order, then calls uni_main().
// Every driver/network call from this point is a direct in-process function
// call — no syscalls, no mode switches, no kernel/user copies.

#include "drivers/pci.h"
#include "drivers/virtio_net.h"
#include "kernel/arch.h"
#include "kernel/boot_info.h"
#include "kernel/boot_shim.h"
#include "kernel/aarch64/fdt.h"
#include "kernel/mm.h"
#include "kernel/panic.h"
#include "kernel/serial.h"
#include "net/dhcp.h"
#include "net/tcp.h"

#if defined(__x86_64__)
#include "kernel/x86_64/gdt.h"
#include "kernel/x86_64/idt.h"
#include "kernel/x86_64/serial.h"
#elif defined(__aarch64__)
#include "kernel/aarch64/exceptions.h"
#include "kernel/aarch64/mmu.h"
#endif

// Provided by the user's application (e.g. apps/webserver/main.cc)
extern "C" int uni_main();

// Linker-generated symbols
extern "C" {
typedef void (*ctor_func_t)();
extern ctor_func_t __init_array_start[];
extern ctor_func_t __init_array_end[];
extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
}

static void zero_bss() {
  uint8_t *p = __bss_start;
  while (p < __bss_end)
    *p++ = 0;
}

static void call_global_constructors() {
  for (ctor_func_t *f = __init_array_start; f < __init_array_end; ++f) {
    (*f)();
  }
}

// Unified boot info, populated by protocol-specific shim before kernel_boot()
static boot::BootInfo g_boot_info;

// ---- Shared boot sequence (called after BootInfo is populated) ---------------

// Also callable from limine_entry.cc
extern "C" void kernel_boot_from_bootinfo(boot::BootInfo *info);

static void kernel_boot(boot::BootInfo *info) {
  serial::init();
  serial::printf("\n");
  serial::printf("==============================================\n");
#if defined(__aarch64__)
  serial::printf("  UniKernel v0.1.0  --  bare-metal aarch64\n");
#else
  serial::printf("  UniKernel v0.1.0  --  bare-metal x86_64\n");
#endif
  serial::printf("==============================================\n");
  serial::printf("  No OS, no syscalls, no context switches.\n");
  serial::printf("  All I/O is in-process via direct calls.\n");
  serial::printf("==============================================\n\n");

#if defined(__aarch64__)
  {
    const fdt::Info &dbg = fdt::info();
    serial::printf(
        "[FDT] uart=0x%lx pcie=0x%lx virtio=%d gic=0x%lx ram=0x%lx+%uMB\n",
        dbg.uart_base, dbg.pcie_ecam_base, dbg.virtio_count, dbg.gic_dist_base,
        dbg.ram_base, (unsigned)(dbg.ram_size / (1024 * 1024)));
  }
#endif

#if defined(__x86_64__)
  serial::printf("[INIT] GDT...\n");
  gdt::init();
  serial::printf("[INIT] IDT...\n");
  idt::init();
#elif defined(__aarch64__)
  serial::printf("[INIT] Exception vectors + GIC...\n");
  exceptions::init();
#endif

  serial::printf("[INIT] Memory manager...\n");
  mm::init(*info);
  serial::printf("       %u MB total, %u MB free\n",
                 (unsigned)(mm::get_total_memory() / (1024 * 1024)),
                 (unsigned)(mm::get_free_memory() / (1024 * 1024)));

  call_global_constructors();

#if defined(__aarch64__)
  // On ARM64, PCI may have been scanned early (for PCI console).
  // pci::init() is idempotent — safe to call even if already scanned.
  {
    const fdt::Info &fdt = fdt::info();
    if (fdt.pcie_ecam_base != 0) {
      serial::printf("[INIT] PCI bus scan...\n");
      pci::init();
    }
  }
#else
  serial::printf("[INIT] PCI bus scan...\n");
  pci::init();
#endif
  serial::printf("[INIT] Virtio-net driver...\n");
  bool net_ok = virtio_net::init();
  if (!net_ok) {
    serial::printf("       [WARN] No virtio-net device found.\n");
  } else {
    const uint8_t *mac = virtio_net::get_mac();
    serial::printf("       MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],
                   mac[1], mac[2], mac[3], mac[4], mac[5]);

    serial::printf("[INIT] DHCP...\n");
    bool dhcp_ok = net::dhcp::discover();
    if (dhcp_ok) {
      serial::printf("       IP obtained successfully\n");
    } else {
      serial::printf("       [WARN] DHCP failed, using 10.0.2.15/24\n");
      net::config.ip = net::Ipv4Addr::from(10, 0, 2, 15);
      net::config.subnet_mask = net::Ipv4Addr::from(255, 255, 255, 0);
      net::config.gateway = net::Ipv4Addr::from(10, 0, 2, 2);
      net::config.dns = net::Ipv4Addr::from(10, 0, 2, 3);
    }

    serial::printf("[INIT] TCP stack...\n");
    net::tcp::init();

    serial::printf("[INIT] Interrupt-driven idle...\n");
    virtio_net::enable_irq();
#if defined(__aarch64__)
    // Enable the virtual timer PPI (INTID 27) in the GIC so that the 100ms
    // one-shot timer inside arch::idle() can wake WFI.  On GICv2 (QEMU) all
    // PPIs are disabled by init_gicv2(); without this explicit enable the
    // timer fires but the GIC never asserts an interrupt to break WFI.
    if (fdt::info().gic_dist_base != 0) {
      exceptions::enable_timer_wakeup();
    }
    // Unmask only IRQ (DAIF.I bit 1 → mask 0x2).  Do NOT unmask FIQ or
    // SError — VZ.framework uses FIQ for hypervisor signaling and clearing
    // DAIF.F crashes the VM.
    if (fdt::info().gic_dist_base != 0) {
      asm volatile("msr daifclr, #0x2" ::: "memory");
    }
#endif
#if defined(__x86_64__)
    // Enable serial RX interrupt (IRQ4 / vector 36) so that Ctrl-C bytes
    // in the UART FIFO wake HLT.  Without this, idle() sleeps until the
    // next virtio-net IRQ and Ctrl-C only works if an HTTP request arrives.
    idt::register_handler(36, [](idt::InterruptFrame *) { serial::rx_isr(); });
    idt::enable_irq(4);
    serial::enable_rx_irq();
    // x86_64: interrupts stay masked (CLI).  idle() does STI;HLT;CLI
    // atomically, so the ISR only runs during the HLT window.
#endif
  }

  serial::printf("\n[BOOT] All subsystems ready. Starting application.\n\n");
  int ret = uni_main();
  serial::printf("\n[SHUTDOWN] Application exited with code %d.\n", ret);
  serial::printf("[SHUTDOWN] Powering off.\n");

  arch::shutdown();
}

// ---- Legacy entry point (called from boot.S) ---------------------------------

extern "C" void kernel_main(uint64_t boot_info_addr) {
  zero_bss();

#if defined(__aarch64__)
  // Parse the Device Tree Blob to discover MMIO device addresses.
  // Must be called before serial::init() (which uses fdt::info() for PL011
  // address) and before virtio_net::init() (FDT virtio-mmio scan).
  fdt::init(boot_info_addr);

  // Map device MMIO regions before any access.
  {
    const fdt::Info &fdt_info = fdt::info();
    if (fdt_info.pcie_ecam_base != 0 && fdt_info.pcie_ecam_size != 0) {
      mmu::map_device_range(fdt_info.pcie_ecam_base, fdt_info.pcie_ecam_size);
    }
    // GIC distributor + redistributor (needed by exceptions::init).
    if (fdt_info.gic_dist_base != 0) {
      mmu::map_device_range(fdt_info.gic_dist_base, 0x10000);
    }
    if (fdt_info.gic_redist_base != 0) {
      mmu::map_device_range(fdt_info.gic_redist_base, 0x20000);
    }
  }

  boot::shim_fdt(&g_boot_info, boot_info_addr);
#else
  boot::shim_x86(&g_boot_info, boot_info_addr);
#endif

  kernel_boot(&g_boot_info);
}

// ---- Entry point for Limine bootloader (called from limine_entry.cc) ---------
// BSS is already zeroed by Limine, FDT/ECAM already handled by limine_entry().

extern "C" void kernel_boot_from_bootinfo(boot::BootInfo *info) {
  kernel_boot(info);
}
