// kernel/entry.cc — C++ kernel entry point
//
// Called from boot.S after the processor is in 64-bit mode with a valid stack.
// On x86_64: RDI = multiboot2 info physical address.
// On aarch64: x0  = DTB physical address (ignored; we use a fixed memory map).
//
// Initialises every subsystem in dependency order, then calls uni_main().
// Every driver/network call from this point is a direct in-process function
// call — no syscalls, no mode switches, no kernel/user copies.

#include "kernel/arch.h"
#include "kernel/serial.h"
#include "kernel/mm.h"
#include "kernel/panic.h"
#include "drivers/pci.h"
#include "drivers/virtio_net.h"
#include "net/dhcp.h"
#include "net/tcp.h"

#if defined(__x86_64__)
#  include "kernel/gdt.h"
#  include "kernel/idt.h"
#elif defined(__aarch64__)
#  include "kernel/aarch64/exceptions.h"
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
    uint8_t* p = __bss_start;
    while (p < __bss_end) *p++ = 0;
}

static void call_global_constructors() {
    for (ctor_func_t* f = __init_array_start; f < __init_array_end; ++f) {
        (*f)();
    }
}

// ---- Kernel entry point (called from boot.S) --------------------------------

extern "C" void kernel_main(uint64_t boot_info_addr) {
    zero_bss();

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
    mm::init(boot_info_addr);
    serial::printf("       %u MB total, %u MB free\n",
                   (unsigned)(mm::get_total_memory() / (1024 * 1024)),
                   (unsigned)(mm::get_free_memory()  / (1024 * 1024)));

    call_global_constructors();

    serial::printf("[INIT] PCI bus scan...\n");
    pci::init();

    serial::printf("[INIT] Virtio-net driver...\n");
    bool net_ok = virtio_net::init();
    if (!net_ok) {
        serial::printf("       [WARN] No virtio-net device found.\n");
    } else {
        const uint8_t* mac = virtio_net::get_mac();
        serial::printf("       MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        serial::printf("[INIT] DHCP...\n");
        bool dhcp_ok = net::dhcp::discover();
        if (dhcp_ok) {
            serial::printf("       IP obtained successfully\n");
        } else {
            serial::printf("       [WARN] DHCP failed, using 10.0.2.15/24\n");
            net::config.ip          = net::Ipv4Addr::from(10, 0, 2, 15);
            net::config.subnet_mask = net::Ipv4Addr::from(255, 255, 255, 0);
            net::config.gateway     = net::Ipv4Addr::from(10, 0, 2, 2);
            net::config.dns         = net::Ipv4Addr::from(10, 0, 2, 3);
        }

        serial::printf("[INIT] TCP stack...\n");
        net::tcp::init();
    }

    serial::printf("\n[BOOT] All subsystems ready. Starting application.\n\n");
    int ret = uni_main();
    serial::printf("\n[SHUTDOWN] Application exited with code %d.\n", ret);
    serial::printf("[SHUTDOWN] Halting.\n");

    arch::cli();
    while (true) arch::hlt();
}
