/* unikernel_arm64.ld — Linker script for ARM64 unikernel (PIE)
 *
 * Link address: 0x00000000
 * Runtime load address: 0x40000000 (QEMU virt RAM base, also used by the
 * HVF runner). Kept PIE so boot.S's R_AARCH64_RELATIVE relocation loop
 * can be re-targeted at a different load address without re-linking —
 * useful if a future runner maps RAM somewhere else.
 *
 * Section layout:
 *   .text.boot  — Linux ARM64 Image header + primary_entry (MUST be first)
 *   .text       — kernel + driver + network + app code
 *   .rodata     — read-only data
 *   .rela.dyn   — R_AARCH64_RELATIVE relocation entries (processed by boot.S)
 *   .data       — initialized data
 *   .init_array — C++ global constructor pointers
 *   .bss        — zero-initialized data (stack, page tables, heap)
 */

ENTRY(_start)

SECTIONS {
    . = 0x00000000;
    _image_start = .;               /* used by Image header image_size field */

    /* ARM64 Image header and boot code must be at the very start */
    .text.boot ALIGN(4096) : {
        KEEP(*(.text.boot))
    }

    .text ALIGN(4096) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4096) : {
        *(.rodata .rodata.*)
    }

    /* Ethernet driver registration table. Each linked `uni-driver-*`
       crate emits one EthernetDriverReg into this section via
       register_ethernet_driver!; `drivers::net::init` walks
       [__start, __stop) to discover registered drivers. Empty when no
       driver crate is linked (compute-only apps). ALIGN(8) matches the
       two-pointer alignment of `&'static dyn EthernetDriver`. */
    .uni_drivers_ethernet ALIGN(8) : {
        __start_uni_drivers_ethernet = .;
        KEEP(*(.uni_drivers_ethernet))
        __stop_uni_drivers_ethernet = .;
    }

    /* Limine boot protocol requests — contiguous, between start/end markers.
       Limine scans the ELF for these sections to discover boot requests. */
    .limine_requests_start ALIGN(8) : {
        KEEP(*(.limine_requests_start))
    }
    .limine_requests ALIGN(8) : {
        KEEP(*(.limine_requests))
    }
    .limine_requests_end ALIGN(8) : {
        KEEP(*(.limine_requests_end))
    }

    /* PIE relocation table — processed by boot.S before C++ starts.
     * boot.S walks [__rela_start, __rela_end) applying R_AARCH64_RELATIVE. */
    .rela.dyn ALIGN(8) : {
        __rela_start = .;
        *(.rela.dyn)
        __rela_end = .;
    }

    .data ALIGN(4096) : {
        *(.data .data.*)
    }

    .init_array ALIGN(8) : {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    }

    .bss ALIGN(4096) : {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        __bss_end = .;
    }

    /* Boot-time stack and page tables: placed OUTSIDE [__bss_start, __bss_end]
       so BSS zeroing (which runs with the MMU already active) does NOT zero
       the page tables that the MMU is currently using. */
    .boot_bss (NOLOAD) : {
        . = ALIGN(65536);
        *(.boot_bss)
    }

    . = ALIGN(4096);
    _kernel_end = .;
    _end = .;
    _image_size = . - _image_start; /* total footprint including BSS */
}
