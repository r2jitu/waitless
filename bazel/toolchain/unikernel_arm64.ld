/* unikernel_arm64.ld — Linker script for ARM64 unikernel
 *
 * Load address: 0x40000000 (QEMU virt machine RAM base)
 *
 * Section layout:
 *   .text.boot  — Linux ARM64 Image header + primary_entry (MUST be first)
 *   .text       — kernel + driver + network + app code
 *   .rodata     — read-only data
 *   .data       — initialized data
 *   .init_array — C++ global constructor pointers
 *   .bss        — zero-initialized data (stack, page tables, heap)
 */

ENTRY(_start)

SECTIONS {
    . = 0x40000000;

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
    _end = .;                       /* used by Image header image_size field */
}
