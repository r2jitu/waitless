ENTRY(_start)

SECTIONS {
    . = 1M;

    /* Multiboot2 header — scanned by GRUB/QEMU multiboot loader */
    .multiboot2 ALIGN(8) : {
        KEEP(*(.multiboot2))
    }

    /* PVH (Xen) ELF note — required by QEMU 10.x for 64-bit ELF -kernel */
    .note.Xen ALIGN(8) : {
        KEEP(*(.note.Xen))
    }

    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    /* Limine boot protocol requests — contiguous, between start/end markers.
       Limine scans the ELF for these sections to discover boot requests. */
    .limine_requests_start ALIGN(16) : {
        KEEP(*(.limine_requests_start))
    }
    .limine_requests ALIGN(16) : {
        KEEP(*(.limine_requests))
    }
    .limine_requests_end ALIGN(16) : {
        KEEP(*(.limine_requests_end))
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    .init_array ALIGN(8) : {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    }

    .bss ALIGN(4K) : {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        __bss_end = .;
    }

    /* Boot-time stack and page tables: placed OUTSIDE the [__bss_start,
       __bss_end] range so zero_bss() does not wipe them while CR3 is
       still pointing at them during early kernel_main execution. */
    .boot_bss (NOLOAD) : {
        . = ALIGN(4096);
        *(.boot_bss)
    }

    . = ALIGN(4K);
    _kernel_end = .;
}
