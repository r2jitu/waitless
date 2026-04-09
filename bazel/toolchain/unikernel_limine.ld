/* Limine higher-half linker script for x86_64.
 *
 * Limine revision 3 requires the kernel to be linked at higher-half virtual
 * addresses (>= 0xFFFF800000000000). We pick the top-2GB region
 * (0xFFFFFFFF80000000+), which matches `-mcmodel=kernel` and is the
 * conventional Linux kernel layout.
 *
 * Limine maps:
 *   - Kernel segments at their linked virtual addresses
 *   - Identity map of first 4GB (physical == virtual for MMIO/bitmap/heap)
 *   - HHDM (Higher Half Direct Map) for all physical memory
 *
 * Layout mirrors unikernel.ld but with `__kernel_base` fixed to higher-half.
 * (We don't share unikernel.ld + an override script: lld evaluates SECTIONS
 * at script-parse time, so a `--defsym` or supplemental `-T` arrives too
 * late to influence the location counter.)
 */

/* Limine reads the actual entry point from the EntryPointRequest in
   `.limine_requests`, not from the ELF entry. We set ENTRY() to a real
   symbol anyway so lld doesn't complain and so --gc-sections has a root
   to walk from. The Limine x86_64 stub enables SSE and aligns the stack
   before tail-calling the Rust kernel_boot. */
ENTRY(limine_entry_stub)

__kernel_base = 0xFFFFFFFF80100000;

/* Explicit PHDRS so lld groups sections by us, not by inferred flags.
   Limine rejects ELFs where two PT_LOAD segments with different
   permissions overlap in the same memory page; in particular, the
   .limine_requests section is RW while the marker sections are R--,
   so without explicit PHDRS lld places them in three different
   segments inside the same page and Limine bails out. We force all
   three limine_requests* sections (and .data/.bss) into a single
   `data` segment. */
PHDRS {
    text   PT_LOAD FLAGS(5);  /* R-X */
    rodata PT_LOAD FLAGS(4);  /* R-- */
    data   PT_LOAD FLAGS(6);  /* RW- */
}

SECTIONS {
    . = __kernel_base;

    /* Multiboot2 header — kept for symmetry; not used by Limine but
       harmless. */
    .multiboot2 ALIGN(8) : {
        KEEP(*(.multiboot2))
    } :rodata

    /* PVH (Xen) ELF note — required by QEMU 10.x for 64-bit ELF -kernel,
       harmless under Limine. */
    .note.Xen ALIGN(8) : {
        KEEP(*(.note.Xen))
    } :rodata

    .text ALIGN(4K) : {
        *(.text .text.*)
    } :text

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    } :rodata

    /* Limine boot protocol requests — contiguous, between start/end markers.
       Limine scans the ELF for these sections to discover boot requests
       and writes the response pointer into each request struct, so they
       belong in the RW data segment. */
    .limine_requests_start ALIGN(4K) : {
        KEEP(*(.limine_requests_start))
    } :data
    .limine_requests ALIGN(16) : {
        KEEP(*(.limine_requests))
    } :data
    .limine_requests_end ALIGN(16) : {
        KEEP(*(.limine_requests_end))
    } :data

    .data ALIGN(4K) : {
        *(.data .data.*)
    } :data

    .init_array ALIGN(8) : {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    } :data

    .bss ALIGN(4K) : {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        __bss_end = .;
    } :data

    /* Boot-time stack and page tables: placed OUTSIDE the [__bss_start,
       __bss_end] range so zero_bss() does not wipe them while CR3 is
       still pointing at them during early kernel_main execution. */
    .boot_bss (NOLOAD) : {
        . = ALIGN(4096);
        *(.boot_bss)
    } :data

    . = ALIGN(4K);
    _kernel_end = .;
}
