/* Supplemental linker script for Limine higher-half boot.
 *
 * Passed as an additional -T flag after the main unikernel.ld.
 * Overrides the PROVIDE(__kernel_base) weak symbol with a strong definition,
 * moving the kernel to the top-2GB region required by Limine revision 3
 * (>= 0xFFFF800000000000) and compatible with -mcmodel=kernel.
 *
 * Limine maps:
 *   - Kernel segments at their linked virtual addresses
 *   - Identity map of first 4GB (physical == virtual for MMIO/bitmap/heap)
 *   - HHDM (Higher Half Direct Map) for all physical memory
 */

ENTRY(kernel_boot_from_bootinfo)

__kernel_base = 0xFFFFFFFF80100000;
