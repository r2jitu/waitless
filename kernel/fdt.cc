// kernel/fdt.cc — Minimal FDT (Device Tree Blob) scanner for ARM64
//
// Walks the DTB structure block looking for nodes with specific compatible
// strings and extracts their MMIO base addresses from the reg property.
//
// Assumptions (standard for QEMU virt and Apple VZ):
//   • #address-cells = 2, #size-cells = 2 at root level
//   • reg addresses stored as (hi32 BE, lo32 BE) → 64-bit address
//   • Devices of interest are direct children of root (depth 1) or /soc (depth 2)

#include "kernel/fdt.h"

#if defined(__aarch64__)

namespace fdt {

static Info g_info;

// ---- Big-endian helpers ----------------------------------------------------

static inline uint32_t be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

// Read a 2-cell big-endian address (hi32, lo32) → 64-bit.
static inline uint64_t be64_2cell(const uint8_t* p) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

// ---- String helpers --------------------------------------------------------

static bool str_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a++ != *b++) return false;
    }
    return *a == *b;
}

// Check if the null-string list [data, data+len) contains null-terminated 'needle'.
static bool strlist_has(const uint8_t* data, uint32_t len, const char* needle) {
    const uint8_t* end = data + len;
    const uint8_t* p   = data;
    while (p < end) {
        if (str_eq((const char*)p, needle)) return true;
        while (p < end && *p) ++p;
        if (p < end) ++p; // skip null terminator
    }
    return false;
}

// ---- DTB structure tokens (all big-endian uint32) --------------------------

static constexpr uint32_t FDT_MAGIC      = 0xD00DFEED;
static constexpr uint32_t FDT_BEGIN_NODE = 1;
static constexpr uint32_t FDT_END_NODE   = 2;
static constexpr uint32_t FDT_PROP       = 3;
static constexpr uint32_t FDT_NOP        = 4;
static constexpr uint32_t FDT_END        = 9;

// Compatible flags set while processing a single node's properties.
static constexpr int CF_PL011  = 1 << 0; // "arm,pl011"
static constexpr int CF_VIRTIO = 1 << 1; // "virtio,mmio"
static constexpr int CF_GICV2  = 1 << 2; // "arm,gic-400" / "arm,cortex-a15-gic"
static constexpr int CF_PCI    = 1 << 3; // device_type="pci" or "pci-host-ecam-generic"
static constexpr int CF_MEMORY = 1 << 4; // device_type="memory" — physical RAM range
// GICv3 ("arm,gic-v3"): detected but intentionally NOT stored — skip GIC init.

// ---- Main parser -----------------------------------------------------------

void init(uint64_t dtb_addr) {
    if (dtb_addr == 0) return;
    const uint8_t* dtb = reinterpret_cast<const uint8_t*>(dtb_addr);

    if (be32(dtb) != FDT_MAGIC) return; // not a valid DTB

    const uint32_t off_struct  = be32(dtb + 8);
    const uint32_t off_strings = be32(dtb + 12);

    const uint8_t* strings = dtb + off_strings;
    const uint8_t* p       = dtb + off_struct;

    // Per-node state stack (depth-indexed).
    // We scan nodes at any depth — devices can be under /soc or root.
    static constexpr int MAX_DEPTH = 8;
    struct NodeState {
        int            compat;       // CF_* flags set from "compatible" property
        uint64_t       reg;          // first address from "reg" property
        uint64_t       reg_size;     // first size from "reg" property
        bool           has_reg;      // true once "reg" has been read
        const uint8_t* ranges_data;  // pointer into DTB for "ranges" property value
        uint32_t       ranges_len;   // byte length of "ranges" value
    };
    NodeState stack[MAX_DEPTH] = {};
    int depth = 0;

    while (true) {
        // Each token is a 4-byte big-endian word.
        uint32_t tok = be32(p); p += 4;

        switch (tok) {

        case FDT_BEGIN_NODE: {
            // Push a fresh node state for the new depth level.
            if (depth < MAX_DEPTH)
                stack[depth] = {0, 0, 0, false, nullptr, 0};
            depth++;
            // Skip the null-terminated node name.
            while (*p) ++p;
            ++p; // skip the null byte
            // Align to 4-byte boundary.
            p = reinterpret_cast<const uint8_t*>(
                    (reinterpret_cast<uintptr_t>(p) + 3) & ~(uintptr_t)3);
            break;
        }

        case FDT_END_NODE: {
            // Process the node we're exiting (stack[depth-1]).
            depth--;
            if (depth >= 0 && depth < MAX_DEPTH) {
                const NodeState& ns = stack[depth];
                if (ns.has_reg) {
                    if ((ns.compat & CF_PL011) && g_info.uart_base == 0)
                        g_info.uart_base = ns.reg;

                    if ((ns.compat & CF_VIRTIO) && g_info.virtio_count < 32)
                        g_info.virtio_bases[g_info.virtio_count++] = ns.reg;

                    // Only store GICv2 distributor base; skip GICv3 (no driver).
                    if ((ns.compat & CF_GICV2) && g_info.gic_dist_base == 0)
                        g_info.gic_dist_base = ns.reg;

                    if ((ns.compat & CF_PCI) && g_info.pcie_ecam_base == 0) {
                        g_info.pcie_ecam_base = ns.reg;
                        g_info.pcie_ecam_size = ns.reg_size;
                    }

                    // Parse PCI "ranges" to find the 32-bit MMIO aperture.
                    // Each entry: [flags(4), child_hi(4), child_lo(4),
                    //              cpu_hi(4), cpu_lo(4), size_hi(4), size_lo(4)] = 28 bytes.
                    // Space type bits[25:24]: 0=cfg 1=I/O 2=32-bit-mem 3=64-bit-mem.
                    if ((ns.compat & CF_PCI) && ns.ranges_data
                            && ns.ranges_len >= 28 && g_info.pci_mmio32_base == 0) {
                        for (uint32_t off = 0; off + 28 <= ns.ranges_len; off += 28) {
                            const uint8_t* e   = ns.ranges_data + off;
                            uint32_t flags     = be32(e);
                            int space          = (flags >> 24) & 3;
                            if (space == 2) { // 32-bit memory space
                                uint64_t cpu_hi = be32(e + 12), cpu_lo = be32(e + 16);
                                g_info.pci_mmio32_base = (cpu_hi << 32) | cpu_lo;
                                g_info.pci_mmio32_size =
                                    ((uint64_t)be32(e + 20) << 32) | be32(e + 24);
                                break;
                            }
                        }
                    }

                    if ((ns.compat & CF_MEMORY) && g_info.ram_size == 0) {
                        g_info.ram_base = ns.reg;
                        g_info.ram_size = ns.reg_size;
                    }
                }
            }
            break;
        }

        case FDT_PROP: {
            uint32_t       vlen    = be32(p);     p += 4;
            uint32_t       nameoff = be32(p);     p += 4;
            const uint8_t* vdata   = p;
            // Advance past the value (padded to 4-byte alignment).
            p += (vlen + 3) & ~(uint32_t)3;

            // Process property for the current node (stack[depth-1]).
            int d = depth - 1;
            if (d >= 0 && d < MAX_DEPTH) {
                const char* pname = (const char*)(strings + nameoff);

                if (str_eq(pname, "compatible")) {
                    if (strlist_has(vdata, vlen, "arm,pl011"))
                        stack[d].compat |= CF_PL011;
                    if (strlist_has(vdata, vlen, "virtio,mmio"))
                        stack[d].compat |= CF_VIRTIO;
                    if (strlist_has(vdata, vlen, "arm,gic-400") ||
                        strlist_has(vdata, vlen, "arm,cortex-a15-gic"))
                        stack[d].compat |= CF_GICV2;
                    if (strlist_has(vdata, vlen, "pci-host-ecam-generic"))
                        stack[d].compat |= CF_PCI;
                    // "arm,gic-v3" is explicitly not flagged (skip GIC init).
                }
                else if (str_eq(pname, "device_type")) {
                    // Canonical way to identify PCIe host bridge nodes.
                    if (strlist_has(vdata, vlen, "pci"))
                        stack[d].compat |= CF_PCI;
                    // Physical RAM nodes.
                    if (strlist_has(vdata, vlen, "memory"))
                        stack[d].compat |= CF_MEMORY;
                }
                else if (str_eq(pname, "reg") && vlen >= 8 && !stack[d].has_reg) {
                    // First address from reg: two 32-bit big-endian cells.
                    stack[d].reg     = be64_2cell(vdata);
                    // Read size if present (next 2 cells after address).
                    stack[d].reg_size = (vlen >= 16) ? be64_2cell(vdata + 8) : 0;
                    stack[d].has_reg = true;
                }
                else if (str_eq(pname, "ranges") && vlen > 0) {
                    stack[d].ranges_data = vdata;
                    stack[d].ranges_len  = vlen;
                }
            }
            break;
        }

        case FDT_NOP:
            break;

        case FDT_END:
            return; // clean exit

        default:
            return; // corrupted DTB — bail out
        }
    }
}

const Info& info() {
    return g_info;
}

} // namespace fdt

#endif // __aarch64__
