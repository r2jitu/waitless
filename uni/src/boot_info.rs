// uni/boot_info.rs — Read-only snapshot of boot-time facts.
//
// Populated once per boot before `uni_boot` runs; immutable thereafter.
// Apps read it via `uni::boot_info()` to size per-core structures,
// decide which NIC driver is active, log runtime identity, etc.
//
// The bare-metal side populates the struct from `boot/entry.rs` after
// ACPI/FDT parsing + NIC discovery. The native side populates it from
// `init_native()` via sysconf/sysctl.
//
// Self-contained (only `core::`) so the file can compile as a
// standalone rust_test target for host-native unit tests.

use uni_percpu::InitOnce;

/// Maximum number of NICs describable in a single `BootInfo`. The
/// kernel currently activates at most one NIC per boot; four slots
/// gives headroom for multi-NIC configurations.
pub const MAX_NICS: usize = 4;

/// Description of one network interface as reported at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NicInfo {
    /// Driver kind: e.g. `"virtio-net"`, `"gve"`, `"posix"`.
    pub name: &'static str,
    /// Link-layer address.
    pub mac: [u8; 6],
    /// Number of RX/TX queue pairs negotiated at init.
    pub num_queue_pairs: u16,
}

impl NicInfo {
    /// All-zero placeholder used to pad the fixed-size storage
    /// array. Not included in the exposed `nics` slice.
    pub const EMPTY: NicInfo = NicInfo {
        name: "",
        mac: [0; 6],
        num_queue_pairs: 0,
    };
}

/// Read-only snapshot of boot-time facts exposed to app code.
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// Total RAM visible to the runtime, in bytes.
    pub ram_bytes: usize,
    /// Number of online CPUs.
    pub num_cpus: u32,
    /// Kernel command line / boot parameters, if any.
    pub boot_args: &'static str,
    /// NICs discovered at boot. Empty if no NIC came up (compute-only
    /// or pre-NIC paths).
    pub nics: &'static [NicInfo],
    /// Wall-clock epoch seconds at boot, if the platform had an RTC
    /// source. `None` means "don't know / not queried".
    pub rtc_epoch: Option<u64>,
}

/// Builder payload for `init_boot_info`. Backends populate this once
/// per boot from platform-specific sources. Not part of the app-facing
/// API — apps just call `boot_info()`.
#[doc(hidden)]
pub struct BootInfoParams {
    pub ram_bytes: usize,
    pub num_cpus: u32,
    pub boot_args: &'static str,
    /// Fixed-size NIC array; only the first `nic_count` entries are
    /// published. Trailing entries are ignored (use `NicInfo::EMPTY`).
    pub nics: [NicInfo; MAX_NICS],
    pub nic_count: u8,
    pub rtc_epoch: Option<u64>,
}

// ---- Storage ---------------------------------------------------------------
//
// Two cells: one holds the NIC array so the published `nics` slice has
// `'static` lifetime; the other holds the `BootInfo` itself. The NIC
// cell is filled first so `BootInfo.nics` can borrow from it.

static NICS_STORAGE: InitOnce<[NicInfo; MAX_NICS]> = InitOnce::new();
static BOOT_INFO: InitOnce<BootInfo> = InitOnce::new();

/// Publish the final boot-time snapshot. Called exactly once per
/// boot, from the platform backend (bare-metal boot entry on the
/// unikernel, `init_native` on POSIX) before `uni_boot` runs. Not
/// part of the app-facing API.
///
/// Panics if called twice.
#[doc(hidden)]
pub fn init_boot_info(p: BootInfoParams) {
    let count = (p.nic_count as usize).min(MAX_NICS);
    NICS_STORAGE.init(p.nics);
    // `NICS_STORAGE` is a `static`, so the returned reference is
    // `&'static [NicInfo; MAX_NICS]` and the sub-slice inherits that.
    let nics_slice: &'static [NicInfo] = &NICS_STORAGE.get()[..count];
    BOOT_INFO.init(BootInfo {
        ram_bytes: p.ram_bytes,
        num_cpus: p.num_cpus,
        boot_args: p.boot_args,
        nics: nics_slice,
        rtc_epoch: p.rtc_epoch,
    });
}

/// Return the boot-time snapshot. Panics if called before
/// `init_boot_info` (which on both platforms runs before `uni_boot`).
pub fn boot_info() -> &'static BootInfo {
    BOOT_INFO.get()
}

/// Whether `init_boot_info` has been called. For tests and platform
/// layering only — app code should call `boot_info()` directly.
pub fn is_initialized() -> bool {
    BOOT_INFO.is_initialized()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_struct_accessors() {
        // Exercises the struct layout without touching the module
        // statics (which can only be initialised once per process,
        // making them unfriendly to `cargo test`'s repeated runs).
        // The NIC array is a local `static` so it has 'static lifetime
        // — matching the production path where `NICS_STORAGE` holds
        // the array.
        static NICS: [NicInfo; MAX_NICS] = [
            NicInfo {
                name: "virtio-net",
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                num_queue_pairs: 3,
            },
            NicInfo::EMPTY,
            NicInfo::EMPTY,
            NicInfo::EMPTY,
        ];
        let bi = BootInfo {
            ram_bytes: 128 * 1024 * 1024,
            num_cpus: 3,
            boot_args: "console=ttyS0",
            nics: &NICS[..1],
            rtc_epoch: Some(1_700_000_000),
        };
        assert_eq!(bi.ram_bytes, 128 * 1024 * 1024);
        assert_eq!(bi.num_cpus, 3);
        assert_eq!(bi.boot_args, "console=ttyS0");
        assert_eq!(bi.nics.len(), 1);
        assert_eq!(bi.nics[0].name, "virtio-net");
        assert_eq!(bi.nics[0].mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(bi.nics[0].num_queue_pairs, 3);
        assert_eq!(bi.rtc_epoch, Some(1_700_000_000));
    }

    #[test]
    fn empty_nic_list_is_valid() {
        let bi = BootInfo {
            ram_bytes: 0,
            num_cpus: 1,
            boot_args: "",
            nics: &[],
            rtc_epoch: None,
        };
        assert!(bi.nics.is_empty());
        assert_eq!(bi.boot_args, "");
        assert!(bi.rtc_epoch.is_none());
    }

    #[test]
    fn nic_info_empty_const() {
        assert_eq!(NicInfo::EMPTY.name, "");
        assert_eq!(NicInfo::EMPTY.mac, [0; 6]);
        assert_eq!(NicInfo::EMPTY.num_queue_pairs, 0);
    }

    #[test]
    fn params_builds_bootinfo_with_bounded_nic_count() {
        // `nic_count` > MAX_NICS is clamped to MAX_NICS — the rest of
        // the array is ignored but still represented by `EMPTY`.
        let p = BootInfoParams {
            ram_bytes: 64 * 1024 * 1024,
            num_cpus: 2,
            boot_args: "",
            nics: [NicInfo::EMPTY; MAX_NICS],
            nic_count: 200,
            rtc_epoch: None,
        };
        // We don't call `init_boot_info` here (see "can only init
        // once" caveat above) — just assert our clamp math.
        let count = (p.nic_count as usize).min(MAX_NICS);
        assert_eq!(count, MAX_NICS);
    }

    #[test]
    fn init_once_semantics() {
        let cell: InitOnce<u32> = InitOnce::new();
        assert!(!cell.is_initialized());
        cell.init(42);
        assert!(cell.is_initialized());
        assert_eq!(*cell.get(), 42);
    }

    #[test]
    #[should_panic(expected = "init called twice")]
    fn double_init_panics() {
        let cell: InitOnce<u32> = InitOnce::new();
        cell.init(1);
        cell.init(2);
    }

    #[test]
    #[should_panic(expected = "called before init")]
    fn get_before_init_panics() {
        let cell: InitOnce<u32> = InitOnce::new();
        let _ = cell.get();
    }
}
