// kernel/x86_64/boot_args.rs — Kernel command line plumbing for the
// Limine boot path.
//
// Mirror of `aarch64::fdt::FdtInfo::boot_args()`: a fixed-size static
// buffer (`BOOT_ARGS_MAX` bytes) populated exactly once during boot,
// then read as `&'static str` for the rest of the kernel's lifetime.
//
// On x86_64 / Limine the cmdline lives behind an
// `ExecutableCmdlineRequest`; the bytes themselves are in
// bootloader-reclaimable memory which we treat as RESERVED (see
// `boot/src/limine_entry.rs`). Even so, we copy into our own buffer
// here so the kernel doesn't have to keep a pointer into a region
// owned by an external boot protocol.

use crate::once::InitOnce;

/// Cap on bytes kept from the Limine cmdline. Matches
/// `aarch64::fdt::BOOT_ARGS_MAX` so behaviour is symmetric across
/// arches: longer cmdlines are truncated, never rejected.
pub const BOOT_ARGS_MAX: usize = 256;

struct StoredArgs {
    buf: [u8; BOOT_ARGS_MAX],
    len: usize,
}

static G_ARGS: InitOnce<StoredArgs> = InitOnce::new();

/// Install the kernel command line. Called once during boot from
/// the Limine entry stub before `kernel_boot_from_bootinfo`. Bytes
/// past `BOOT_ARGS_MAX` are silently truncated.
///
/// Panics if called more than once (`InitOnce` contract). Must be
/// called before any reader hits [`boot_args`] — practically that
/// means call it from `limine_entry()` before invoking the kernel
/// boot routine.
pub fn install(bytes: &[u8]) {
    let n = bytes.len().min(BOOT_ARGS_MAX);
    let mut stored = StoredArgs {
        buf: [0; BOOT_ARGS_MAX],
        len: n,
    };
    stored.buf[..n].copy_from_slice(&bytes[..n]);
    G_ARGS.init(stored);
}

/// Kernel command line as a `&'static str`. Returns `""` when:
///   * no cmdline was installed (older boot stub, no Limine
///     response),
///   * the cmdline bytes weren't valid UTF-8.
///
/// Apps key configuration off this (e.g. `quic.log=events` flips
/// the QUIC stack into verbose-event mode); they tolerate the
/// empty string as "stay at defaults".
pub fn boot_args() -> &'static str {
    match G_ARGS.try_get() {
        Some(args) => core::str::from_utf8(&args.buf[..args.len]).unwrap_or(""),
        None => "",
    }
}
