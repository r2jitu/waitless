// drivers/lib.rs — Outer `drivers` crate: NIC dispatcher over both
// driver crates plus umbrella re-exports.
//
// The shared hardware-access infrastructure (MMIO helpers, PCI
// enumeration, VirtIO transport, virtio-console) lives in the sibling
// `drivers_infra` sub-target. Each NIC lives in its own crate
// (`//uni-driver-virtio-net`, `//uni-driver-gve`). This crate glues
// them together by:
//
//   * Re-exporting the infra surface so existing callers keep seeing
//     `drivers::pci::init()`, `drivers::virtio_console::*` FFI, etc.
//   * Owning `drivers::net` — the NIC dispatcher that picks virtio vs.
//     gve at runtime (legacy path; Phase 5 Step 6 retires this in
//     favour of `uni_net::linked_ethernet_drivers()` registry walks).
//
// Split keeps the driver-crate deps acyclic: driver crates depend on
// `drivers_infra`; this crate depends on everything, so `drivers::net`
// can statically reach both driver crates.

#![no_std]

extern crate drivers_infra;
extern crate uni_driver_virtio_net as virtio_net;
extern crate uni_driver_gve as gve;

// Re-export the infra surface so `drivers::{pci, virtio, virtio_console,
// mmio_read32, …}` paths keep resolving. Callers don't need to know
// about the sub-target split.
pub use drivers_infra::*;

pub mod net;
