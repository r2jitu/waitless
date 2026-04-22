// drivers/lib.rs — Outer `drivers` crate: NIC dispatcher that
// trait-dispatches through the `uni_net_driver` active-driver slot,
// plus umbrella re-exports of the shared infrastructure.
//
// The shared hardware-access infrastructure (MMIO helpers, PCI
// enumeration, VirtIO transport, virtio-console) lives in the sibling
// `drivers_infra` sub-target. Each NIC lives in its own crate
// (`//uni-driver-virtio-net`, `//uni-driver-gve`) that registers via
// `register_ethernet_driver!`. `drivers/net.rs` walks the registry
// at init, installs the winner in the active-driver slot, and every
// subsequent call trait-dispatches through that slot.
//
// Crucially this crate has **no static references to the NIC crates**
// — so apps pick their driver set via their own BUILD deps, not by
// what `//drivers:drivers` happens to pull in.

#![no_std]

extern crate drivers_infra;

// Re-export the infra surface so `drivers::{pci, virtio, virtio_console,
// mmio_read32, …}` paths keep resolving. Callers don't need to know
// about the sub-target split.
pub use drivers_infra::*;

pub mod net;
