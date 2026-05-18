// drivers/lib.rs — Outer `drivers` crate: umbrella re-exports of the
// shared infrastructure plus the NIC dispatch layer.
//
// The shared hardware-access infrastructure (MMIO helpers, PCI
// enumeration, VirtIO transport, virtio-console) lives in the sibling
// `drivers_infra` sub-target. The NIC dispatch layer — thin wrappers
// over the `uni_net_driver` active-driver slot — lives in the sibling
// host-buildable `nic` crate. Each NIC lives in its own crate
// (`//uni-driver-virtio-net`, `//uni-driver-gve`) that registers via
// `register_ethernet_driver!`; `nic::init()` walks the registry at
// init, installs the winner in the active-driver slot, and every
// subsequent call trait-dispatches through that slot.
//
// Crucially this crate has **no static references to the NIC crates**
// — so apps pick their driver set via their own BUILD deps, not by
// what `//drivers:drivers` happens to pull in.

#![no_std]

extern crate drivers_infra;

// Re-export the infra surface so `uni_drivers::{pci, virtio, virtio_console,
// mmio_read32, …}` paths keep resolving. Callers don't need to know
// about the sub-target split.
pub use drivers_infra::*;

// NIC dispatch lives in the standalone host-buildable `nic` crate
// (`//drivers:nic`), split out so the TX-side net crates can call the
// dispatchers without being dragged onto this os:none umbrella.
// Re-exported as `uni_drivers::net` so existing callers are unchanged.
pub extern crate nic as net;
