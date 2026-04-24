// uni-backend/src/unikernel.rs — Bare-metal dispatch.

use uni_kernel::serial;

// ---- Lifecycle / config ---------------------------------------------------

pub fn log(msg: &[u8]) {
    serial::puts(msg)
}

pub fn config_port(default_port: u16) -> u16 {
    default_port
}

/// TLS port override stub. On the unikernel there are no env
/// variables, so the caller-supplied default is the only source of
/// truth; the real override lives in the native backend.
pub fn config_tls_port(default_port: u16) -> u16 {
    default_port
}

pub fn check_shutdown() -> bool {
    serial::check_shutdown()
}

// ---- Net stack re-exports (TCP/UDP + driver diagnostics) ------------------

pub use uni_drivers::net::{
    num_queue_pairs as net_num_queue_pairs, rx_counts as net_rx_counts,
    rx_used_cursors as net_rx_used_cursors,
};
// `tcp_close` is the only sync TCP API callers still reach — it's
// used by `uni::TcpStream::close` on the graceful-shutdown path.
// Every other sync TCP primitive (accept / recv / send / listen /
// has_data / is_closed / poll) has no callers outside the async
// reactor's internal hooks and is gone.
pub use uni_net_stack::tcp::close as tcp_close;
pub use uni_net_stack::udp::send as udp_send;

// ---- Event loop re-exports ------------------------------------------------

pub use uni_kernel::eventloop::{request_shutdown, set_ready};
pub use uni_kernel::percpu::num_cores as num_workers;

// ---- Async runtime re-exports ---------------------------------------------

pub mod runtime {
    pub use uni_runtime::{sleep_us, spawn, Sleep};
}

// ---- Heap stats -----------------------------------------------------------

pub fn heap_stats() -> super::HeapStats {
    let s = uni_kernel::mm::heap_stats();
    super::HeapStats {
        allocated_bytes: s.allocated_bytes,
        available_bytes: s.available_bytes,
        claimed_bytes: s.claimed_bytes,
        allocation_count: s.allocation_count,
        fragment_count: s.fragment_count,
        total_allocation_count: s.total_allocation_count,
    }
}

// ---- Wait for events ------------------------------------------------------

/// RAII guard that masks IRQs on construction and unmasks on drop.
/// Used to bracket the "check pending → idle" race window. Zero cost
/// on x86 where the idle uses `sti;hlt;cli` atomically.
#[must_use = "the guard unmasks IRQs when dropped; binding to _ unmasks immediately"]
struct IrqGuard {
    _no_send: core::marker::PhantomData<*mut ()>,
}

impl IrqGuard {
    #[inline]
    fn new() -> Self {
        uni_kernel::cpu::mask_irq();
        IrqGuard {
            _no_send: core::marker::PhantomData,
        }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        uni_kernel::cpu::unmask_irq();
    }
}

pub fn wait_for_events() {
    uni_drivers::net::flush_tx_staging();

    if uni_drivers::net::irq_idle_supported() {
        let _irq = IrqGuard::new();
        uni_drivers::net::arm_rx_interrupts();
        if !uni_drivers::net::has_pending_rx() && !uni_drivers::net::has_pending_tx() {
            uni_kernel::cpu::idle_bounded();
        }
        uni_drivers::net::flush_tx_staging();
    } else {
        uni_kernel::cpu::relax();
    }
}
