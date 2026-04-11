// tools/hvf-runner/src/main.rs
//
// CLI entry point for the HVF runner. Parses arguments, enables raw
// terminal mode, spawns a stdin reader thread, creates and runs the VM.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

mod decoder;
mod fdt;
mod hvf;
mod pl011;
mod spsc;
mod terminal;
mod virtio;
mod vm;
mod userspace_net;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: run-hvf <path-to.img> [ram_mib]");
        eprintln!("  Boots an ARM64 kernel image under Apple Hypervisor.framework.");
        eprintln!("  Requires codesign with com.apple.security.hypervisor entitlement.");
        std::process::exit(1);
    }
    let kernel_path = &args[1];
    let ram_mib: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(128);

    // macOS version gate: hv_gic_create requires macOS 15+.
    let os_ver = os_version();
    if os_ver < 15 {
        eprintln!(
            "run-hvf: requires macOS 15.0 or later (detected {os_ver}.x). \
             The native vGIC API (hv_gic_create) was added in macOS 15."
        );
        std::process::exit(1);
    }

    // Switch terminal to raw mode so Ctrl-C → 0x03 byte to guest.
    terminal::enable_raw();

    // Install a cleanup handler for abnormal exits.
    // (Ctrl-C is handled by the guest via serial, not by SIGINT.)
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        terminal::restore();
        orig_hook(info);
    }));

    // Spawn stdin reader thread — pushes bytes into pl011::RX_BUF.
    std::thread::spawn(|| {
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 64];
        while !SHUTDOWN.load(Ordering::Relaxed) {
            match handle.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let mut rx = pl011::RX_BUF.lock().unwrap();
                    for &b in &buf[..n] {
                        rx.push_back(b);
                    }
                }
                Err(_) => break,
            }
        }
    });

    eprintln!("==> HVF runner: booting {kernel_path} ({ram_mib} MB RAM)");

    // Start userspace networking (no vmnet, no root required).
    let host_port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let vmnet_mac = match userspace_net::start(host_port) {
        Ok(mac) => mac,
        Err(e) => {
            eprintln!("run-hvf: network failed: {e}");
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        }
    };

    // Create and run the VM.
    let mut vm = match vm::Vm::new_with_mac(kernel_path, ram_mib, vmnet_mac) {
        Ok(vm) => vm,
        Err(e) => {
            terminal::restore();
            eprintln!("run-hvf: failed to create VM: {e}");
            std::process::exit(1);
        }
    };

    match vm.run() {
        Ok(()) => {
            eprintln!("\n==> Guest requested shutdown. Exiting.");
        }
        Err(e) => {
            terminal::restore();
            eprintln!("\nrun-hvf: VM exited with error: {e}");
            std::process::exit(1);
        }
    }

    SHUTDOWN.store(true, Ordering::Relaxed);
    terminal::restore();
}

/// Get the major macOS version number (e.g. 15 for Sonoma, 26 for Tahoe).
fn os_version() -> u32 {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    let name = c"kern.osproductversion";
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return 0;
    }
    let s = std::str::from_utf8(&buf[..len.saturating_sub(1)]).unwrap_or("");
    s.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0)
}
