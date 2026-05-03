// tools/hvf-runner/src/main.rs
//
// CLI entry point for the HVF runner. Parses arguments, enables raw
// terminal mode, spawns a stdin reader thread, creates and runs the VM.
//
// CLI:
//   run-hvf <path-to.img> [OPTIONS]
//
// Options:
//   --ram=MB              Guest RAM in MiB (default: 128)
//   --cpus=N              vCPU count (default: 1)
//   -p PROTO:HOST:GUEST   Port forward (repeatable).
//                         PROTO = tcp | udp.
//                         Default if no -p given:
//                             -p tcp:8080:80 -p udp:18080:7
//   -h, --help            Show usage

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

mod decoder;
mod fdt;
mod hvf;
mod terminal;
mod virtio;
mod virtio_console;
mod vm;
mod userspace_net;

use userspace_net::{PortMapping, Proto};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn usage(prog: &str) {
    eprintln!("Usage: {prog} <path-to.img> [OPTIONS]");
    eprintln!("  Boots an ARM64 kernel image under Apple Hypervisor.framework.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --ram=MB              Guest RAM in MiB (default: 128)");
    eprintln!("  --cpus=N              vCPU count (default: 1)");
    eprintln!("  -p PROTO:HOST:GUEST   Port forward (repeatable).");
    eprintln!("                        PROTO = tcp | udp.");
    eprintln!("                        Default: -p tcp:8080:80 -p udp:18080:7");
    eprintln!("  -h, --help            Show this help");
    eprintln!();
    eprintln!("Requires codesign with com.apple.security.hypervisor entitlement.");
}

fn parse_port_mapping(spec: &str) -> Result<PortMapping, String> {
    let mut parts = spec.splitn(3, ':');
    let proto_s = parts.next().ok_or_else(|| format!("empty mapping"))?;
    let host_s = parts.next().ok_or_else(|| format!("missing host port in '{spec}'"))?;
    let guest_s = parts.next().ok_or_else(|| format!("missing guest port in '{spec}'"))?;
    let proto = match proto_s {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return Err(format!("unknown proto '{other}' in '{spec}' (want tcp or udp)")),
    };
    let host: u16 = host_s.parse().map_err(|_| format!("bad host port '{host_s}'"))?;
    let guest: u16 = guest_s.parse().map_err(|_| format!("bad guest port '{guest_s}'"))?;
    Ok(PortMapping { proto, host, guest })
}

struct Args {
    kernel_path: String,
    ram_mib: usize,
    cpu_count: usize,
    mappings: Vec<PortMapping>,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let prog = argv.first().cloned().unwrap_or_else(|| "run-hvf".into());
    if argv.len() < 2 {
        usage(&prog);
        return Err("missing <path-to.img>".into());
    }
    let mut kernel_path: Option<String> = None;
    let mut ram_mib: usize = 128;
    let mut cpu_count: usize = 1;
    let mut mappings: Vec<PortMapping> = Vec::new();

    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-h" || a == "--help" {
            usage(&prog);
            std::process::exit(0);
        } else if let Some(v) = a.strip_prefix("--ram=") {
            ram_mib = v.parse().map_err(|_| format!("bad --ram value '{v}'"))?;
        } else if let Some(v) = a.strip_prefix("--cpus=") {
            cpu_count = v.parse().map_err(|_| format!("bad --cpus value '{v}'"))?;
        } else if a == "-p" {
            i += 1;
            let v = argv.get(i).ok_or_else(|| "-p expects a value".to_string())?;
            mappings.push(parse_port_mapping(v)?);
        } else if let Some(v) = a.strip_prefix("-p=") {
            mappings.push(parse_port_mapping(v)?);
        } else if a.starts_with('-') {
            return Err(format!("unknown option '{a}'"));
        } else if kernel_path.is_none() {
            kernel_path = Some(a.clone());
        } else {
            return Err(format!("unexpected positional argument '{a}'"));
        }
        i += 1;
    }

    let kernel_path = kernel_path.ok_or_else(|| "missing <path-to.img>".to_string())?;

    // Default port forwards if none given: HTTP on 8080→80 and UDP echo on 18080→7.
    if mappings.is_empty() {
        mappings.push(PortMapping { proto: Proto::Tcp, host: 8080, guest: 80 });
        mappings.push(PortMapping { proto: Proto::Udp, host: 18080, guest: 7 });
    }

    Ok(Args { kernel_path, ram_mib, cpu_count, mappings })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("run-hvf: {e}");
            std::process::exit(1);
        }
    };

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
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        terminal::restore();
        orig_hook(info);
    }));

    // Spawn stdin reader thread — pushes bytes into the virtio-console
    // RX_BUF and kicks every vCPU so a parked cooperative-yield loop
    // wakes up promptly. Without the wake, the guest would only notice
    // a Ctrl-C on the next 10 ms vcpu_poll timeout (or never, if it's
    // deeply parked) — see vm.rs yield loop comment for the full chain.
    std::thread::spawn(|| {
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 64];
        while !SHUTDOWN.load(Ordering::Relaxed) {
            match handle.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    {
                        let mut rx = virtio_console::RX_BUF.lock().unwrap();
                        for &b in &buf[..n] {
                            rx.push_back(b);
                        }
                    }
                    // Drive the RX queue from this thread so the byte
                    // is in guest RAM by the time the vCPU wakes —
                    // saves one round trip vs deferring to the vCPU's
                    // next poll cycle.
                    virtio_console::drive_rx();
                    // wake_all_vcpus writes the per-vCPU wake pipe, which
                    // is in vcpu_poll's poll-fd set; that fires
                    // `any_injected=true` and breaks the cooperative-yield
                    // loop so the guest observes the byte promptly.
                    userspace_net::wake_all_vcpus();
                }
                Err(_) => break,
            }
        }
    });

    eprintln!("==> HVF runner: booting {} ({} MB RAM)", parsed.kernel_path, parsed.ram_mib);

    // Start userspace networking (no vmnet, no root required).
    let vmnet_mac = match userspace_net::start(&parsed.mappings, parsed.cpu_count) {
        Ok(mac) => mac,
        Err(e) => {
            eprintln!("run-hvf: network failed: {e}");
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        }
    };

    // Create and run the VM.
    let mut vm = match vm::Vm::new_with_config(&parsed.kernel_path, parsed.ram_mib, parsed.cpu_count, vmnet_mac) {
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
