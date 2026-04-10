// Minimal vmnet.framework demo — measures packet delivery rate.
//
// Creates a vmnet host-mode interface, waits for DHCP, then pings
// the VM IP and counts how many packets vmnet_read returns per second.
//
// Usage: sudo cargo run --release --example vmnet_demo

fn main() {
    eprintln!("==> Creating vmnet host-mode interface...");
    let mut iface = vmnet::Interface::new(
        vmnet::mode::Mode::Host(Default::default()),
        Default::default(),
    ).expect("vmnet::Interface::new failed");

    let params: Vec<vmnet::parameters::Parameter> = iface.parameters().into();
    for p in &params {
        eprintln!("  param: {p:?}");
    }

    // Register PACKETS_AVAILABLE callback and count invocations.
    let cb_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cb_count2 = cb_count.clone();
    iface.set_event_callback(vmnet::Events::PACKETS_AVAILABLE, move |_, _| {
        cb_count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }).expect("set_event_callback failed");

    // Poll vmnet_read in a loop and count packets.
    eprintln!("==> Polling vmnet_read for 10 seconds...");
    eprintln!("    (Run 'ping 192.168.18.X' from another terminal to generate traffic)");

    let mut buf = [0u8; 2048];
    let mut total_pkts: u64 = 0;
    let mut total_reads: u64 = 0;
    let start = std::time::Instant::now();
    let mut last_report = start;

    while start.elapsed().as_secs() < 10 {
        total_reads += 1;
        match iface.read(&mut buf) {
            Ok(n) if n > 0 => {
                total_pkts += 1;
                // Print first byte of ethertype for identification
                if total_pkts <= 10 {
                    let ethertype = if n >= 14 {
                        format!("{:02x}{:02x}", buf[12], buf[13])
                    } else {
                        "??".to_string()
                    };
                    eprintln!("  pkt #{total_pkts}: {n} bytes, ethertype=0x{ethertype}");
                }
            }
            _ => {}
        }

        // Report every second.
        if last_report.elapsed().as_secs() >= 1 {
            let cb = cb_count.load(std::sync::atomic::Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            eprintln!(
                "  [{elapsed:.1}s] reads={total_reads} pkts={total_pkts} ({:.0} pkt/s) callbacks={cb}",
                total_pkts as f64 / elapsed
            );
            last_report = std::time::Instant::now();
        }

        // Small sleep to avoid 100% CPU.
        std::thread::sleep(std::time::Duration::from_micros(100));
    }

    let elapsed = start.elapsed().as_secs_f64();
    let cb = cb_count.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("\n==> Results ({elapsed:.1}s):");
    eprintln!("    Total reads: {total_reads}");
    eprintln!("    Total packets: {total_pkts} ({:.1} pkt/s)", total_pkts as f64 / elapsed);
    eprintln!("    GCD callbacks: {cb} ({:.1}/s)", cb as f64 / elapsed);
}
