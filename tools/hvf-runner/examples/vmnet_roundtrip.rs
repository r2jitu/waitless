// Measure vmnet round-trip: send ARP request, time the reply.
// This isolates vmnet performance from HVF/VM completely.
//
// Usage: sudo cargo run --release --example vmnet_roundtrip

fn main() {
    eprintln!("==> Creating vmnet host-mode interface...");
    let mut iface = vmnet::Interface::new(
        vmnet::mode::Mode::Host(Default::default()),
        Default::default(),
    ).expect("vmnet::Interface::new failed");

    let params: Vec<vmnet::parameters::Parameter> = iface.parameters().into();
    let mut our_mac = [0u8; 6];
    for p in &params {
        if let vmnet::parameters::Parameter::MACAddress(ref s) = p {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                for (i, part) in parts.iter().enumerate() {
                    our_mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                }
            }
        }
        eprintln!("  {p:?}");
    }

    // Build an ARP request: who-has 192.168.18.1 (the bridge gateway)?
    let gateway_ip: [u8; 4] = [192, 168, 18, 1];
    let sender_ip: [u8; 4] = [192, 168, 18, 99]; // fake sender IP
    let mut arp_req = [0u8; 42]; // 14 eth + 28 arp
    // Ethernet header
    arp_req[0..6].copy_from_slice(&[0xff; 6]); // dst = broadcast
    arp_req[6..12].copy_from_slice(&our_mac);   // src = our MAC
    arp_req[12..14].copy_from_slice(&[0x08, 0x06]); // ethertype = ARP
    // ARP
    arp_req[14..16].copy_from_slice(&[0x00, 0x01]); // htype = Ethernet
    arp_req[16..18].copy_from_slice(&[0x08, 0x00]); // ptype = IPv4
    arp_req[18] = 6; // hlen
    arp_req[19] = 4; // plen
    arp_req[20..22].copy_from_slice(&[0x00, 0x01]); // oper = request
    arp_req[22..28].copy_from_slice(&our_mac); // sender MAC
    arp_req[28..32].copy_from_slice(&sender_ip); // sender IP
    // target MAC = 0 (unknown)
    arp_req[38..42].copy_from_slice(&gateway_ip); // target IP

    // Measure ARP round-trips.
    eprintln!("\n==> ARP round-trip test (10 iterations)...");
    let mut buf = [0u8; 2048];

    // Drain any stale packets first.
    for _ in 0..100 { let _ = iface.read(&mut buf); }

    for i in 0..10 {
        let t = std::time::Instant::now();
        iface.write(&arp_req).expect("write failed");

        // Wait for ARP reply.
        let mut got_reply = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match iface.read(&mut buf) {
                Ok(n) if n >= 42 => {
                    // Check if it's an ARP reply (ethertype=0x0806, oper=0x0002)
                    if buf[12] == 0x08 && buf[13] == 0x06 && buf[20] == 0x00 && buf[21] == 0x02 {
                        let elapsed = t.elapsed();
                        eprintln!("  ARP reply #{}: {:?}", i + 1, elapsed);
                        got_reply = true;
                        break;
                    }
                }
                _ => {
                    std::hint::spin_loop();
                }
            }
        }
        if !got_reply {
            eprintln!("  ARP reply #{}: TIMEOUT", i + 1);
        }
    }

    // Now measure sustained throughput: send/receive as fast as possible.
    eprintln!("\n==> Sustained read throughput (5s, reading all traffic)...");
    let start = std::time::Instant::now();
    let mut pkts = 0u64;
    let mut reads = 0u64;
    let mut last = start;

    while start.elapsed().as_secs() < 5 {
        // Send ARP request every iteration to saturate.
        let _ = iface.write(&arp_req);
        reads += 1;
        match iface.read(&mut buf) {
            Ok(n) if n > 0 => { pkts += 1; }
            _ => {}
        }

        if last.elapsed().as_secs() >= 1 {
            let elapsed = start.elapsed().as_secs_f64();
            eprintln!(
                "  [{elapsed:.1}s] reads={reads} pkts={pkts} ({:.0}/s)",
                pkts as f64 / elapsed
            );
            last = std::time::Instant::now();
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("\n==> Final: {pkts} pkts in {elapsed:.1}s = {:.0} pkt/s", pkts as f64 / elapsed);
}
