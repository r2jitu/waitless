// net/protocol_tests.rs — Host-native unit tests for protocol parsing.
//
// Tests frame parsing using raw byte arrays. No driver or kernel deps needed.
// Run: bazel test //crates/net:protocol_tests

// Inline byte-order helpers (avoid dep on net_types which has panic=abort)
fn htons(h: u16) -> u16 {
    h.to_be()
}
fn ntohs(n: u16) -> u16 {
    u16::from_be(n)
}
fn ntohl(n: u32) -> u32 {
    u32::from_be(n)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = (data[i] as u16) | ((data[i + 1] as u16) << 8);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Ethernet ─────────────────────────────────────────────────────────────────

#[test]
fn ethernet_parse_valid_frame() {
    // Ethernet frame: dst=ff:ff:ff:ff:ff:ff, src=52:54:00:12:34:56, ethertype=0x0806 (ARP)
    let frame: [u8; 20] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // src
        0x08, 0x06, // ethertype = ARP (big-endian)
        // payload (6 bytes)
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
    ];
    // Parse: header is 14 bytes, ethertype should be 0x0806
    assert!(frame.len() >= 14);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    assert_eq!(ethertype, 0x0806);
    let payload = &frame[14..];
    assert_eq!(payload.len(), 6);
}

#[test]
fn ethernet_parse_too_short() {
    let frame: [u8; 10] = [0; 10]; // less than 14 bytes
    assert!(frame.len() < 14); // would fail ethernet_parse
}

// ── ARP ──────────────────────────────────────────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ArpPacket {
    hw_type: u16,
    proto_type: u16,
    hw_len: u8,
    proto_len: u8,
    operation: u16,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
}

#[test]
fn arp_request_encoding() {
    let pkt = ArpPacket {
        hw_type: htons(1),         // Ethernet
        proto_type: htons(0x0800), // IPv4
        hw_len: 6,
        proto_len: 4,
        operation: htons(1), // Request
        sender_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        sender_ip: [10, 0, 2, 15],
        target_mac: [0; 6],
        target_ip: [10, 0, 2, 2],
    };
    let bytes = unsafe { core::slice::from_raw_parts(&pkt as *const _ as *const u8, 28) };
    assert_eq!(bytes.len(), 28);
    // hw_type = 1 in big-endian
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1], 0x01);
    // operation = 1 (request) in big-endian
    assert_eq!(bytes[6], 0x00);
    assert_eq!(bytes[7], 0x01);
    // sender IP at offset 14
    assert_eq!(&bytes[14..18], &[10, 0, 2, 15]);
    // target IP at offset 24
    assert_eq!(&bytes[24..28], &[10, 0, 2, 2]);
}

#[test]
fn arp_reply_decode() {
    // ARP reply: operation=2, sender_mac=aa:bb:cc:dd:ee:ff, sender_ip=10.0.2.2
    let data: [u8; 28] = [
        0x00, 0x01, // hw_type = 1
        0x08, 0x00, // proto_type = 0x0800
        0x06, 0x04, // hw_len=6, proto_len=4
        0x00, 0x02, // operation = 2 (reply)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // sender_mac
        10, 0, 2, 2, // sender_ip
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // target_mac
        10, 0, 2, 15, // target_ip
    ];
    let operation = ntohs(u16::from_ne_bytes([data[6], data[7]]));
    assert_eq!(operation, 2);
    assert_eq!(&data[8..14], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(&data[14..18], &[10, 0, 2, 2]);
}

// ── IPv4 ─────────────────────────────────────────────────────────────────────

#[test]
fn ipv4_header_parse() {
    // Minimal IPv4 header: version=4, IHL=5, total_len=40, proto=6 (TCP)
    let hdr: [u8; 20] = [
        0x45, 0x00, // version=4, IHL=5, TOS=0
        0x00, 0x28, // total_length=40 (big-endian)
        0x00, 0x01, // identification
        0x40, 0x00, // flags=DF, fragment_offset=0
        0x40, 0x06, // TTL=64, protocol=6 (TCP)
        0x00, 0x00, // checksum (0 for test)
        0x0A, 0x00, 0x02, 0x0F, // src = 10.0.2.15
        0x0A, 0x00, 0x02, 0x02, // dst = 10.0.2.2
    ];
    let version = hdr[0] >> 4;
    let ihl = (hdr[0] & 0x0F) as usize;
    let total_len = ntohs(u16::from_ne_bytes([hdr[2], hdr[3]]));
    let protocol = hdr[9];

    assert_eq!(version, 4);
    assert_eq!(ihl, 5);
    assert_eq!(total_len, 40);
    assert_eq!(protocol, 6); // TCP
    assert_eq!(&hdr[12..16], &[10, 0, 2, 15]); // src
    assert_eq!(&hdr[16..20], &[10, 0, 2, 2]); // dst
}

#[test]
fn ipv4_header_checksum_valid() {
    // Same header with computed checksum — verify it
    let mut hdr: [u8; 20] = [
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x02,
        0x0F, 0x0A, 0x00, 0x02, 0x02,
    ];
    let cksum = checksum(&hdr);
    hdr[10] = (cksum & 0xFF) as u8;
    hdr[11] = (cksum >> 8) as u8;
    // Verify: checksum over header with correct checksum should be 0
    assert_eq!(checksum(&hdr), 0);
}

#[test]
fn ipv4_reject_version6() {
    // Version 6 should be rejected by IPv4 parser
    let hdr: [u8; 20] = [
        0x65, 0x00, 0x00, 0x28, // version=6 (invalid for IPv4)
        0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x0F, 0x0A, 0x00, 0x02,
        0x02,
    ];
    let version = hdr[0] >> 4;
    assert_ne!(version, 4);
}

#[test]
fn ipv4_accepts_coalesced_super_segment_length() {
    // RX item M: a HW-GRO / RSC coalesced super-segment hands
    // `ipv4_parse` only part 0 of the RX chain — header + the first
    // slice of payload — while `total_length` declares the whole
    // coalesced length. The parse must NOT reject `total_length >
    // data.len()` (that dropped every super-segment pre-item-M); it
    // clamps the part-0 payload view to the bytes present instead.
    // This mirrors `ipv4_parse`'s post-item-M bound check —
    // `ipv4`'s `os:none` dep chain (`//crates/kernel/bare`) keeps the real
    // function out of this host-native test crate.
    let frame: [u8; 24] = [
        0x45, 0x00, // version=4, IHL=5
        0xC3, 0x50, // total_length = 50000 (coalesced; far past this buffer)
        0x00, 0x01, 0x40, 0x00, // identification, flags=DF
        0x40, 0x06, 0x00, 0x00, // TTL=64, proto=6 (TCP), checksum
        0x0A, 0x00, 0x02, 0x0F, // src = 10.0.2.15
        0x0A, 0x00, 0x02, 0x02, // dst = 10.0.2.2
        0xDE, 0xAD, 0xBE, 0xEF, // 4 bytes of L4 payload present in part 0
    ];
    let data = &frame[..];
    let ihl = (data[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    let total_len = ntohs(u16::from_ne_bytes([data[2], data[3]])) as usize;

    // Post-item-M reject conditions: a packet shorter than its own
    // header, or whose header itself outruns the buffer. Neither here.
    assert!(total_len >= header_len, "total_length covers the header");
    assert!(header_len <= data.len(), "header present in part 0");
    // `total_length` (50000) exceeds the buffer — this is the
    // super-segment shape, and it is NOT a reject. The payload view
    // clamps to the bytes physically present.
    assert!(total_len > data.len());
    let payload_end = total_len.min(data.len());
    let payload = &data[header_len..payload_end];
    assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

// ── TCP ──────────────────────────────────────────────────────────────────────

#[test]
fn tcp_syn_segment_parse() {
    // TCP SYN: src_port=12345, dst_port=80, seq=1000, flags=SYN
    let seg: [u8; 20] = [
        0x30, 0x39, // src_port = 12345 (big-endian)
        0x00, 0x50, // dst_port = 80
        0x00, 0x00, 0x03, 0xE8, // seq = 1000
        0x00, 0x00, 0x00, 0x00, // ack = 0
        0x50, 0x02, // data_offset=5 (20 bytes), flags=SYN (0x02)
        0xFF, 0xFF, // window = 65535
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ];
    let src_port = ntohs(u16::from_ne_bytes([seg[0], seg[1]]));
    let dst_port = ntohs(u16::from_ne_bytes([seg[2], seg[3]]));
    let seq = ntohl(u32::from_ne_bytes([seg[4], seg[5], seg[6], seg[7]]));
    let data_offset = (seg[12] >> 4) as usize * 4;
    let flags = seg[13];

    assert_eq!(src_port, 12345);
    assert_eq!(dst_port, 80);
    assert_eq!(seq, 1000);
    assert_eq!(data_offset, 20);
    assert_eq!(flags & 0x02, 0x02); // SYN flag set
    assert_eq!(flags & 0x10, 0x00); // ACK flag not set
}

#[test]
fn tcp_synack_flags() {
    let flags: u8 = 0x12; // SYN + ACK
    assert_eq!(flags & 0x02, 0x02); // SYN
    assert_eq!(flags & 0x10, 0x10); // ACK
    assert_eq!(flags & 0x01, 0x00); // not FIN
    assert_eq!(flags & 0x04, 0x00); // not RST
}

// ── DHCP ─────────────────────────────────────────────────────────────────────

#[test]
fn dhcp_magic_cookie() {
    // DHCP magic cookie: 99.130.83.99 = 0x63825363
    let cookie_bytes: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
    let cookie = u32::from_be_bytes(cookie_bytes);
    assert_eq!(cookie, 0x63825363);
}

#[test]
fn dhcp_option_parsing() {
    // DHCP options: message type (53), subnet mask (1), end (255)
    let opts: [u8; 9] = [
        53, 1, 2, // option 53 (message type), len=1, value=2 (OFFER)
        1, 4, 255, 255, 255, 0, // option 1 (subnet mask), len=4, value=255.255.255.0
    ];
    // Parse option 53
    assert_eq!(opts[0], 53);
    assert_eq!(opts[1], 1); // length
    assert_eq!(opts[2], 2); // DHCP OFFER

    // Parse option 1
    assert_eq!(opts[3], 1); // subnet mask option
    assert_eq!(opts[4], 4); // length
    assert_eq!(&opts[5..9], &[255, 255, 255, 0]);
}

#[test]
fn dhcp_option_end_marker() {
    let opts: [u8; 4] = [53, 1, 1, 255]; // message type=1 (DISCOVER), then END
    let mut i = 0;
    let mut msg_type = 0u8;
    while i < opts.len() {
        match opts[i] {
            255 => break,
            0 => {
                i += 1;
                continue;
            }
            53 => {
                let len = opts[i + 1] as usize;
                if len >= 1 {
                    msg_type = opts[i + 2];
                }
                i += 2 + len;
            }
            _ => {
                let len = opts[i + 1] as usize;
                i += 2 + len;
            }
        }
    }
    assert_eq!(msg_type, 1); // DISCOVER
}
