// scripts/run-vz.swift — Boot an ARM64 unikernel via Apple Virtualization.framework
//
// Build (run-local.sh does this automatically on first use):
//   swiftc run-vz.swift -o run-vz -framework Virtualization
//
// Usage:
//   run-vz <path-to.img> [host-port]
//
// The input must be a raw ARM64 binary image (not an ELF).
// Build it with Bazel: bazel build //apps/webserver:webserver.img
// Or convert manually: llvm-objcopy -O binary webserver.elf webserver.img
//
// Provides the same user experience as QEMU user-mode networking:
//   VM IP:  10.0.2.15   (assigned by our DHCP server)
//   GW IP:  10.0.2.2    (our bridge answers ARP and routes TCP)
//   Ports:  host:HOST_PORT → VM:80  (TCP proxy via Ethernet injection)
//   Serial: stdin/stdout via VirtIO console (Ctrl-C → graceful shutdown)
//
// Requires macOS 11 (VZVirtioConsoleDeviceSerialPortConfiguration).

import Darwin
import Foundation
import Virtualization

// ─── Constants ───────────────────────────────────────────────────────────────

let GW_MAC   = Data([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
let BCAST_MAC = Data([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
let VM_IP    = Data([10, 0, 2, 15])
let GW_IP    = Data([10, 0, 2, 2])

// ─── Terminal raw mode ───────────────────────────────────────────────────────

private var savedTermios = termios()
private var termRaw      = false

func enableRawInput() {
    guard isatty(STDIN_FILENO) != 0, tcgetattr(STDIN_FILENO, &savedTermios) == 0 else { return }
    var t = savedTermios
    // Disable signal generation (ISIG) and line buffering (ICANON).
    // Ctrl-C becomes byte 0x03 forwarded to the VM's virtio console.
    t.c_lflag &= ~tcflag_t(ISIG | ICANON | ECHO | IEXTEN)
    t.c_iflag &= ~tcflag_t(ICRNL | IXON)
    t.c_oflag &= ~tcflag_t(OPOST)
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t)
    termRaw = true
}

func restoreTerminal() {
    if termRaw { tcsetattr(STDIN_FILENO, TCSAFLUSH, &savedTermios) }
}

// ─── Packet helpers ───────────────────────────────────────────────────────────

func u16be(_ v: Int) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
func u32be(_ v: UInt32) -> Data {
    Data([UInt8(v>>24), UInt8((v>>16)&0xff), UInt8((v>>8)&0xff), UInt8(v&0xff)])
}

func ipv4Checksum(_ d: Data) -> UInt16 {
    var s: UInt32 = 0
    let b = Array(d)
    var i = 0
    while i + 1 < b.count { s += UInt32(b[i]) << 8 | UInt32(b[i+1]); i += 2 }
    if i < b.count { s += UInt32(b[i]) << 8 }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16) }
    return UInt16(~s & 0xffff)
}

func buildEth(dst: Data, ethertype: UInt16, payload: Data) -> Data {
    dst + GW_MAC + u16be(Int(ethertype)) + payload
}

func buildIPv4(src: Data, dst: Data, proto: UInt8, payload: Data) -> Data {
    var h = Data(count: 20)
    h[0] = 0x45
    let len = UInt16(20 + payload.count)
    h[2] = UInt8(len >> 8); h[3] = UInt8(len & 0xff)
    h[6] = 0x40             // DF
    h[8] = 64               // TTL
    h[9] = proto
    h[12...15] = src[...]; h[16...19] = dst[...]
    let cs = ipv4Checksum(h)
    h[10] = UInt8(cs >> 8); h[11] = UInt8(cs & 0xff)
    return h + payload
}

func buildUDP(srcPort: Int, dstPort: Int, data: Data) -> Data {
    let len = 8 + data.count
    return u16be(srcPort) + u16be(dstPort) + u16be(len) + Data([0,0]) + data
}

func tcpCsum(srcIP: Data, dstIP: Data, seg: Data) -> UInt16 {
    var ph = srcIP + dstIP + Data([0, 6]) + u16be(seg.count)
    ph += seg
    if ph.count % 2 != 0 { ph += Data([0]) }
    return ipv4Checksum(ph)
}

func buildTCP(sp: Int, dp: Int, seq: UInt32, ack: UInt32, flags: UInt8,
              data: Data, srcIP: Data, dstIP: Data) -> Data {
    var h = Data(count: 20)
    h[0] = UInt8(sp>>8); h[1] = UInt8(sp&0xff)
    h[2] = UInt8(dp>>8); h[3] = UInt8(dp&0xff)
    h[4...7] = u32be(seq)[...]; h[8...11] = u32be(ack)[...]
    h[12] = 0x50; h[13] = flags
    h[14] = 0xff; h[15] = 0xff  // window
    let seg = h + data
    let cs  = tcpCsum(srcIP: srcIP, dstIP: dstIP, seg: seg)
    var out = seg; out[16] = UInt8(cs>>8); out[17] = UInt8(cs&0xff)
    return out
}

// ─── TCP proxy connection ─────────────────────────────────────────────────────

final class ProxyConn {
    let hostFD:  Int32
    let srcPort: Int
    var mySeq:   UInt32
    var peerAck: UInt32 = 0   // VM's seq (we track for our ack field)
    var state:   Int = 0      // 0=SYN_SENT 1=ESTAB 2=CLOSED
    var pending: Data = Data()

    init(fd: Int32, port: Int) {
        hostFD  = fd; srcPort = port
        mySeq   = UInt32.random(in: 0..<UInt32.max)
    }
}

// ─── Network bridge ───────────────────────────────────────────────────────────

final class NetBridge {
    let vmFD:     Int32   // our end of the socketpair → frames to/from VM
    let hostPort: Int32
    var vmMAC:    Data?   // learned from first VM frame
    var conns:    [Int: ProxyConn] = [:]
    var nextPort  = 40000

    init(vmFD: Int32, port: Int32) { self.vmFD = vmFD; self.hostPort = port }

    // ── Frame I/O ────────────────────────────────────────────────────────────

    func sendToVM(_ frame: Data) {
        _ = frame.withUnsafeBytes { read in write(vmFD, read.baseAddress!, frame.count) }
    }

    func toVM(dstMAC: Data, ethertype: UInt16, payload: Data) {
        sendToVM(buildEth(dst: dstMAC, ethertype: ethertype, payload: payload))
    }

    func tcpToVM(c: ProxyConn, flags: UInt8, data: Data) {
        let dst = vmMAC ?? BCAST_MAC
        let tcp = buildTCP(sp: c.srcPort, dp: 80, seq: c.mySeq, ack: c.peerAck,
                           flags: flags, data: data, srcIP: GW_IP, dstIP: VM_IP)
        toVM(dstMAC: dst, ethertype: 0x0800,
             payload: buildIPv4(src: GW_IP, dst: VM_IP, proto: 6, payload: tcp))
    }

    // ── ARP ──────────────────────────────────────────────────────────────────

    func handleARP(_ arp: Data, srcMAC: Data) {
        guard arp.count >= 28,
              (UInt16(arp[6])<<8)|UInt16(arp[7]) == 1,  // REQUEST
              Data(arp[24...27]) == GW_IP else { return }

        var rep = Data(count: 28)
        rep[0]=0; rep[1]=1; rep[2]=0x08; rep[3]=0x00
        rep[4]=6; rep[5]=4; rep[6]=0; rep[7]=2     // REPLY
        rep[8...13] = GW_MAC[...]
        rep[14...17] = GW_IP[...]
        rep[18...23] = srcMAC[...]
        rep[24...27] = srcMAC[...]  // target IP is whatever they asked about
        rep[24...27] = arp[14...17] // target IP = sender IP (their IP)
        toVM(dstMAC: srcMAC, ethertype: 0x0806, payload: rep)
    }

    // ── DHCP ─────────────────────────────────────────────────────────────────

    func handleDHCP(_ udp: Data, srcMAC: Data) {
        guard udp.count >= 8 else { return }
        let sp = (Int(udp[0])<<8)|Int(udp[1]), dp = (Int(udp[2])<<8)|Int(udp[3])
        guard sp == 68 && dp == 67 else { return }
        let bootp = Data(udp.dropFirst(8))  // fresh Data so [n] indices start at 0
        guard bootp.count >= 236 else { return }
        let xid = Data(bootp[4...7])

        // Find message type option
        var msgType: UInt8 = 0
        // DHCP options start at bootp offset 240: skip fixed 236-byte bootp header
        // and the 4-byte magic cookie (99.130.83.99) that precedes the TLV options.
        var i = 0; let opts = Array(Data(bootp.dropFirst(240)))
        while i < opts.count {
            let t = opts[i]; if t == 255 { break }; if t == 0 { i += 1; continue }
            let l = Int(opts[i+1])
            if t == 53, l >= 1 { msgType = opts[i+2] }
            i += 2 + l
        }
        guard msgType == 1 || msgType == 3 else { return }
        let replyType: UInt8 = (msgType == 1) ? 2 : 5

        // Build BOOTP reply (236 bytes)
        var bp = Data(count: 236)
        bp[0]=2; bp[1]=1; bp[2]=6; bp[3]=0
        bp[4...7] = xid[...]
        bp[16...19] = VM_IP[...]    // yiaddr
        bp[20...23] = GW_IP[...]    // siaddr
        bp[28...33] = srcMAC[...]   // chaddr

        // DHCP options
        var o = Data([99,130,83,99])   // magic cookie
        o += Data([53,1,replyType])    // msg type
        o += Data([54,4])+GW_IP        // server id
        o += Data([51,4,0,1,81,128])   // lease 86400s
        o += Data([1,4,255,255,255,0]) // subnet
        o += Data([3,4])+GW_IP         // router
        o += Data([6,4,10,0,2,3])      // DNS
        o += Data([255])               // end

        let udpPkt = buildUDP(srcPort: 67, dstPort: 68, data: bp + o)
        let dst = Data([255,255,255,255])
        let ipPkt = buildIPv4(src: GW_IP, dst: dst, proto: 17, payload: udpPkt)
        let frame = buildEth(dst: srcMAC, ethertype: 0x0800, payload: ipPkt)
        sendToVM(frame)
    }

    // ── TCP (VM → host direction: from TCP proxy perspective) ─────────────────

    func handleTCPFromVM(_ tcp: Data) {
        guard tcp.count >= 20 else { return }
        let dstPort = (Int(tcp[2])<<8)|Int(tcp[3])
        let seq     = (UInt32(tcp[4])<<24)|(UInt32(tcp[5])<<16)|(UInt32(tcp[6])<<8)|UInt32(tcp[7])
        let ack     = (UInt32(tcp[8])<<24)|(UInt32(tcp[9])<<16)|(UInt32(tcp[10])<<8)|UInt32(tcp[11])
        let flags   = tcp[13]
        let doff    = Int((tcp[12] >> 4) * 4)
        let payload = tcp.dropFirst(doff)

        let SYN: UInt8=0x02, ACK: UInt8=0x10, FIN: UInt8=0x01, RST: UInt8=0x04

        guard let c = conns[dstPort] else { return }

        if flags & RST != 0 {
            close(c.hostFD); conns.removeValue(forKey: dstPort); return
        }

        switch c.state {
        case 0:
            guard flags & SYN != 0, flags & ACK != 0 else { return }
            c.peerAck = seq + 1
            c.state   = 1
            tcpToVM(c: c, flags: ACK, data: Data())
            if !c.pending.isEmpty {
                tcpToVM(c: c, flags: ACK|0x08, data: c.pending)
                c.mySeq += UInt32(c.pending.count)
                c.pending = Data()
            }

        case 1:
            if flags & ACK != 0 { _ = ack }  // we don't do retransmit, ignore ack
            if !payload.isEmpty {
                c.peerAck = seq + UInt32(payload.count)
                _ = payload.withUnsafeBytes { write(c.hostFD, $0.baseAddress!, payload.count) }
                tcpToVM(c: c, flags: ACK, data: Data())
            }
            if flags & FIN != 0 {
                c.peerAck += 1
                tcpToVM(c: c, flags: ACK|FIN, data: Data())
                c.mySeq += 1
                c.state = 2
                close(c.hostFD)
                conns.removeValue(forKey: dstPort)
            }
        default: break
        }
    }

    // ── IPv4 dispatcher ──────────────────────────────────────────────────────

    func handleIPv4(_ ip: Data, srcMAC: Data) {
        guard ip.count >= 20 else { return }
        let proto = ip[9]
        let ihl   = Int(ip[0] & 0x0f) * 4
        // Data(slice) copies into a new Data with indices starting at 0,
        // so handlers can safely use body[0], body[1] etc.
        let body  = Data(ip.dropFirst(ihl))
        if proto == 17 { handleDHCP(body, srcMAC: srcMAC) }
        else if proto == 6 { handleTCPFromVM(body) }
    }

    // ── Frame dispatcher ──────────────────────────────────────────────────────

    func processFrame(_ frame: Data) {
        guard frame.count >= 14 else { return }
        let srcMAC    = Data(frame[6...11])
        if vmMAC == nil, srcMAC != GW_MAC, srcMAC != BCAST_MAC { vmMAC = srcMAC }
        let ethertype = (UInt16(frame[12])<<8)|UInt16(frame[13])

        let payload   = frame.dropFirst(14)
        if ethertype == 0x0806      { handleARP(Data(payload), srcMAC: srcMAC) }
        else if ethertype == 0x0800 { handleIPv4(Data(payload), srcMAC: srcMAC) }
    }

    // ── New incoming host connection → synthesize TCP SYN to VM ──────────────

    func newHostConn(fd: Int32) {
        let port = nextPort; nextPort = nextPort % 19999 + 40001
        let c    = ProxyConn(fd: fd, port: port)
        conns[port] = c
        let SYN: UInt8 = 0x02
        tcpToVM(c: c, flags: SYN, data: Data())
        c.mySeq += 1  // SYN consumes one seq#
    }

    // ── Main bridge loop ──────────────────────────────────────────────────────

    func run() {
        // Listen for incoming host TCP connections
        let listenFD = socket(AF_INET, SOCK_STREAM, 0)
        var opt: Int32 = 1
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &opt, 4)
        var sa = sockaddr_in()
        sa.sin_family  = sa_family_t(AF_INET)
        sa.sin_port    = in_port_t(UInt16(bigEndian: UInt16(hostPort)))
        sa.sin_addr.s_addr = INADDR_ANY
        withUnsafeMutablePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        listen(listenFD, 128)

        // Non-blocking accept: lets us drain all pending connections in one loop.
        let listenFlags = fcntl(listenFD, F_GETFL, 0)
        _ = fcntl(listenFD, F_SETFL, listenFlags | O_NONBLOCK)

        var frameBuf = Data(count: 65536)

        while true {
            // Build poll list
            var pfds: [pollfd] = []
            pfds.append(pollfd(fd: vmFD,     events: Int16(POLLIN), revents: 0))
            pfds.append(pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0))
            let connPorts = Array(conns.keys)
            for port in connPorts {
                if let c = conns[port], c.state < 2 {
                    pfds.append(pollfd(fd: c.hostFD, events: Int16(POLLIN), revents: 0))
                }
            }

            let n = poll(&pfds, nfds_t(pfds.count), 10)
            guard n > 0 else { continue }

            // VM frames — drain ALL pending frames per iteration.
            // Previously we read only one frame per poll, causing the vmFD
            // socket buffer to overflow under load.  Dropped frames meant TCP
            // FINs were never delivered to the bridge, so the VM's FIN_WAIT_1
            // connections were never freed and the TCP pool exhausted after a
            // few seconds.  Draining in a loop prevents the buffer overflow.
            if pfds[0].revents & Int16(POLLIN) != 0 {
                while true {
                    let r = frameBuf.withUnsafeMutableBytes {
                        recv(vmFD, $0.baseAddress!, $0.count, Int32(MSG_DONTWAIT))
                    }
                    if r <= 0 { break }
                    processFrame(frameBuf.prefix(r))
                }
            }

            // New host connections — accept all pending, not just one.
            if pfds[1].revents & Int16(POLLIN) != 0 {
                while true {
                    var ca = sockaddr_in(); var cl = socklen_t(MemoryLayout<sockaddr_in>.size)
                    let fd: Int32 = withUnsafeMutablePointer(to: &ca) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            accept(listenFD, $0, &cl)
                        }
                    }
                    if fd < 0 { break }
                    newHostConn(fd: fd)
                }
            }

            // Data from host connections
            for i in 2..<pfds.count {
                guard pfds[i].revents & Int16(POLLIN) != 0 else { continue }
                guard let c = conns[connPorts[i - 2]] else { continue }
                let r = frameBuf.withUnsafeMutableBytes { read(c.hostFD, $0.baseAddress!, $0.count) }
                if r <= 0 {
                    if c.state == 1 {
                        tcpToVM(c: c, flags: 0x01|0x10, data: Data())  // FIN+ACK
                        c.mySeq += 1
                    }
                    close(c.hostFD)
                    conns.removeValue(forKey: c.srcPort)
                } else if c.state == 1 {
                    let data = frameBuf.prefix(r)
                    tcpToVM(c: c, flags: 0x08|0x10, data: data)  // PSH+ACK
                    c.mySeq += UInt32(r)
                } else {
                    c.pending += frameBuf.prefix(r)
                }
            }
        }
    }
}

// ─── VZVirtualMachine delegate ───────────────────────────────────────────────

@available(macOS 11, *)
final class VMDelegate: NSObject, VZVirtualMachineDelegate {
    // Holds the Pipe alive for the entire VM lifetime when running non-interactively.
    // Swift ARC would otherwise release it after its last use in main(), closing the
    // write end and sending EOF to the VirtIO serial device (which triggers VM stop).
    var keepAlivePipe: Pipe?

    func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: Error) {
        restoreTerminal()
        fputs("run-vz: VM stopped with error: \(error)\n", stderr)
        exit(1)
    }
    func guestDidStop(_ vm: VZVirtualMachine) {
        restoreTerminal()
        exit(0)
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

@available(macOS 11, *)
func main() throws {
    let args = CommandLine.arguments
    guard args.count >= 2 else {
        fputs("Usage: run-vz <path-to.img> [host-port]\n", stderr); exit(1)
    }
    let binPath  = args[1]
    let hostPort = Int32(args.count >= 3 ? Int(args[2]) ?? 8080 : 8080)
    let memory   = Int(ProcessInfo.processInfo.environment["UNIKERNEL_MEMORY"] ?? "128")! * 1024 * 1024
    let cpus     = Int(ProcessInfo.processInfo.environment["UNIKERNEL_CPUS"] ?? "1")!

    // Create socketpair for VM ↔ bridge Ethernet frames.
    // SOCK_DGRAM preserves message (frame) boundaries and is supported
    // by AF_UNIX socketpair on macOS (SOCK_SEQPACKET is not).
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
        fputs("run-vz: socketpair failed\n", stderr); exit(1)
    }

    // ── VZ configuration ────────────────────────────────────────────────────

    let cfg = VZVirtualMachineConfiguration()

    // CPU + memory
    cfg.cpuCount = max(VZVirtualMachineConfiguration.minimumAllowedCPUCount,
                       min(VZVirtualMachineConfiguration.maximumAllowedCPUCount, cpus))
    cfg.memorySize = UInt64(memory)

    // Bootloader
    let loader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: binPath))
    cfg.bootLoader = loader

    // Serial console: VirtIO serial port → stdin/stdout.
    // Uses VZVirtioConsoleDeviceSerialPortConfiguration (macOS 11+) which
    // presents a simple single-port VirtIO console (no MULTIPORT feature),
    // matching what hello-apple-vz demonstrates works with bare-metal kernels.
    //
    // When stdin is not a terminal (e.g. benchmark or CI), we use a Pipe as
    // the reading side so the VirtIO serial device never sees EOF.  Receiving
    // EOF on the reading file handle causes VZ to disconnect the serial device
    // and signal the VM to stop — breaking long-running benchmarks.
    let serialReadHandle: FileHandle
    let consolePipe: Pipe?  // kept alive so write end stays open
    if isatty(STDIN_FILENO) != 0 {
        serialReadHandle = FileHandle.standardInput
        consolePipe = nil
    } else {
        let pipe = Pipe()
        serialReadHandle = pipe.fileHandleForReading
        consolePipe = pipe  // write end never closed → no EOF to VM
    }
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: serialReadHandle,
        fileHandleForWriting: FileHandle.standardOutput)
    cfg.serialPorts = [serialPort]

    // Network: VirtIO NIC → our bridge socket
    let net     = VZVirtioNetworkDeviceConfiguration()
    net.attachment = VZFileHandleNetworkDeviceAttachment(
        fileHandle: FileHandle(fileDescriptor: fds[0]))
    cfg.networkDevices = [net]

    // Validate
    try cfg.validate()

    // ── Start bridge thread ─────────────────────────────────────────────────

    let bridge = NetBridge(vmFD: fds[1], port: hostPort)
    Thread { bridge.run() }.start()

    // ── Start VM ─────────────────────────────────────────────────────────────

    let delegate = VMDelegate()
    delegate.keepAlivePipe = consolePipe  // prevent ARC from closing pipe before VM stops
    let vm       = VZVirtualMachine(configuration: cfg, queue: .main)
    vm.delegate  = delegate

    enableRawInput()

    fputs("==> VZ.framework unikernel starting\n", stderr)
    fputs("    Network: http://localhost:\(hostPort)/ → VM port 80\n", stderr)
    fputs("    Serial console below.  Press Ctrl-C to exit.\n\n", stderr)

    vm.start { result in
        if case .failure(let err) = result {
            restoreTerminal()
            fputs("run-vz: failed to start VM: \(err)\n", stderr)
            exit(1)
        }
    }

    RunLoop.main.run()
}

if #available(macOS 11, *) {
    try main()
} else {
    fputs("run-vz: requires macOS 11 or later\n", stderr)
    exit(1)
}
