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
// Performance: zero-copy packet construction, kqueue event loop,
// TCP_NODELAY, enlarged socket buffers.  No Swift Data/Array on hot path.

import Darwin
import Foundation
import Virtualization

// ─── Constants (raw bytes, no heap allocations) ──────────────────────────────

let GW_MAC:  (UInt8,UInt8,UInt8,UInt8,UInt8,UInt8) = (0xaa,0xbb,0xcc,0xdd,0xee,0xff)
let VM_IP4:  (UInt8,UInt8,UInt8,UInt8) = (10, 0, 2, 15)
let GW_IP4:  (UInt8,UInt8,UInt8,UInt8) = (10, 0, 2, 2)

// ─── Terminal raw mode ───────────────────────────────────────────────────────

private var savedTermios = termios()
private var termRaw      = false

func enableRawInput() {
    guard isatty(STDIN_FILENO) != 0, tcgetattr(STDIN_FILENO, &savedTermios) == 0 else { return }
    var t = savedTermios
    t.c_lflag &= ~tcflag_t(ISIG | ICANON | ECHO | IEXTEN)
    t.c_iflag &= ~tcflag_t(ICRNL | IXON)
    t.c_oflag &= ~tcflag_t(OPOST)
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t)
    termRaw = true
}

func restoreTerminal() {
    if termRaw { tcsetattr(STDIN_FILENO, TCSAFLUSH, &savedTermios) }
}

// ─── Zero-copy packet builder ────────────────────────────────────────────────
// All packet construction writes directly into a pre-allocated buffer.
// No Data, no Array, no heap allocations on the hot path.

@inline(__always)
func put16(_ p: UnsafeMutablePointer<UInt8>, _ v: UInt16) {
    p[0] = UInt8(v >> 8); p[1] = UInt8(v & 0xff)
}

@inline(__always)
func put32(_ p: UnsafeMutablePointer<UInt8>, _ v: UInt32) {
    p[0] = UInt8(v >> 24); p[1] = UInt8((v >> 16) & 0xff)
    p[2] = UInt8((v >> 8) & 0xff); p[3] = UInt8(v & 0xff)
}

@inline(__always)
func get16(_ p: UnsafePointer<UInt8>) -> UInt16 {
    UInt16(p[0]) << 8 | UInt16(p[1])
}

@inline(__always)
func get32(_ p: UnsafePointer<UInt8>) -> UInt32 {
    UInt32(p[0]) << 24 | UInt32(p[1]) << 16 | UInt32(p[2]) << 8 | UInt32(p[3])
}

@inline(__always)
func putMAC(_ p: UnsafeMutablePointer<UInt8>, _ m: (UInt8,UInt8,UInt8,UInt8,UInt8,UInt8)) {
    p[0] = m.0; p[1] = m.1; p[2] = m.2; p[3] = m.3; p[4] = m.4; p[5] = m.5
}

@inline(__always)
func putIP4(_ p: UnsafeMutablePointer<UInt8>, _ ip: (UInt8,UInt8,UInt8,UInt8)) {
    p[0] = ip.0; p[1] = ip.1; p[2] = ip.2; p[3] = ip.3
}

func checksumBuf(_ p: UnsafePointer<UInt8>, _ len: Int) -> UInt16 {
    var s: UInt32 = 0
    var i = 0
    while i + 1 < len { s += UInt32(p[i]) << 8 | UInt32(p[i+1]); i += 2 }
    if i < len { s += UInt32(p[i]) << 8 }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16) }
    return UInt16(~s & 0xffff)
}

// Write Ethernet header into `p`, return pointer to payload area.
@inline(__always)
func writeEthHdr(_ p: UnsafeMutablePointer<UInt8>,
                 dstMAC: UnsafePointer<UInt8>,
                 ethertype: UInt16) -> UnsafeMutablePointer<UInt8> {
    memcpy(p, dstMAC, 6)
    putMAC(p + 6, GW_MAC)
    put16(p + 12, ethertype)
    return p + 14
}

@inline(__always)
func writeIPv4Hdr(_ p: UnsafeMutablePointer<UInt8>,
                  srcIP: (UInt8,UInt8,UInt8,UInt8),
                  dstIP: (UInt8,UInt8,UInt8,UInt8),
                  proto: UInt8,
                  payloadLen: Int) {
    p[0] = 0x45; p[1] = 0
    put16(p + 2, UInt16(20 + payloadLen))
    p[4] = 0; p[5] = 0; p[6] = 0x40; p[7] = 0
    p[8] = 64; p[9] = proto
    p[10] = 0; p[11] = 0
    putIP4(p + 12, srcIP); putIP4(p + 16, dstIP)
    let cs = checksumBuf(p, 20)
    p[10] = UInt8(cs >> 8); p[11] = UInt8(cs & 0xff)
}

func tcpChecksum(srcIP: (UInt8,UInt8,UInt8,UInt8),
                 dstIP: (UInt8,UInt8,UInt8,UInt8),
                 tcp: UnsafePointer<UInt8>, tcpLen: Int) -> UInt16 {
    var s: UInt32 = 0
    // Pseudo-header
    s += UInt32(srcIP.0) << 8 | UInt32(srcIP.1)
    s += UInt32(srcIP.2) << 8 | UInt32(srcIP.3)
    s += UInt32(dstIP.0) << 8 | UInt32(dstIP.1)
    s += UInt32(dstIP.2) << 8 | UInt32(dstIP.3)
    s += 6 // TCP protocol
    s += UInt32(tcpLen)
    // Segment
    var i = 0
    while i + 1 < tcpLen { s += UInt32(tcp[i]) << 8 | UInt32(tcp[i+1]); i += 2 }
    if i < tcpLen { s += UInt32(tcp[i]) << 8 }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16) }
    return UInt16(~s & 0xffff)
}

// ─── TCP proxy connection ─────────────────────────────────────────────────────

final class ProxyConn {
    let hostFD:  Int32
    let srcPort: UInt16
    var mySeq:   UInt32
    var peerAck: UInt32 = 0
    var state:   Int = 0      // 0=SYN_SENT 1=ESTAB 2=CLOSED
    var pending     = UnsafeMutablePointer<UInt8>.allocate(capacity: 65536)
    var pendingLen  = 0

    init(fd: Int32, port: UInt16) {
        hostFD  = fd; srcPort = port
        mySeq   = UInt32.random(in: 0..<UInt32.max)
    }
    deinit { pending.deallocate() }
}

// ─── Network bridge ───────────────────────────────────────────────────────────

final class NetBridge {
    let vmFD:     Int32
    let hostPort: Int32
    var vmMACBuf  = UnsafeMutablePointer<UInt8>.allocate(capacity: 6) // flat buffer
    var hasVmMAC  = false
    let bcastMAC  = UnsafeMutablePointer<UInt8>.allocate(capacity: 6)
    var conns:    [Int: ProxyConn] = [:]
    var nextPort: UInt16 = 40000

    // Pre-allocated I/O buffers
    let txBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 65536)
    let rxBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 65536)

    init(vmFD: Int32, port: Int32) {
        self.vmFD = vmFD; self.hostPort = port
        memset(bcastMAC, 0xff, 6)
    }

    // ── Frame I/O ────────────────────────────────────────────────────────────

    @inline(__always)
    func sendFrame(_ len: Int) {
        _ = Darwin.write(vmFD, txBuf, len)
    }

    func tcpToVM(c: ProxyConn, flags: UInt8,
                 payload: UnsafePointer<UInt8>?, payloadLen: Int) {
        let dst = hasVmMAC ? vmMACBuf : bcastMAC
        let ip = writeEthHdr(txBuf, dstMAC: dst, ethertype: 0x0800)
        let tcp = ip + 20
        let tcpLen = 20 + payloadLen

        // TCP header
        put16(tcp, UInt16(c.srcPort))
        put16(tcp + 2, 80)
        put32(tcp + 4, c.mySeq)
        put32(tcp + 8, c.peerAck)
        tcp[12] = 0x50; tcp[13] = flags
        put16(tcp + 14, 0xffff)
        tcp[16] = 0; tcp[17] = 0; tcp[18] = 0; tcp[19] = 0

        if payloadLen > 0, let payload = payload {
            memcpy(tcp + 20, payload, payloadLen)
        }

        let cs = tcpChecksum(srcIP: GW_IP4, dstIP: VM_IP4, tcp: tcp, tcpLen: tcpLen)
        tcp[16] = UInt8(cs >> 8); tcp[17] = UInt8(cs & 0xff)

        writeIPv4Hdr(ip, srcIP: GW_IP4, dstIP: VM_IP4, proto: 6, payloadLen: tcpLen)
        sendFrame(14 + 20 + tcpLen)
    }

    // ── ARP ──────────────────────────────────────────────────────────────────

    func handleARP(_ arp: UnsafePointer<UInt8>, _ arpLen: Int,
                   srcMAC: UnsafePointer<UInt8>) {
        guard arpLen >= 28, get16(arp + 6) == 1,
              arp[24] == GW_IP4.0, arp[25] == GW_IP4.1,
              arp[26] == GW_IP4.2, arp[27] == GW_IP4.3 else { return }

        let p = writeEthHdr(txBuf, dstMAC: srcMAC, ethertype: 0x0806)
        put16(p, 1); put16(p + 2, 0x0800)
        p[4] = 6; p[5] = 4; put16(p + 6, 2)
        putMAC(p + 8, GW_MAC); putIP4(p + 14, GW_IP4)
        memcpy(p + 18, srcMAC, 6)
        memcpy(p + 24, arp + 14, 4) // target IP = request sender IP
        sendFrame(14 + 28)
    }

    // ── DHCP ─────────────────────────────────────────────────────────────────

    func handleDHCP(_ udp: UnsafePointer<UInt8>, _ udpLen: Int,
                    srcMAC: UnsafePointer<UInt8>) {
        guard udpLen >= 8, get16(udp) == 68, get16(udp + 2) == 67 else { return }
        let bootp = udp + 8, bootpLen = udpLen - 8
        guard bootpLen >= 240 else { return }

        var msgType: UInt8 = 0
        var i = 240
        while i < bootpLen {
            let t = bootp[i]; if t == 255 { break }; if t == 0 { i += 1; continue }
            guard i + 1 < bootpLen else { break }
            let l = Int(bootp[i+1])
            if t == 53, l >= 1, i + 2 < bootpLen { msgType = bootp[i+2] }
            i += 2 + l
        }
        guard msgType == 1 || msgType == 3 else { return }
        let replyType: UInt8 = (msgType == 1) ? 2 : 5

        let eth = writeEthHdr(txBuf, dstMAC: srcMAC, ethertype: 0x0800)
        let ip = eth, udpH = ip + 20, bp = udpH + 8

        memset(bp, 0, 236)
        bp[0] = 2; bp[1] = 1; bp[2] = 6
        memcpy(bp + 4, bootp + 4, 4)       // xid
        putIP4(bp + 16, VM_IP4)             // yiaddr
        putIP4(bp + 20, GW_IP4)             // siaddr
        memcpy(bp + 28, srcMAC, 6)          // chaddr

        let opts = bp + 236; var o = 0
        opts[o]=99; opts[o+1]=130; opts[o+2]=83; opts[o+3]=99; o += 4
        opts[o]=53; opts[o+1]=1; opts[o+2]=replyType; o += 3
        opts[o]=54; opts[o+1]=4; putIP4(opts+o+2, GW_IP4); o += 6
        opts[o]=51; opts[o+1]=4; put32(opts+o+2, 86400); o += 6
        opts[o]=1; opts[o+1]=4; opts[o+2]=255; opts[o+3]=255; opts[o+4]=255; opts[o+5]=0; o += 6
        opts[o]=3; opts[o+1]=4; putIP4(opts+o+2, GW_IP4); o += 6
        opts[o]=6; opts[o+1]=4; opts[o+2]=10; opts[o+3]=0; opts[o+4]=2; opts[o+5]=3; o += 6
        opts[o]=255; o += 1

        let udpTotal = 8 + 236 + o
        put16(udpH, 67); put16(udpH + 2, 68)
        put16(udpH + 4, UInt16(udpTotal)); udpH[6] = 0; udpH[7] = 0
        writeIPv4Hdr(ip, srcIP: GW_IP4, dstIP: (255,255,255,255), proto: 17, payloadLen: udpTotal)
        sendFrame(14 + 20 + udpTotal)
    }

    // ── TCP from VM ──────────────────────────────────────────────────────────

    func handleTCPFromVM(_ tcp: UnsafePointer<UInt8>, _ tcpLen: Int) {
        guard tcpLen >= 20 else { return }
        let dstPort = Int(get16(tcp + 2))
        let seq = get32(tcp + 4), ack = get32(tcp + 8)
        let flags = tcp[13]
        let doff = Int(tcp[12] >> 4) * 4
        let payloadLen = tcpLen - doff

        guard let c = conns[dstPort] else { return }
        if flags & 0x04 != 0 { // RST
            close(c.hostFD); conns.removeValue(forKey: dstPort); return
        }

        switch c.state {
        case 0: // SYN_SENT
            guard flags & 0x02 != 0, flags & 0x10 != 0 else { return } // SYN+ACK
            c.peerAck = seq + 1; c.state = 1
            tcpToVM(c: c, flags: 0x10, payload: nil, payloadLen: 0)
            if c.pendingLen > 0 {
                tcpToVM(c: c, flags: 0x18, payload: c.pending, payloadLen: c.pendingLen)
                c.mySeq += UInt32(c.pendingLen); c.pendingLen = 0
            }
        case 1: // ESTABLISHED
            _ = ack
            if payloadLen > 0 {
                c.peerAck = seq + UInt32(payloadLen)
                _ = Darwin.write(c.hostFD, tcp + doff, payloadLen)
                tcpToVM(c: c, flags: 0x10, payload: nil, payloadLen: 0)
            }
            if flags & 0x01 != 0 { // FIN
                c.peerAck += 1
                tcpToVM(c: c, flags: 0x11, payload: nil, payloadLen: 0) // FIN+ACK
                c.mySeq += 1; c.state = 2
                close(c.hostFD); conns.removeValue(forKey: dstPort)
            }
        default: break
        }
    }

    // ── Dispatchers ──────────────────────────────────────────────────────────

    @inline(__always)
    func handleIPv4(_ ip: UnsafePointer<UInt8>, _ ipLen: Int,
                    srcMAC: UnsafePointer<UInt8>) {
        guard ipLen >= 20 else { return }
        let ihl = Int(ip[0] & 0x0f) * 4
        let body = ip + ihl, bodyLen = ipLen - ihl
        if ip[9] == 17 { handleDHCP(body, bodyLen, srcMAC: srcMAC) }
        else if ip[9] == 6 { handleTCPFromVM(body, bodyLen) }
    }

    @inline(__always)
    func processFrame(_ frame: UnsafePointer<UInt8>, _ frameLen: Int) {
        guard frameLen >= 14 else { return }
        let srcMAC = frame + 6
        if !hasVmMAC && srcMAC[0] != 0xff && srcMAC[0] != GW_MAC.0 {
            memcpy(vmMACBuf, srcMAC, 6); hasVmMAC = true
        }
        let et = get16(frame + 12)
        let payload = frame + 14, pLen = frameLen - 14
        if et == 0x0806 { handleARP(payload, pLen, srcMAC: srcMAC) }
        else if et == 0x0800 { handleIPv4(payload, pLen, srcMAC: srcMAC) }
    }

    // ── New host connection ──────────────────────────────────────────────────

    func newHostConn(fd: Int32, kq: Int32) {
        let port = nextPort
        nextPort = nextPort >= 59999 ? 40000 : nextPort + 1
        var one: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, 4)
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        let c = ProxyConn(fd: fd, port: port)
        conns[Int(port)] = c
        // Register with kqueue
        var ev = kevent(ident: UInt(fd), filter: Int16(EVFILT_READ),
                        flags: UInt16(EV_ADD), fflags: 0, data: 0,
                        udata: UnsafeMutableRawPointer(bitPattern: Int(port)))
        kevent(kq, &ev, 1, nil, 0, nil)
        tcpToVM(c: c, flags: 0x02, payload: nil, payloadLen: 0) // SYN
        c.mySeq += 1
    }

    // ── Main loop (kqueue) ───────────────────────────────────────────────────

    func run() {
        // Enlarge socketpair buffers for burst throughput
        var bufSize: Int32 = 1024 * 1024
        setsockopt(vmFD, SOL_SOCKET, SO_SNDBUF, &bufSize, 4)
        setsockopt(vmFD, SOL_SOCKET, SO_RCVBUF, &bufSize, 4)
        _ = fcntl(vmFD, F_SETFL, fcntl(vmFD, F_GETFL, 0) | O_NONBLOCK)

        // Listen socket
        let listenFD = socket(AF_INET, SOCK_STREAM, 0)
        var opt: Int32 = 1
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &opt, 4)
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = UInt16(hostPort).bigEndian
        sa.sin_addr.s_addr = INADDR_ANY
        withUnsafeMutablePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        listen(listenFD, 128)
        _ = fcntl(listenFD, F_SETFL, fcntl(listenFD, F_GETFL, 0) | O_NONBLOCK)

        // Create kqueue
        let kq = kqueue()

        // Register vmFD and listenFD
        var events: [kevent] = [
            kevent(ident: UInt(vmFD), filter: Int16(EVFILT_READ),
                   flags: UInt16(EV_ADD), fflags: 0, data: 0, udata: nil),
            kevent(ident: UInt(listenFD), filter: Int16(EVFILT_READ),
                   flags: UInt16(EV_ADD), fflags: 0, data: 0, udata: nil)
        ]
        kevent(kq, &events, 2, nil, 0, nil)

        let evBuf = UnsafeMutablePointer<kevent>.allocate(capacity: 256)

        while true {
            // 1ms timeout for responsiveness
            var ts = timespec(tv_sec: 0, tv_nsec: 1_000_000)
            let nev = kevent(kq, nil, 0, evBuf, 256, &ts)
            if nev <= 0 { continue }

            for i in 0..<nev {
                let ev = evBuf[Int(i)]
                let fd = Int32(ev.ident)

                if fd == vmFD {
                    // Drain all VM frames
                    while true {
                        let r = recv(vmFD, rxBuf, 65536, Int32(MSG_DONTWAIT))
                        if r <= 0 { break }
                        processFrame(rxBuf, r)
                    }
                } else if fd == listenFD {
                    // Accept all pending connections
                    while true {
                        var ca = sockaddr_in()
                        var cl = socklen_t(MemoryLayout<sockaddr_in>.size)
                        let afd: Int32 = withUnsafeMutablePointer(to: &ca) {
                            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                accept(listenFD, $0, &cl)
                            }
                        }
                        if afd < 0 { break }
                        newHostConn(fd: afd, kq: kq)
                    }
                } else {
                    // Host connection data
                    let port = Int(bitPattern: ev.udata)
                    guard let c = conns[port] else {
                        // Stale event — remove from kqueue
                        var rmev = kevent(ident: ev.ident, filter: Int16(EVFILT_READ),
                                          flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
                        kevent(kq, &rmev, 1, nil, 0, nil)
                        continue
                    }
                    let r = Darwin.read(c.hostFD, rxBuf, 65536)
                    if r <= 0 {
                        if c.state == 1 {
                            tcpToVM(c: c, flags: 0x11, payload: nil, payloadLen: 0) // FIN+ACK
                            c.mySeq += 1
                        }
                        var rmev = kevent(ident: UInt(c.hostFD), filter: Int16(EVFILT_READ),
                                          flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
                        kevent(kq, &rmev, 1, nil, 0, nil)
                        close(c.hostFD); conns.removeValue(forKey: port)
                    } else if c.state == 1 {
                        tcpToVM(c: c, flags: 0x18, payload: rxBuf, payloadLen: r) // PSH+ACK
                        c.mySeq += UInt32(r)
                    } else {
                        memcpy(c.pending + c.pendingLen, rxBuf, r)
                        c.pendingLen += r
                    }
                }
            }
        }
    }
}

// ─── VZVirtualMachine delegate ───────────────────────────────────────────────

final class VMDelegate: NSObject, VZVirtualMachineDelegate {
    var keepAlivePipe: Pipe?
    func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: Error) {
        restoreTerminal(); fputs("run-vz: VM stopped with error: \(error)\n", stderr); exit(1)
    }
    func guestDidStop(_ vm: VZVirtualMachine) { restoreTerminal(); exit(0) }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() throws {
    let args = CommandLine.arguments
    guard args.count >= 2 else {
        fputs("Usage: run-vz <path-to.img> [host-port]\n", stderr); exit(1)
    }
    let binPath  = args[1]
    let hostPort = Int32(args.count >= 3 ? Int(args[2]) ?? 8080 : 8080)
    let memory   = Int(ProcessInfo.processInfo.environment["UNIKERNEL_MEMORY"] ?? "128")! * 1024 * 1024
    let cpus     = Int(ProcessInfo.processInfo.environment["UNIKERNEL_CPUS"] ?? "1")!

    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
        fputs("run-vz: socketpair failed\n", stderr); exit(1)
    }

    let cfg = VZVirtualMachineConfiguration()
    cfg.cpuCount = max(VZVirtualMachineConfiguration.minimumAllowedCPUCount,
                       min(VZVirtualMachineConfiguration.maximumAllowedCPUCount, cpus))
    cfg.memorySize = UInt64(memory)
    cfg.bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: binPath))

    let serialReadHandle: FileHandle
    let consolePipe: Pipe?
    if isatty(STDIN_FILENO) != 0 {
        serialReadHandle = FileHandle.standardInput; consolePipe = nil
    } else {
        let pipe = Pipe()
        serialReadHandle = pipe.fileHandleForReading; consolePipe = pipe
    }
    let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
    serialPort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: serialReadHandle,
        fileHandleForWriting: FileHandle.standardOutput)
    cfg.serialPorts = [serialPort]

    let net = VZVirtioNetworkDeviceConfiguration()
    net.attachment = VZFileHandleNetworkDeviceAttachment(
        fileHandle: FileHandle(fileDescriptor: fds[0]))
    cfg.networkDevices = [net]

    try cfg.validate()

    let bridge = NetBridge(vmFD: fds[1], port: hostPort)
    Thread { bridge.run() }.start()

    let delegate = VMDelegate()
    delegate.keepAlivePipe = consolePipe
    let vm = VZVirtualMachine(configuration: cfg, queue: .main)
    vm.delegate = delegate

    enableRawInput()
    fputs("==> VZ.framework unikernel starting\n", stderr)
    fputs("    Network: http://localhost:\(hostPort)/ → VM port 80\n", stderr)
    fputs("    Serial console below.  Press Ctrl-C to exit.\n\n", stderr)

    vm.start { result in
        if case .failure(let err) = result {
            restoreTerminal(); fputs("run-vz: failed to start VM: \(err)\n", stderr); exit(1)
        }
    }
    RunLoop.main.run()
}

try main()
