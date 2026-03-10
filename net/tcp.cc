#include "net/tcp.h"
#include "net/ipv4.h"
#include "net/ethernet.h"
#include "kernel/mm.h"
#include "kernel/serial.h"
#include "drivers/virtio_net.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);
extern "C" void* memset(void* dst, int c, size_t n);

namespace net {
namespace tcp {

// Connection pool
static Connection connections[MAX_CONNECTIONS];
static bool initialized = false;

// Simple counter for initial sequence numbers
static uint32_t seq_counter = 100000;

// Receive buffer size for new connections
static constexpr size_t RX_BUF_SIZE = 8192;

// Maximum segment size (payload only, excluding TCP header)
static constexpr size_t MSS = 1460;

// ----- Internal helpers -----

static Connection* alloc_connection() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i].state == State::CLOSED) {
            return &connections[i];
        }
    }
    return nullptr;
}

static Connection* find_connection(Ipv4Addr remote_ip, uint16_t remote_port,
                                   uint16_t local_port) {
    // First, look for an exact match (established or in-progress connection)
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        Connection* c = &connections[i];
        if (c->state != State::CLOSED && c->state != State::LISTEN &&
            c->remote_ip == remote_ip &&
            c->remote_port == remote_port &&
            c->local_port == local_port) {
            return c;
        }
    }
    return nullptr;
}

static Connection* find_listener(uint16_t local_port) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        Connection* c = &connections[i];
        if (c->state == State::LISTEN && c->local_port == local_port) {
            return c;
        }
    }
    return nullptr;
}

static size_t rx_buf_used(Connection* conn) {
    if (conn->rx_head >= conn->rx_tail) {
        return conn->rx_head - conn->rx_tail;
    }
    return conn->rx_buf_size - conn->rx_tail + conn->rx_head;
}

static size_t rx_buf_free(Connection* conn) {
    return conn->rx_buf_size - 1 - rx_buf_used(conn);
}

static void rx_buf_write(Connection* conn, const uint8_t* data, size_t len) {
    // Fast memcpy for contiguous runs, avoiding per-byte modulo.
    while (len > 0) {
        // Contiguous space from head to end-of-buffer (or to tail if tail > head)
        size_t contig = conn->rx_buf_size - conn->rx_head;
        if (contig > len) contig = len;
        memcpy(conn->rx_buf + conn->rx_head, data, contig);
        conn->rx_head = (conn->rx_head + contig) % conn->rx_buf_size;
        data += contig;
        len -= contig;
    }
}

// Static TX buffer for send_segment.  Safe because the unikernel is
// single-threaded and the hot path (gateway ARP cached) is non-reentrant.
static uint8_t seg_buf_[sizeof(TcpHeader) + MSS];

static void send_segment(Connection* conn, uint8_t flags,
                          const void* data, size_t len) {
    size_t total = sizeof(TcpHeader) + len;
    uint8_t* buf = seg_buf_;

    TcpHeader* tcp = (TcpHeader*)buf;
    tcp->src_port = htons(conn->local_port);
    tcp->dst_port = htons(conn->remote_port);
    tcp->seq = htonl(conn->snd_nxt);
    tcp->ack = htonl(conn->rcv_nxt);
    tcp->data_offset = (5 << 4); // 20 bytes header, no options
    tcp->flags = flags;
    tcp->window = htons(conn->rcv_wnd);
    tcp->checksum = 0;
    tcp->urgent = 0;

    if (data && len > 0) {
        memcpy(buf + sizeof(TcpHeader), data, len);
    }

    tcp->checksum = tcp_checksum(config.ip, conn->remote_ip,
                                  ipv4::PROTO_TCP, buf, total);

    ipv4::send(conn->remote_ip, ipv4::PROTO_TCP, buf, total);
}

// Send a RST to a remote host (not tied to an existing connection)
static uint8_t rst_buf_[sizeof(TcpHeader)];

static void send_rst(Ipv4Addr remote_ip, uint16_t local_port,
                     uint16_t remote_port, uint32_t seq_num,
                     uint32_t ack_num) {
    size_t total = sizeof(TcpHeader);
    uint8_t* buf = rst_buf_;

    TcpHeader* tcp = (TcpHeader*)buf;
    tcp->src_port = htons(local_port);
    tcp->dst_port = htons(remote_port);
    tcp->seq = htonl(seq_num);
    tcp->ack = htonl(ack_num);
    tcp->data_offset = (5 << 4);
    tcp->flags = RST | ACK;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urgent = 0;

    tcp->checksum = tcp_checksum(config.ip, remote_ip,
                                  ipv4::PROTO_TCP, buf, total);

    ipv4::send(remote_ip, ipv4::PROTO_TCP, buf, total);
}

static void free_connection(Connection* conn) {
    if (conn->rx_buf) {
        mm::kfree(conn->rx_buf);
        conn->rx_buf = nullptr;
    }
    conn->state = State::CLOSED;
    conn->rx_head = 0;
    conn->rx_tail = 0;
    conn->accepted = false;
    conn->listener_port = 0;
}

// ----- Public API -----

void init() {
    if (initialized) return;
    memset(connections, 0, sizeof(connections));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        connections[i].state = State::CLOSED;
    }
    initialized = true;
    serial::printf("tcp: initialized (%d max connections)\n", MAX_CONNECTIONS);
}

Connection* listen(uint16_t port) {
    Connection* conn = alloc_connection();
    if (!conn) {
        serial::printf("tcp: no free connections for listen on port %u\n",
                       (unsigned)port);
        return nullptr;
    }

    memset(conn, 0, sizeof(Connection));
    conn->state = State::LISTEN;
    conn->local_port = port;
    conn->rcv_wnd = RX_BUF_SIZE - 1;
    conn->accepted = false;

    // Listeners don't need rx_buf; child connections will get them
    conn->rx_buf = nullptr;
    conn->rx_buf_size = 0;
    conn->rx_head = 0;
    conn->rx_tail = 0;

    serial::printf("tcp: listening on port %u\n", (unsigned)port);
    return conn;
}

int send(Connection* conn, const void* data, size_t len) {
    if (!conn || conn->state != State::ESTABLISHED) {
        return -1;
    }

    const uint8_t* p = (const uint8_t*)data;
    size_t sent = 0;

    while (sent < len) {
        size_t chunk = len - sent;
        if (chunk > MSS) {
            chunk = MSS;
        }

        uint8_t flags = ACK;
        // Set PSH on last segment
        if (sent + chunk >= len) {
            flags |= PSH;
        }

        send_segment(conn, flags, p + sent, chunk);
        conn->snd_nxt += (uint32_t)chunk;
        sent += chunk;
    }

    return (int)sent;
}

size_t recv(Connection* conn, void* buf, size_t max_len) {
    if (!conn || !conn->rx_buf) {
        return 0;
    }

    size_t available = rx_buf_used(conn);
    if (available == 0) {
        return 0;
    }

    size_t to_read = available;
    if (to_read > max_len) {
        to_read = max_len;
    }

    uint8_t* dst = (uint8_t*)buf;
    size_t remaining = to_read;
    while (remaining > 0) {
        size_t contig = conn->rx_buf_size - conn->rx_tail;
        if (contig > remaining) contig = remaining;
        memcpy(dst, conn->rx_buf + conn->rx_tail, contig);
        conn->rx_tail = (conn->rx_tail + contig) % conn->rx_buf_size;
        dst += contig;
        remaining -= contig;
    }

    return to_read;
}

void close(Connection* conn) {
    if (!conn) return;

    switch (conn->state) {
    case State::ESTABLISHED:
        // Send FIN, move to FIN_WAIT_1
        send_segment(conn, FIN | ACK, nullptr, 0);
        conn->snd_nxt += 1; // FIN consumes a sequence number
        conn->state = State::FIN_WAIT_1;
        break;

    case State::CLOSE_WAIT:
        // App acknowledged the remote FIN; now send our FIN
        send_segment(conn, FIN | ACK, nullptr, 0);
        conn->snd_nxt += 1;
        conn->state = State::LAST_ACK;
        break;

    case State::LISTEN:
    case State::SYN_RECEIVED:
        free_connection(conn);
        break;

    default:
        // For other states, just free
        free_connection(conn);
        break;
    }
}

bool has_data(Connection* conn) {
    if (!conn || !conn->rx_buf) {
        return false;
    }
    return rx_buf_used(conn) > 0;
}

Connection* accept(Connection* listener) {
    if (!listener || listener->state != State::LISTEN) {
        return nullptr;
    }

    // Scan for connections belonging to this listener that are ESTABLISHED
    // and have not been returned via accept() yet
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        Connection* c = &connections[i];
        if (c->state == State::ESTABLISHED &&
            c->listener_port == listener->local_port &&
            !c->accepted) {
            c->accepted = true;
            return c;
        }
    }
    return nullptr;
}

void receive(Ipv4Addr src_ip, const uint8_t* data, size_t len) {
    if (len < sizeof(TcpHeader)) {
        return;
    }

    const TcpHeader* tcp = (const TcpHeader*)data;

    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_num = ntohl(tcp->ack);
    uint8_t flags = tcp->flags;

    // Calculate data offset (header length)
    size_t tcp_header_len = (size_t)((tcp->data_offset >> 4) & 0x0F) * 4;
    if (tcp_header_len < sizeof(TcpHeader) || tcp_header_len > len) {
        return;
    }

    const uint8_t* payload = data + tcp_header_len;
    size_t payload_len = len - tcp_header_len;

    // Find matching connection
    Connection* conn = find_connection(src_ip, src_port, dst_port);

    if (!conn) {
        // No established/in-progress connection found
        if (flags & SYN) {
            // Look for a listener on this port
            Connection* listener = find_listener(dst_port);
            if (!listener) {
                // No listener: send RST
                send_rst(src_ip, dst_port, src_port, 0, seq + 1);
                return;
            }

            // Create a new connection for this SYN
            conn = alloc_connection();
            if (!conn) {
                serial::printf("tcp: no free connections for incoming SYN\n");
                return;
            }

            memset(conn, 0, sizeof(Connection));
            conn->state = State::SYN_RECEIVED;
            conn->remote_ip = src_ip;
            conn->local_port = dst_port;
            conn->remote_port = src_port;
            conn->listener_port = listener->local_port;
            conn->accepted = false;

            conn->rcv_nxt = seq + 1; // SYN consumes a sequence number
            conn->snd_nxt = seq_counter++;
            conn->snd_una = conn->snd_nxt;
            conn->rcv_wnd = RX_BUF_SIZE - 1;

            // Allocate receive buffer
            conn->rx_buf = (uint8_t*)mm::kmalloc(RX_BUF_SIZE);
            if (!conn->rx_buf) {
                serial::printf("tcp: failed to allocate rx buffer\n");
                conn->state = State::CLOSED;
                return;
            }
            conn->rx_buf_size = RX_BUF_SIZE;
            conn->rx_head = 0;
            conn->rx_tail = 0;

            // Send SYN+ACK
            send_segment(conn, SYN | ACK, nullptr, 0);
            conn->snd_nxt += 1; // SYN consumes a sequence number
            return;
        }

        // Not a SYN and no matching connection: send RST
        if (!(flags & RST)) {
            if (flags & ACK) {
                send_rst(src_ip, dst_port, src_port, ack_num, 0);
            } else {
                send_rst(src_ip, dst_port, src_port, 0, seq + (uint32_t)payload_len);
            }
        }
        return;
    }

    // RST handling: any state -> CLOSED
    if (flags & RST) {
        serial::printf("tcp: RST received, closing connection port %u\n",
                       (unsigned)conn->local_port);
        free_connection(conn);
        return;
    }

    // State machine
    switch (conn->state) {
    case State::SYN_RECEIVED:
        if (flags & ACK) {
            if (ack_num == conn->snd_nxt) {
                conn->snd_una = ack_num;
                conn->state = State::ESTABLISHED;
            }
        }
        break;

    case State::ESTABLISHED:
        // Process ACK
        if (flags & ACK) {
            // Advance snd_una if the peer acknowledged new data
            if (ack_num > conn->snd_una) {
                conn->snd_una = ack_num;
            }
        }

        // Process incoming data
        if (payload_len > 0) {
            if (seq == conn->rcv_nxt) {
                // In-order data: copy to receive buffer
                size_t space = rx_buf_free(conn);
                size_t to_copy = payload_len;
                if (to_copy > space) {
                    to_copy = space;
                }

                if (to_copy > 0) {
                    rx_buf_write(conn, payload, to_copy);
                    conn->rcv_nxt += (uint32_t)to_copy;
                }

                // Send ACK
                send_segment(conn, ACK, nullptr, 0);
            } else if (seq < conn->rcv_nxt) {
                // Duplicate/old data: re-ACK
                send_segment(conn, ACK, nullptr, 0);
            }
            // Out-of-order future data: drop (simplified stack)
        }

        // Process FIN
        if (flags & FIN) {
            conn->rcv_nxt = seq + (uint32_t)payload_len + 1; // FIN consumes a seq
            conn->state = State::CLOSE_WAIT;
            send_segment(conn, ACK, nullptr, 0);
        }
        break;

    case State::FIN_WAIT_1:
        if (flags & ACK) {
            if (ack_num == conn->snd_nxt) {
                conn->snd_una = ack_num;
                if (flags & FIN) {
                    // Simultaneous close: ACK + FIN
                    conn->rcv_nxt = seq + (uint32_t)payload_len + 1;
                    conn->state = State::TIME_WAIT;
                    send_segment(conn, ACK, nullptr, 0);
                    // Simplified: immediately free TIME_WAIT connections
                    free_connection(conn);
                } else {
                    conn->state = State::FIN_WAIT_2;
                }
            }
        } else if (flags & FIN) {
            // FIN without ACK of our FIN
            conn->rcv_nxt = seq + (uint32_t)payload_len + 1;
            conn->state = State::TIME_WAIT;
            send_segment(conn, ACK, nullptr, 0);
            free_connection(conn);
        }
        break;

    case State::FIN_WAIT_2:
        if (flags & FIN) {
            conn->rcv_nxt = seq + (uint32_t)payload_len + 1;
            conn->state = State::TIME_WAIT;
            send_segment(conn, ACK, nullptr, 0);
            // Simplified: immediately free TIME_WAIT connections
            free_connection(conn);
        }
        break;

    case State::LAST_ACK:
        if (flags & ACK) {
            if (ack_num == conn->snd_nxt) {
                free_connection(conn);
            }
        }
        break;

    case State::CLOSE_WAIT:
        // Waiting for app to call close(). Just ACK data if any.
        if (payload_len > 0 && seq == conn->rcv_nxt) {
            conn->rcv_nxt += (uint32_t)payload_len;
            send_segment(conn, ACK, nullptr, 0);
        }
        break;

    case State::TIME_WAIT:
        // Should not normally reach here since we free immediately,
        // but handle gracefully
        free_connection(conn);
        break;

    default:
        break;
    }
}

void poll() {
    virtio_net::poll(ethernet::receive);
}

} // namespace tcp
} // namespace net
