#pragma once
#include "net/types.h"
#include <stddef.h>
#include <stdint.h>

namespace net {
namespace tcp {

struct TcpHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset; // (offset >> 4) * 4 = header length in bytes
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
} __attribute__((packed));

// TCP flags
static constexpr uint8_t FIN = 0x01;
static constexpr uint8_t SYN = 0x02;
static constexpr uint8_t RST = 0x04;
static constexpr uint8_t PSH = 0x08;
static constexpr uint8_t ACK = 0x10;

enum class State {
  CLOSED,
  LISTEN,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  LAST_ACK,
  TIME_WAIT
};

struct Connection {
  State state = State::CLOSED;
  Ipv4Addr remote_ip;
  uint16_t local_port;
  uint16_t remote_port;

  uint32_t snd_nxt; // Next sequence number to send
  uint32_t snd_una; // Oldest unacknowledged
  uint32_t rcv_nxt; // Next expected receive sequence
  uint16_t rcv_wnd; // Receive window

  // Receive buffer (ring buffer)
  uint8_t *rx_buf;
  size_t rx_buf_size;
  size_t rx_head; // Write position
  size_t rx_tail; // Read position

  // Port of the listener that spawned this connection
  uint16_t listener_port;

  // Flag: has this connection been returned to the app via accept()?
  bool accepted;

  bool valid() const { return state != State::CLOSED; }
};

// Max simultaneous connections
static constexpr int MAX_CONNECTIONS = 128;

// Initialize TCP subsystem
void init();

// Create a listening socket on a port. Returns connection pointer.
Connection *listen(uint16_t port);

// Send data on an established connection.
// Returns number of bytes sent, or -1 on error.
int send(Connection *conn, const void *data, size_t len);

// Read data from connection's receive buffer.
// Returns bytes read (0 if no data available).
size_t recv(Connection *conn, void *buf, size_t max_len);

// Close a connection gracefully (send FIN).
void close(Connection *conn);

// Process a received TCP segment. Called by ipv4::receive().
void receive(Ipv4Addr src_ip, const uint8_t *data, size_t len);

// Poll network: process received packets.
// Call this regularly from your event loop.
void poll();

// Check if connection has data available to read.
bool has_data(Connection *conn);

// Check if there's a pending incoming connection on a listener.
// Returns the new connection, or nullptr if none.
Connection *accept(Connection *listener);

} // namespace tcp
} // namespace net
