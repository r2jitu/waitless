// kernel/x86_64/serial.cc — Serial port driver implementation (COM1)
//
// Implements 115200 baud 8N1 serial output on COM1 (I/O port 0x3F8).
// This is the primary debug output channel for the unikernel since there
// is no VGA/framebuffer console. QEMU's -serial stdio flag maps this to
// the host terminal.

#include "kernel/serial.h"
#include "kernel/arch.h"
#include <stdarg.h>
#include <stddef.h>

namespace serial {

// COM1 port base address and register offsets
static constexpr uint16_t COM1 = 0x3F8;

// Register offsets from base port
static constexpr uint16_t RBR = 0; // Receive Buffer Register (read, DLAB=0)
static constexpr uint16_t THR = 0; // Transmit Holding Register (write, DLAB=0)
static constexpr uint16_t DLL = 0; // Divisor Latch Low (DLAB=1)
static constexpr uint16_t DLH = 1; // Divisor Latch High (DLAB=1)
static constexpr uint16_t IER = 1; // Interrupt Enable Register (DLAB=0)
static constexpr uint16_t FCR = 2; // FIFO Control Register (write)
static constexpr uint16_t LCR = 3; // Line Control Register
static constexpr uint16_t MCR = 4; // Modem Control Register
static constexpr uint16_t LSR = 5; // Line Status Register

// ============================================================================
// Internal formatting helpers
// ============================================================================

// Hex digit lookup
static const char hex_chars[] = "0123456789abcdef";

// Write an unsigned 64-bit integer in hexadecimal (no leading "0x")
static void write_hex(uint64_t val) {
  // Find the highest non-zero nibble (or print "0" if val is 0)
  if (val == 0) {
    putc('0');
    return;
  }

  // Count leading zero nibbles to skip them
  int started = 0;
  for (int i = 60; i >= 0; i -= 4) {
    uint8_t nibble = (val >> i) & 0xF;
    if (nibble != 0 || started) {
      putc(hex_chars[nibble]);
      started = 1;
    }
  }
}

// Write an unsigned 64-bit integer in hexadecimal with zero-padding
// to the specified width (for %02x style formatting)
static void write_hex_padded(uint64_t val, int width) {
  // Buffer for up to 16 hex digits
  char buf[17];
  int len = 0;

  if (val == 0) {
    buf[len++] = '0';
  } else {
    uint64_t tmp = val;
    while (tmp > 0) {
      buf[len++] = hex_chars[tmp & 0xF];
      tmp >>= 4;
    }
  }

  // Pad with zeros to requested width
  for (int i = len; i < width; i++) {
    putc('0');
  }

  // Print digits in reverse (they were stored LSB-first)
  for (int i = len - 1; i >= 0; i--) {
    putc(buf[i]);
  }
}

// Write an unsigned 64-bit integer in decimal
static void write_dec(uint64_t val) {
  if (val == 0) {
    putc('0');
    return;
  }

  // Maximum digits in a 64-bit decimal number is 20
  char buf[21];
  int pos = 0;

  while (val > 0) {
    buf[pos++] = '0' + (val % 10);
    val /= 10;
  }

  // Print in reverse order
  for (int i = pos - 1; i >= 0; i--) {
    putc(buf[i]);
  }
}

// Write a signed 64-bit integer in decimal
static void write_signed_dec(int64_t val) {
  if (val < 0) {
    putc('-');
    // Handle INT64_MIN carefully: -(INT64_MIN) overflows.
    // Cast to unsigned after negation trick.
    write_dec((uint64_t)(-(val + 1)) + 1);
  } else {
    write_dec((uint64_t)val);
  }
}

// ============================================================================
// Public API
// ============================================================================

void init() {
  // Disable all UART interrupts
  arch::outb(COM1 + IER, 0x00);

  // Enable DLAB (Divisor Latch Access Bit) to set baud rate
  arch::outb(COM1 + LCR, 0x80);

  // Set divisor to 1 (115200 baud)
  // Baud divisor = 115200 / desired_baud = 115200 / 115200 = 1
  arch::outb(COM1 + DLL, 0x01); // Divisor low byte
  arch::outb(COM1 + DLH, 0x00); // Divisor high byte

  // Configure line: 8 data bits, no parity, 1 stop bit (8N1)
  // Also clears DLAB
  arch::outb(COM1 + LCR, 0x03);

  // Enable FIFO, clear TX/RX queues, 14-byte threshold
  arch::outb(COM1 + FCR, 0xC7);

  // Set RTS/DSR + OUT2 (required for interrupts on some hardware)
  arch::outb(COM1 + MCR, 0x0B);
}

void putc(char c) {
  // Wait for the Transmit Holding Register to be empty
  // LSR bit 5 (0x20) = THR empty
  while ((arch::inb(COM1 + LSR) & 0x20) == 0) {
    // Busy-wait (spin)
  }

  arch::outb(COM1 + THR, c);
}

void puts(const char *s) {
  if (!s)
    return;
  while (*s) {
    if (*s == '\n') {
      putc('\r'); // Convert LF to CRLF for terminal compatibility
    }
    putc(*s);
    s++;
  }
}

void printf(const char *fmt, ...) {
  if (!fmt)
    return;

  va_list args;
  va_start(args, fmt);

  while (*fmt) {
    if (*fmt != '%') {
      if (*fmt == '\n')
        putc('\r');
      putc(*fmt);
      fmt++;
      continue;
    }

    fmt++; // Skip '%'

    // Parse optional zero-padding width (e.g., %02x)
    int pad_width = 0;
    bool zero_pad = false;

    if (*fmt == '0') {
      zero_pad = true;
      fmt++;
      // Parse width digits
      while (*fmt >= '0' && *fmt <= '9') {
        pad_width = pad_width * 10 + (*fmt - '0');
        fmt++;
      }
    } else if (*fmt >= '1' && *fmt <= '9') {
      while (*fmt >= '0' && *fmt <= '9') {
        pad_width = pad_width * 10 + (*fmt - '0');
        fmt++;
      }
    }

    // Check for 'l' length modifier
    bool long_mod = false;
    if (*fmt == 'l') {
      long_mod = true;
      fmt++;
    }

    switch (*fmt) {
    case 's': {
      const char *s = va_arg(args, const char *);
      puts(s ? s : "(null)");
      break;
    }
    case 'd': {
      int64_t val;
      if (long_mod) {
        val = va_arg(args, int64_t);
      } else {
        val = va_arg(args, int);
      }
      write_signed_dec(val);
      break;
    }
    case 'u': {
      uint64_t val;
      if (long_mod) {
        val = va_arg(args, uint64_t);
      } else {
        val = va_arg(args, unsigned int);
      }
      write_dec(val);
      break;
    }
    case 'x': {
      uint64_t val;
      if (long_mod) {
        val = va_arg(args, uint64_t);
      } else {
        val = va_arg(args, unsigned int);
      }
      if (zero_pad && pad_width > 0) {
        write_hex_padded(val, pad_width);
      } else {
        write_hex(val);
      }
      break;
    }
    case 'p': {
      // Pointer: print as 0x followed by hex
      uint64_t val = (uint64_t)va_arg(args, void *);
      puts("0x");
      write_hex(val);
      break;
    }
    case 'c': {
      // char is promoted to int in va_arg
      char c = (char)va_arg(args, int);
      putc(c);
      break;
    }
    case '%': {
      putc('%');
      break;
    }
    case '\0': {
      // Format string ended with a trailing '%'
      goto done;
    }
    default: {
      // Unknown format specifier — print it literally
      putc('%');
      putc(*fmt);
      break;
    }
    }

    fmt++;
  }

done:
  va_end(args);
}

// ============================================================================
// Shutdown detection
// ============================================================================

int try_getc() {
  // LSR bit 0 = Data Ready: at least one byte is in the RX FIFO
  if (arch::inb(COM1 + LSR) & 0x01) {
    return (int)(uint8_t)arch::inb(COM1 + RBR);
  }
  return -1;
}

static bool shutdown_requested = false;

bool check_shutdown() {
  if (shutdown_requested)
    return true;
  int c;
  while ((c = try_getc()) >= 0) {
    if (c == 0x03) { // Ctrl-C byte forwarded by QEMU (signal=off)
      shutdown_requested = true;
      return true;
    }
  }
  return false;
}

void enable_rx_irq() {
  // Enable ERBFI (Received Data Available Interrupt) in the UART IER.
  // After calling this, COM1 will assert IRQ4 whenever the RX FIFO
  // has data.  The caller must register an IDT handler and unmask
  // IRQ4 in the 8259 PIC before this takes effect.
  arch::outb(COM1 + IER, 0x01);
}

void rx_isr() {
  // Drain the RX FIFO to clear the UART interrupt condition.
  // Must be called from the IRQ4 ISR on x86.
  int c;
  while ((c = try_getc()) >= 0) {
    if (c == 0x03)
      shutdown_requested = true;
  }
}

} // namespace serial
