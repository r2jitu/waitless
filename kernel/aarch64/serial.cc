// kernel/aarch64/serial.cc — ARM64 serial console driver
//
// Supports two backends, selected at runtime based on FDT discovery:
//
//   PL011 UART (QEMU "virt" machine):
//     Physical address discovered from FDT "arm,pl011" node.
//     All register accesses are MMIO.
//
//   VirtIO console (VZ.framework, or any platform with PCI):
//     Discovered via PCI bus scan (virtio-pci) or FDT virtio-mmio nodes.
//     Uses virtio_console:: driver (drivers/virtio_console.h).
//
// PL011 register map (offsets from uart_base):
//   0x000  DR    — Data Register (read/write)
//   0x018  FR    — Flag Register (bit 5 = TXFF = TX FIFO full)
//   0x024  IBRD  — Integer Baud Rate Divisor
//   0x028  FBRD  — Fractional Baud Rate Divisor
//   0x02C  LCR_H — Line Control Register
//   0x030  CR    — Control Register

#include "kernel/serial.h"
#include "drivers/pci.h"
#include "drivers/virtio_console.h"
#include "drivers/virtio_pci.h"
#include "kernel/aarch64/fdt.h"
#include <stdarg.h>

namespace serial {

// ---- Backend selection -----------------------------------------------------

enum class Backend { NONE, PL011, VIRTIO };
static Backend g_backend = Backend::NONE;

// ---- PL011 register offsets ------------------------------------------------

static constexpr uint64_t PL011_DR = 0x000;    // Data register
static constexpr uint64_t PL011_FR = 0x018;    // Flag register
static constexpr uint64_t PL011_IBRD = 0x024;  // Integer baud rate divisor
static constexpr uint64_t PL011_FBRD = 0x028;  // Fractional baud rate divisor
static constexpr uint64_t PL011_LCR_H = 0x02C; // Line control
static constexpr uint64_t PL011_CR = 0x030;    // Control

static constexpr uint32_t FR_TXFF = (1U << 5); // TX FIFO full
static constexpr uint32_t FR_RXFE = (1U << 4); // RX FIFO empty
static constexpr uint32_t CR_UARTEN = (1U << 0);
static constexpr uint32_t CR_TXE = (1U << 8);
static constexpr uint32_t CR_RXE = (1U << 9);

static uint64_t g_uart_base = 0;

static inline volatile uint32_t *pl011(uint64_t off) {
  return reinterpret_cast<volatile uint32_t *>(g_uart_base + off);
}

// ---- PL011 init ------------------------------------------------------------

static void pl011_init(uint64_t base) {
  g_uart_base = base;
  *pl011(PL011_CR) = 0;    // disable UART
  *pl011(PL011_IBRD) = 13; // 115200 @ 24 MHz
  *pl011(PL011_FBRD) = 1;
  *pl011(PL011_LCR_H) = (3U << 5) | (1U << 4); // 8N1, FIFO on
  *pl011(PL011_CR) = CR_UARTEN | CR_TXE | CR_RXE;
  g_backend = Backend::PL011;
}

// ---- Public API ------------------------------------------------------------

void init() {
  const fdt::Info &fdt = fdt::info();

  // Prefer PL011 if FDT found one (QEMU path).
  if (fdt.uart_base != 0) {
    pl011_init(fdt.uart_base);
    return;
  }

  // Try virtio-mmio console if FDT found virtio-mmio devices (QEMU path).
  if (fdt.virtio_count > 0) {
    for (int i = 0; i < fdt.virtio_count; i++) {
      if (virtio_console::init(fdt.virtio_bases[i])) {
        g_backend = Backend::VIRTIO;
        return;
      }
    }
  }

  // PCI VirtIO console (VZ.framework and any other PCI-based platform).
  // pci::init() is idempotent; calling it early is safe — the later call
  // in kernel_main() will be a no-op.
  if (fdt.pcie_ecam_base != 0) {
    pci::init();
    virtio_pci::Device *con = virtio_pci::find(3); // device type 3 = console
    if (con && virtio_console::init_pci(con)) {
      g_backend = Backend::VIRTIO;
      return;
    }
  }

  // No console found.
  // DO NOT fall back to a hardcoded PL011 address:
  //   • On VZ.framework (128MB RAM), GPA 0x09000000 is outside the
  //     Stage-2 memory map → any write causes "Internal Virtualization
  //     error" (VZError.internalError, Code=1) and VM abort.
  //   • If this path is reached, g_backend remains NONE and putc() is
  //     a no-op — kernel runs silently rather than crashing.
  // (If FDT is broken, increase UNIKERNEL_MEMORY to > 144MB to allow
  //  the PL011 fallback to work, or fix FDT parsing.)
}

void putc(char c) {
  if (g_backend == Backend::VIRTIO) {
    virtio_console::putc(c);
    return;
  }
  if (g_backend == Backend::NONE)
    return; // no output device yet
  // PL011
  while (*pl011(PL011_FR) & FR_TXFF)
    asm volatile("nop");
  *pl011(PL011_DR) = (uint32_t)(uint8_t)c;
}

void puts(const char *s) {
  while (*s) {
    if (*s == '\n')
      putc('\r');
    putc(*s++);
  }
}

// ---- Minimal printf --------------------------------------------------------
// Supports: %s %c %d %u %x %lx %p %%

static void write_uint(unsigned long long val, unsigned base, int width,
                       char pad, bool upper) {
  const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  char buf[64];
  int len = 0;

  if (val == 0) {
    buf[len++] = '0';
  } else {
    while (val > 0) {
      buf[len++] = digits[val % base];
      val /= base;
    }
  }
  // Pad
  for (int i = len; i < width; i++)
    putc(pad);
  // Print reversed
  for (int i = len - 1; i >= 0; i--)
    putc(buf[i]);
}

static void write_int(long long val, int width, char pad) {
  if (val < 0) {
    putc('-');
    write_uint((unsigned long long)(-val), 10, width - 1, pad, false);
  } else {
    write_uint((unsigned long long)val, 10, width, pad, false);
  }
}

void printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

  for (const char *p = fmt; *p; p++) {
    if (*p != '%') {
      if (*p == '\n')
        putc('\r');
      putc(*p);
      continue;
    }
    p++;

    // Flags
    char pad = ' ';
    int width = 0;
    if (*p == '0') {
      pad = '0';
      p++;
    }
    while (*p >= '0' && *p <= '9') {
      width = width * 10 + (*p - '0');
      p++;
    }

    // Length modifier
    bool is_long = false;
    if (*p == 'l') {
      is_long = true;
      p++;
      if (*p == 'l')
        p++;
    }
    if (*p == 'z') {
      is_long = true;
      p++;
    }

    switch (*p) {
    case 's': {
      const char *s = va_arg(ap, const char *);
      if (!s)
        s = "(null)";
      puts(s);
      break;
    }
    case 'c':
      putc((char)va_arg(ap, int));
      break;
    case 'd': {
      long long v =
          is_long ? va_arg(ap, long long) : (long long)va_arg(ap, int);
      write_int(v, width, pad);
      break;
    }
    case 'u': {
      unsigned long long v = is_long
                                 ? va_arg(ap, unsigned long long)
                                 : (unsigned long long)va_arg(ap, unsigned int);
      write_uint(v, 10, width, pad, false);
      break;
    }
    case 'x':
    case 'X': {
      unsigned long long v = is_long
                                 ? va_arg(ap, unsigned long long)
                                 : (unsigned long long)va_arg(ap, unsigned int);
      write_uint(v, 16, width, pad, *p == 'X');
      break;
    }
    case 'p': {
      putc('0');
      putc('x');
      write_uint((unsigned long long)va_arg(ap, void *), 16, 16, '0', false);
      break;
    }
    case '%':
      putc('%');
      break;
    default:
      putc('%');
      putc(*p);
      break;
    }
  }

  va_end(ap);
}

// ---- Shutdown detection ----------------------------------------------------

int try_getc() {
  if (g_backend == Backend::VIRTIO) {
    return virtio_console::try_getc();
  }
  if (g_backend == Backend::NONE)
    return -1;
  // PL011: FR bit 4 = RXFE; if clear, a byte is waiting
  if (!(*pl011(PL011_FR) & FR_RXFE)) {
    return (int)(uint8_t)(*pl011(PL011_DR) & 0xFF);
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

} // namespace serial
