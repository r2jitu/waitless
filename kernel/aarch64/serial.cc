// kernel/aarch64/serial.cc — PL011 UART driver for ARM64
//
// The QEMU "virt" machine exposes a PL011 UART at physical address 0x09000000.
// All register accesses are MMIO (no I/O ports on ARM64).
//
// PL011 register map (offsets from UART_BASE):
//   0x000  DR    — Data Register (read/write)
//   0x018  FR    — Flag Register (bit 5 = TXFF = TX FIFO full)
//   0x024  IBRD  — Integer Baud Rate Divisor
//   0x028  FBRD  — Fractional Baud Rate Divisor
//   0x02C  LCR_H — Line Control Register
//   0x030  CR    — Control Register

#include "kernel/serial.h"
#include <stdarg.h>

namespace serial {

// ---- PL011 register base and offsets ---------------------------------------

static constexpr uint64_t UART_BASE = 0x09000000UL;

static constexpr uint64_t DR    = UART_BASE + 0x000; // Data register
static constexpr uint64_t FR    = UART_BASE + 0x018; // Flag register
static constexpr uint64_t IBRD  = UART_BASE + 0x024; // Integer baud rate divisor
static constexpr uint64_t FBRD  = UART_BASE + 0x028; // Fractional baud rate divisor
static constexpr uint64_t LCR_H = UART_BASE + 0x02C; // Line control
static constexpr uint64_t CR    = UART_BASE + 0x030; // Control

static constexpr uint32_t FR_TXFF = (1U << 5);  // TX FIFO full
static constexpr uint32_t CR_UARTEN = (1U << 0); // UART enable
static constexpr uint32_t CR_TXE    = (1U << 8); // TX enable
static constexpr uint32_t CR_RXE    = (1U << 9); // RX enable

static inline volatile uint32_t* reg(uint64_t addr) {
    return reinterpret_cast<volatile uint32_t*>(addr);
}

// ---- Public API ------------------------------------------------------------

void init() {
    // Disable UART
    *reg(CR) = 0;

    // Baud rate: QEMU doesn't enforce baud in emulation, but set 115200
    // Assuming 24 MHz UART clock: divisor = 24000000 / (16 * 115200) = 13.02
    // IBRD = 13, FBRD = floor(0.02 * 64 + 0.5) = 1
    *reg(IBRD) = 13;
    *reg(FBRD) = 1;

    // 8 bits, 1 stop, no parity, FIFO enabled
    *reg(LCR_H) = (3U << 5) | (1U << 4); // WLEN=11 (8-bit), FEN=1

    // Enable UART with TX and RX
    *reg(CR) = CR_UARTEN | CR_TXE | CR_RXE;
}

void putc(char c) {
    // Wait until the TX FIFO has room
    while (*reg(FR) & FR_TXFF)
        asm volatile("nop");
    *reg(DR) = (uint32_t)(uint8_t)c;
}

void puts(const char* s) {
    while (*s) {
        if (*s == '\n') putc('\r');
        putc(*s++);
    }
}

// ---- Minimal printf --------------------------------------------------------
// Supports: %s %c %d %u %x %lx %p %%

static void write_uint(unsigned long long val, unsigned base, int width,
                       char pad, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buf[64];
    int  len = 0;

    if (val == 0) {
        buf[len++] = '0';
    } else {
        while (val > 0) {
            buf[len++] = digits[val % base];
            val /= base;
        }
    }
    // Pad
    for (int i = len; i < width; i++) putc(pad);
    // Print reversed
    for (int i = len - 1; i >= 0; i--) putc(buf[i]);
}

static void write_int(long long val, int width, char pad) {
    if (val < 0) {
        putc('-');
        write_uint((unsigned long long)(-val), 10, width - 1, pad, false);
    } else {
        write_uint((unsigned long long)val, 10, width, pad, false);
    }
}

void printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    for (const char* p = fmt; *p; p++) {
        if (*p != '%') {
            if (*p == '\n') putc('\r');
            putc(*p);
            continue;
        }
        p++;

        // Flags
        char pad = ' ';
        int  width = 0;
        if (*p == '0') { pad = '0'; p++; }
        while (*p >= '0' && *p <= '9') {
            width = width * 10 + (*p - '0');
            p++;
        }

        // Length modifier
        bool is_long = false;
        if (*p == 'l') { is_long = true; p++; if (*p == 'l') p++; }
        if (*p == 'z') { is_long = true; p++; }

        switch (*p) {
            case 's': {
                const char* s = va_arg(ap, const char*);
                if (!s) s = "(null)";
                puts(s);
                break;
            }
            case 'c':
                putc((char)va_arg(ap, int));
                break;
            case 'd': {
                long long v = is_long ? va_arg(ap, long long)
                                      : (long long)va_arg(ap, int);
                write_int(v, width, pad);
                break;
            }
            case 'u': {
                unsigned long long v = is_long ? va_arg(ap, unsigned long long)
                                               : (unsigned long long)va_arg(ap, unsigned int);
                write_uint(v, 10, width, pad, false);
                break;
            }
            case 'x':
            case 'X': {
                unsigned long long v = is_long ? va_arg(ap, unsigned long long)
                                               : (unsigned long long)va_arg(ap, unsigned int);
                write_uint(v, 16, width, pad, *p == 'X');
                break;
            }
            case 'p': {
                putc('0'); putc('x');
                write_uint((unsigned long long)va_arg(ap, void*), 16, 16, '0', false);
                break;
            }
            case '%':
                putc('%');
                break;
            default:
                putc('%'); putc(*p);
                break;
        }
    }

    va_end(ap);
}

} // namespace serial
