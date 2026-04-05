// kernel/serial_printf.cc — C++ printf/vprintf shim over Rust serial_putc
//
// Provides serial::printf and serial::vprintf for C++ callers that need
// formatted output. Calls the Rust serial_putc (kernel/serial.rs) for
// character output. Will be removed once all C++ callers are migrated.
//
// Supports: %s %c %d %u %x %lx %p %%
//           Width and zero-padding (e.g. %02x, %016lx)

#include <stdarg.h>
#include <stdint.h>

// Rust serial functions (kernel/serial.rs)
extern "C" void serial_putc(uint8_t c);
extern "C" void serial_puts(const char *s);

namespace serial {

// Forward declarations from serial.h that we implement here.
void printf(const char *fmt, ...);
void vprintf(const char *fmt, va_list ap);

// ---- Internal formatting helpers -------------------------------------------

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
  for (int i = len; i < width; i++)
    serial_putc(pad);
  for (int i = len - 1; i >= 0; i--)
    serial_putc(buf[i]);
}

static void write_int(long long val, int width, char pad) {
  if (val < 0) {
    serial_putc('-');
    write_uint((unsigned long long)(-val), 10, width - 1, pad, false);
  } else {
    write_uint((unsigned long long)val, 10, width, pad, false);
  }
}

// ---- Public API ------------------------------------------------------------

void vprintf(const char *fmt, va_list ap) {
  for (const char *p = fmt; *p; p++) {
    if (*p != '%') {
      if (*p == '\n')
        serial_putc('\r');
      serial_putc(*p);
      continue;
    }
    p++;

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
      serial_puts(s ? s : "(null)");
      break;
    }
    case 'c':
      serial_putc((char)va_arg(ap, int));
      break;
    case 'd': {
      long long v =
          is_long ? va_arg(ap, long long) : (long long)va_arg(ap, int);
      write_int(v, width, pad);
      break;
    }
    case 'u': {
      unsigned long long v = is_long ? va_arg(ap, unsigned long long)
                                     : (unsigned long long)va_arg(ap, unsigned);
      write_uint(v, 10, width, pad, false);
      break;
    }
    case 'x':
    case 'X': {
      unsigned long long v = is_long ? va_arg(ap, unsigned long long)
                                     : (unsigned long long)va_arg(ap, unsigned);
      write_uint(v, 16, width, pad, *p == 'X');
      break;
    }
    case 'p': {
      serial_putc('0');
      serial_putc('x');
      write_uint((unsigned long long)va_arg(ap, void *), 16, 16, '0', false);
      break;
    }
    case '%':
      serial_putc('%');
      break;
    default:
      serial_putc('%');
      serial_putc(*p);
      break;
    }
  }
}

void printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
}

} // namespace serial
