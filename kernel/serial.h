#pragma once

// kernel/serial.h — Serial console interface
//
// Thin C++ wrapper around the Rust serial implementation (kernel/serial.rs).
// The extern "C" functions are exported by the Rust library; the namespace
// serial inlines provide source-compatible C++ API.
//
// printf/vprintf remain implemented in C++ (serial_printf.cc) since Rust
// cannot export C-compatible variadic functions on stable.

#include <stdarg.h>
#include <stdint.h>

// ---- Rust extern "C" functions (kernel/serial.rs) ----

extern "C" {
void serial_init();
void serial_putc(uint8_t c);
void serial_puts(const char *s);
int serial_try_getc();
bool serial_check_shutdown();
}

// ---- Source-compatible C++ namespace wrappers ----

namespace serial {

inline void init() { serial_init(); }
inline void putc(char c) { serial_putc((uint8_t)c); }
inline void puts(const char *s) { serial_puts(s); }
inline int try_getc() { return serial_try_getc(); }
inline bool check_shutdown() { return serial_check_shutdown(); }

// printf/vprintf — implemented in serial_printf.cc (calls Rust serial_putc)
void printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void vprintf(const char *fmt, va_list args);

} // namespace serial
