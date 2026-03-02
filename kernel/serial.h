#pragma once

// kernel/serial.h — Serial port driver (COM1) interface
//
// Provides formatted text output over the serial port for kernel logging
// and debugging. COM1 at 0x3F8, 115200 baud, 8N1.

#include <stdint.h>

namespace serial {

// Initialize COM1 at 115200 baud, 8N1, FIFO enabled
void init();

// Write a single character (waits for TX buffer to be ready)
void putc(char c);

// Write a null-terminated string
void puts(const char* s);

// Minimal printf supporting: %s %d %u %x %lx %p %c %%
// No heap allocation. Uses va_list internally.
void printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// Read one byte from the serial RX buffer without blocking.
// Returns the byte value (0–255) if data is available, or -1 if empty.
int try_getc();

// Returns true if a graceful-shutdown request has arrived on the serial port
// (i.e., byte 0x03, which QEMU sends when the user presses Ctrl-C with
// signal=off).  Once set, subsequent calls always return true.
bool check_shutdown();

} // namespace serial
