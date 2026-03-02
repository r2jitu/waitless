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

} // namespace serial
