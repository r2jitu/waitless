// kernel/ffi.cc — C-linkage FFI wrappers for Rust interop
//
// Provides extern "C" functions that Rust code can call via FFI.
// These wrap the C++ namespaced kernel APIs (serial, uni, etc.)
// with stable C ABI symbols.

#include "kernel/serial.h"
#include <stdarg.h>

extern "C" {

void serial_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  serial::vprintf(fmt, ap);
  va_end(ap);
}

} // extern "C"
