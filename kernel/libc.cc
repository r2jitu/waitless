// kernel/libc.cc — Minimal libc and C++ runtime support
//
// Provides the standard memory/string functions required by freestanding C++,
// plus the C++ operator new/delete that delegate to mm::kmalloc/kfree, and
// the ABI support functions needed by the compiler (__cxa_pure_virtual, etc.).
//
// These are all declared extern "C" to match the expected ABI linkage.

#include "kernel/mm.h"
#include "kernel/panic.h"
#include <stddef.h>
#include <stdint.h>

extern "C" {

// ============================================================================
// Memory functions
// ============================================================================

void *memcpy(void *dest, const void *src, size_t n) {
  uint8_t *d = static_cast<uint8_t *>(dest);
  const uint8_t *s = static_cast<const uint8_t *>(src);
  for (size_t i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dest;
}

void *memset(void *dest, int val, size_t n) {
  uint8_t *d = static_cast<uint8_t *>(dest);
  uint8_t v = static_cast<uint8_t>(val);
  for (size_t i = 0; i < n; i++) {
    d[i] = v;
  }
  return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
  uint8_t *d = static_cast<uint8_t *>(dest);
  const uint8_t *s = static_cast<const uint8_t *>(src);

  if (d < s) {
    // Copy forward (no overlap risk in this direction)
    for (size_t i = 0; i < n; i++) {
      d[i] = s[i];
    }
  } else if (d > s) {
    // Copy backward to handle overlapping regions safely
    for (size_t i = n; i > 0; i--) {
      d[i - 1] = s[i - 1];
    }
  }
  // If d == s, nothing to do

  return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
  const uint8_t *a = static_cast<const uint8_t *>(s1);
  const uint8_t *b = static_cast<const uint8_t *>(s2);
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return (int)a[i] - (int)b[i];
    }
  }
  return 0;
}

// ============================================================================
// String functions
// ============================================================================

size_t strlen(const char *s) {
  size_t len = 0;
  while (s[len])
    len++;
  return len;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (s1[i] != s2[i]) {
      return (int)(unsigned char)s1[i] - (int)(unsigned char)s2[i];
    }
    if (s1[i] == '\0')
      break;
  }
  return 0;
}

char *strcpy(char *dest, const char *src) {
  char *d = dest;
  while ((*d++ = *src++) != '\0') {
    // Copy including the null terminator
  }
  return dest;
}

// optnone: prevent the compiler from widening null-padding byte stores to
// halfword/word stores (STURH/STRH), which require natural alignment that
// the destination may not have (e.g. route strings at offset +9 in Server).
__attribute__((optnone)) char *strncpy(char *dest, const char *src, size_t n) {
  size_t i;
  for (i = 0; i < n && src[i] != '\0'; i++) {
    dest[i] = src[i];
  }
  // Pad remainder with null bytes
  for (; i < n; i++) {
    dest[i] = '\0';
  }
  return dest;
}

// ============================================================================
// C++ ABI support
// ============================================================================

// Called when a pure virtual function is invoked (should never happen in
// correct code). This is a fatal error.
void __cxa_pure_virtual() { kernel_panic("Pure virtual function called!"); }

// Static destructor registration — in a unikernel we never exit, so
// global destructors are never called. Return 0 (success) as a no-op.
int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }

// DSO handle — used by __cxa_atexit for shared library identification.
// In a statically-linked kernel, this is just a null pointer.
void *__dso_handle = nullptr;

} // extern "C"

// ============================================================================
// C++ operator new/delete
// ============================================================================

// Single-object allocation
void *operator new(size_t size) { return mm::kmalloc(size); }

// Array allocation
void *operator new[](size_t size) { return mm::kmalloc(size); }

// Single-object deallocation
void operator delete(void *ptr) noexcept { mm::kfree(ptr); }

// Array deallocation
void operator delete[](void *ptr) noexcept { mm::kfree(ptr); }

// Sized single-object deallocation (C++14)
void operator delete(void *ptr, size_t) noexcept { mm::kfree(ptr); }

// Sized array deallocation (C++14)
void operator delete[](void *ptr, size_t) noexcept { mm::kfree(ptr); }
