#pragma once
// kernel/aarch64/timer.h — ARM Generic Timer interface
//
// Uses the ARM64 physical counter (CNTPCT_EL0) for busy-wait timeouts.
// The frequency is read from CNTFRQ_EL0 at runtime.

#include <stdint.h>

namespace timer {

// Return current tick count (ARM64 physical counter).
static inline uint64_t now_ticks() {
    uint64_t v;
    asm volatile("mrs %0, cntpct_el0" : "=r"(v));
    return v;
}

// Return timer frequency in ticks/second (typically 24 MHz or 62.5 MHz).
static inline uint64_t freq() {
    uint64_t f;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f;
}

// Convert milliseconds to ticks.
static inline uint64_t ms_to_ticks(uint64_t ms) {
    return (freq() / 1000ULL) * ms;
}

// Return elapsed milliseconds since a previous tick snapshot.
static inline uint64_t elapsed_ms(uint64_t start) {
    return (now_ticks() - start) * 1000ULL / freq();
}

// Busy-wait for ms milliseconds.
static inline void delay_ms(uint64_t ms) {
    uint64_t end = now_ticks() + ms_to_ticks(ms);
    while (now_ticks() < end) asm volatile("nop");
}

} // namespace timer
