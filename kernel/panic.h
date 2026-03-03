#pragma once

// kernel/panic.h — Kernel panic and assertion support
//
// Provides kernel_panic() for unrecoverable errors and an ASSERT macro
// for debug-time invariant checking. Both halt the machine after printing
// diagnostic information to the serial console.

#include "kernel/serial.h"
#include "kernel/arch.h"

// Halt the system with a panic message.
// Prints the message to the serial console, then enters an infinite
// cli/hlt loop from which there is no recovery.
[[noreturn]] inline void kernel_panic(const char* msg) {
    // Disable interrupts immediately to prevent further damage
    arch::cli();

    serial::puts("\n!!! KERNEL PANIC !!!\n");
    serial::puts(msg);
    serial::puts("\nSystem halted.\n");

    // Shut down via PSCI so hypervisors (VZ, QEMU) exit cleanly.
    // On bare metal, this falls through to an infinite WFE loop.
    arch::shutdown();
}

// Assertion macro for kernel invariant checking.
// On failure, prints file, line, and the failed condition, then panics.
#define ASSERT(cond)                                                          \
    do {                                                                      \
        if (!(cond)) {                                                        \
            serial::printf("ASSERT FAILED: %s\n  at %s:%d\n",                \
                           #cond, __FILE__, __LINE__);                        \
            kernel_panic("Assertion failure");                                \
        }                                                                     \
    } while (0)
