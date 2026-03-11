#pragma once

// kernel/arch.h — Architecture-specific helpers (dispatcher)
//
// Includes the right per-architecture header based on the compiler target.
// All code that includes this header gets a uniform `arch::` namespace
// regardless of the target CPU.

#if defined(__aarch64__)
#include "kernel/aarch64/arch.h"
#elif defined(__x86_64__)
#include "kernel/x86_64/arch.h"
#else
#error "Unknown target architecture — add an arch.h include above"
#endif
