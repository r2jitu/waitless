#pragma once
// kernel/limine.h — Limine Boot Protocol definitions (revision 3)
//
// Struct layouts and magic numbers taken from the official limine.h
// (https://github.com/limine-bootloader/limine).
// BSD Zero Clause License, (C) 2022-2025 mintsuki and contributors.
//
// Only the features we actually use are defined here.

#include <stdint.h>

namespace limine {

// ---- Common magic (first two uint64s of every request ID) -------------------

static constexpr uint64_t COMMON_MAGIC_0 = 0xc7b1dd30df4c8b88;
static constexpr uint64_t COMMON_MAGIC_1 = 0x0a82e883a194f07b;

// ---- Base revision (must appear in .limine_requests) ------------------------

struct BaseRevision {
  uint64_t id[2] = {0xf9562b2d5c95a6c8, 0x6a7b384944536bdc};
  uint64_t revision = 3;
};

// ---- Section markers --------------------------------------------------------

static constexpr uint64_t REQUESTS_START_MARKER[4] = {
    0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf,
    0x785c6ed015d3e316, 0x181e920a7852b9d9};
static constexpr uint64_t REQUESTS_END_MARKER[2] = {
    0xadc0e0531bb10d03, 0x9572709f31764c62};

// ---- Memory map -------------------------------------------------------------

static constexpr uint64_t MEMMAP_USABLE = 0;
static constexpr uint64_t MEMMAP_RESERVED = 1;
static constexpr uint64_t MEMMAP_ACPI_RECLAIMABLE = 2;
static constexpr uint64_t MEMMAP_ACPI_NVS = 3;
static constexpr uint64_t MEMMAP_BAD_MEMORY = 4;
static constexpr uint64_t MEMMAP_BOOTLOADER_RECLAIMABLE = 5;
static constexpr uint64_t MEMMAP_KERNEL_AND_MODULES = 6;
static constexpr uint64_t MEMMAP_FRAMEBUFFER = 7;

struct MemmapEntry {
  uint64_t base;
  uint64_t length;
  uint64_t type;
};

struct MemmapResponse {
  uint64_t revision;
  uint64_t entry_count;
  MemmapEntry **entries;
};

struct MemmapRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0x67cf3d9d378a806f, 0xe304acdfc50c3c62};
  uint64_t revision = 0;
  MemmapResponse *response = nullptr;
};

// ---- Entry point ------------------------------------------------------------

typedef void (*EntryPointFunc)();

struct EntryPointResponse {
  uint64_t revision;
};

struct EntryPointRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0x13d86c035a1cd3e1, 0x2b0caa89d8f3026a};
  uint64_t revision = 0;
  EntryPointResponse *response = nullptr;
  EntryPointFunc entry = nullptr;
};

// ---- HHDM (Higher Half Direct Map) -----------------------------------------

struct HhdmResponse {
  uint64_t revision;
  uint64_t offset;
};

struct HhdmRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0x48dcf1cb8ad2b852, 0x63984e959a98244b};
  uint64_t revision = 0;
  HhdmResponse *response = nullptr;
};

// ---- Kernel address ---------------------------------------------------------

struct KernelAddressResponse {
  uint64_t revision;
  uint64_t physical_base;
  uint64_t virtual_base;
};

struct KernelAddressRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0x71ba76863cc55f63, 0xb2644a48c516a487};
  uint64_t revision = 0;
  KernelAddressResponse *response = nullptr;
};

// ---- DTB (aarch64) ----------------------------------------------------------

struct DtbResponse {
  uint64_t revision;
  void *dtb_ptr;
};

struct DtbRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0xb40ddb48fb54bac7, 0x545081493f81ffb7};
  uint64_t revision = 0;
  DtbResponse *response = nullptr;
};

// ---- RSDP (x86) -------------------------------------------------------------

struct RsdpResponse {
  uint64_t revision;
  void *address;
};

struct RsdpRequest {
  uint64_t id[4] = {COMMON_MAGIC_0, COMMON_MAGIC_1,
                     0xc5e77b6b397e7b43, 0x27637845accdcf3c};
  uint64_t revision = 0;
  RsdpResponse *response = nullptr;
};

} // namespace limine
