// Reading and writing the game's memory on the client's behalf, never faulting on a bad address.
//
// The host answers how many bytes from an address are mapped and readable (or writable), so a wrong pointer is a
// refusal. Code and read-only data are written through wiixl.patch's checked Write, which also keeps the host's record
// of who changed what; the heap is written directly after the same compare-first check.
#pragma once

#include "events.hpp"

namespace purah {

// Copies up to `length` bytes from `address`; returns how many were readable (0 = unmapped).
inline uint32_t ReadGame(uint64_t address, uint32_t length, uint8_t* out) {
    if (address < 0x10000) return 0;
    const uint64_t n = host::S::ReadableBytes(address, length);
    const auto* src = reinterpret_cast<const uint8_t*>(address);
    for (uint64_t i = 0; i < n; ++i) out[i] = src[i];
    return static_cast<uint32_t>(n);
}

// PokeResult.status: 0 written, 1 the bytes there differ from `expected`, 2 refused, 3 writes are off.
inline uint8_t PokeGame(const proto::Poke& p) {
    if (p.count == 0 || p.address < 0x10000) return 2;
    if (host::S::ReadableBytes(p.address, p.count) < p.count) return 2;
    const auto* here = reinterpret_cast<const uint8_t*>(p.address);
    for (uint16_t i = 0; i < p.count; ++i)
        if (here[i] != p.expected[i]) return 1;

    if (InImage(p.address)) return host::S::Write(p.address, p.replacement, p.count, p.expected, p.count) ? 0 : 2;
    if (host::S::WritableBytes(p.address, p.count) < p.count) return 2;
    auto* dst = reinterpret_cast<uint8_t*>(p.address);
    for (uint16_t i = 0; i < p.count; ++i) dst[i] = p.replacement[i];
    return 0;
}

}  // namespace purah
