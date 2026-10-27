// The entry every function hook goes through.
//
// A C++ hook function cannot be a faithful stand-in for a game function: the compiler is free to use x8 before the hook body can read it, and
// x8 is where the caller passes the address of a returned struct (the document loaders return one, and calling them with a garbage x8 writes
// through it). So the hook entry is assembly, in three parts:
//
//   purah_stub_N   one per book row, generated into book_stubs.hpp: `mov w16, #N` then a branch to purah_common.
//   purah_common   saves x0..x8, the caller's stack pointer (where its stack arguments start) and its return address in a Frame on this
//                  stack, calls purah_dispatch(N, frame), then returns purah_dispatch's value in x0 and the frame's second result in x1.
//   purah_call     calls the original function with the saved x0..x8 and a copy of the first four stack arguments, and keeps both result
//                  registers in the frame.
//
// The floating-point argument registers are not touched: none of this code (and none of the C++ it calls, which is built
// general-regs-only) writes them.
#pragma once

#include <cstdint>

namespace purah {

// What purah_common saves. The caller's return address is the word just before the frame.
struct Frame {
    uint64_t x[8];       // x0..x7 as the game passed them
    uint64_t x8;         // the struct-return address, if the function has one
    uint64_t stackArgs;  // the caller's stack pointer: its first stack arguments are here
    uint64_t r0;         // what the original returned in x0
    uint64_t r1;         // and in x1
};

inline uint64_t CallerReturnAddress(const Frame* f) { return reinterpret_cast<const uint64_t*>(f)[-1]; }

}  // namespace purah

extern "C" uint64_t purah_dispatch(uint32_t id, purah::Frame* frame);
extern "C" uint64_t purah_call(uintptr_t original, purah::Frame* frame);

asm(R"(
    .text
    .balign 4
    .global purah_common
purah_common:
    mov   x17, sp
    sub   sp, sp, #128
    stp   x29, x30, [sp]
    mov   x29, sp
    stp   x0, x1, [sp, #16]
    stp   x2, x3, [sp, #32]
    stp   x4, x5, [sp, #48]
    stp   x6, x7, [sp, #64]
    str   x8, [sp, #80]
    str   x17, [sp, #88]
    stp   xzr, xzr, [sp, #96]
    uxtw  x16, w16
    mov   x0, x16
    add   x1, sp, #16
    bl    purah_dispatch
    ldr   x1, [sp, #104]
    ldp   x29, x30, [sp]
    add   sp, sp, #128
    ret

    .balign 4
    .global purah_call
purah_call:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    stp   x19, x20, [sp, #-16]!
    mov   x19, x1
    mov   x16, x0
    sub   sp, sp, #32
    ldr   x9, [x19, #72]
    ldp   x10, x11, [x9]
    stp   x10, x11, [sp]
    ldp   x10, x11, [x9, #16]
    stp   x10, x11, [sp, #16]
    ldp   x0, x1, [x19]
    ldp   x2, x3, [x19, #16]
    ldp   x4, x5, [x19, #32]
    ldp   x6, x7, [x19, #48]
    ldr   x8, [x19, #64]
    blr   x16
    add   sp, sp, #32
    stp   x0, x1, [x19, #80]
    ldp   x19, x20, [sp], #16
    ldp   x29, x30, [sp], #16
    ret
)");
