// Break mode: a hooked thread stops where it is, tells the client, and waits to be told what to do.
//
// The client answers a stopped hit (a ProbeHit or ProbeReturn whose hitId is non-zero) with Resume, StepOut or
// ForceReturn. Resume runs the function; StepOut runs it and stops again when it returns; ForceReturn skips it (or, at a
// return stop, replaces the value it returned). The wait ends by itself after kStopTimeoutMs, or at once if the client
// goes away, so a lost client cannot freeze the game for good.
//
// A stop on the thread that runs the server's tick would deadlock (nothing could read the answer), so that thread
// serves the connection from inside the wait.
#pragma once

#include "events.hpp"

namespace purah {

enum class StopAction : uint32_t { Waiting, Resume, StepOut, ForceReturn };

constexpr uint32_t kStopSlots = 8;
constexpr uint32_t kStopTimeoutMs = 30000;

struct StopSlot {
    volatile uint64_t hitId = 0;  // 0 = free
    volatile StopAction action = StopAction::Waiting;
    volatile uint64_t value = 0;
};

inline StopSlot g_stops[kStopSlots];
inline uint64_t g_nextHitId = 1;
inline volatile uint32_t g_tickThread = 0;
inline void (*g_serve)() = nullptr;  // runs one server tick; set by the server

// Claims a slot and a fresh hit id; 0 when every slot is taken (then the thread does not stop).
inline uint64_t BeginStop() {
    const uint64_t id = __atomic_add_fetch(&g_nextHitId, 1, __ATOMIC_RELAXED);
    for (uint32_t i = 0; i < kStopSlots; ++i) {
        uint64_t free = 0;
        if (__atomic_compare_exchange_n(&g_stops[i].hitId, &free, id, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            g_stops[i].action = StopAction::Waiting;
            return id;
        }
    }
    return 0;
}

// Called by the server when the client answers.
inline bool AnswerStop(uint64_t hitId, StopAction action, uint64_t value) {
    for (uint32_t i = 0; i < kStopSlots; ++i)
        if (g_stops[i].hitId == hitId && g_stops[i].action == StopAction::Waiting) {
            g_stops[i].value = value;
            g_stops[i].action = action;
            return true;
        }
    return false;
}

// Blocks the calling thread until the stop is answered. Returns the action; `*value` is the ForceReturn value.
inline StopAction WaitForStop(uint64_t hitId, uint64_t* value) {
    StopSlot* slot = nullptr;
    for (uint32_t i = 0; i < kStopSlots; ++i)
        if (g_stops[i].hitId == hitId) slot = &g_stops[i];
    if (!slot) return StopAction::Resume;

    const bool serving = host::ThreadId() == g_tickThread && g_serve != nullptr;
    StopAction action = StopAction::Waiting;
    for (uint32_t waited = 0; waited < kStopTimeoutMs; ++waited) {
        action = slot->action;
        if (action != StopAction::Waiting || !g_clientConnected) break;
        if (serving) g_serve();
        host::S::SleepNanos(1000000);
    }
    if (action == StopAction::Waiting) {
        action = StopAction::Resume;
        EmitLog(1, g_clientConnected ? "a stopped thread timed out waiting for the client and was resumed" : "the client left; a stopped thread was resumed");
    }
    *value = slot->value;
    slot->hitId = 0;
    return action;
}

}  // namespace purah
