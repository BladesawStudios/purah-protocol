// Which way a failing function went out.
//
// A function that returns false has several places it can do so. tools/ghidra/ExportReturnSites.py lists them, and a tiny hook sits on each
// hookable one (book_exits.hpp); when a path to false is taken its hook records "this thread left this function through exit N". When the step
// that called the function then fails, the watch asks which exit was last taken and reports it (ActorExit). What an exit means is Prism's business:
// the module knows only the function, the exit's number and how many exits the function has.
//
// Works for any function in the table: the step functions, and the preloadPrepare / initialize / postInitialize function of every component class
// (the watch finds a component's stage function from its name, through book::kComponentStages).
#pragma once

#include "book_data.hpp"
#include "book_exits.hpp"
#include "events.hpp"

namespace purah {

constexpr uint16_t kNoExit = 0xFFFF;
constexpr int kNoFunction = -1;

struct ExitHit {
    volatile uint32_t thread = 0;
    volatile uint16_t id = kNoExit;
};

inline volatile bool g_exitsActive = false;
inline bool g_exitInstalled[book::kExitCount > 0 ? book::kExitCount : 1] = {};

extern "C" ExitHit purah_exit_hits[];

// The index of the function with this offset in the exit table, or kNoFunction when it has no hookable exit.
inline int FunctionIndex(uint32_t offset) {
    for (uint32_t i = 0; i < book::kFunctionCount; ++i)
        if (book::kFunctions[i] == offset) return static_cast<int>(i);
    return kNoFunction;
}

// The stage function (1 preload, 2 initialize, 3 post) of the component class `name`, as an exit-table index.
inline int ComponentStageFunction(const char* name, uint32_t length, uint8_t stage) {
    for (uint32_t i = 0; i < book::kStageCount; ++i) {
        const book::ComponentStages& known = book::kComponentStages[i];
        if (!SameText(name, length, known.name)) continue;
        const uint32_t offset = stage == 1 ? known.preload : stage == 2 ? known.initialize : known.post;
        return offset ? FunctionIndex(offset) : kNoFunction;
    }
    return kNoFunction;
}

inline void ClearExit(int func) {
    if (func >= 0) purah_exit_hits[func].thread = 0;
}

// The exit the calling thread last took out of the function, or kNoExit; consumed.
inline uint16_t TakeExit(int func) {
    if (func < 0) return kNoExit;
    ExitHit& hit = purah_exit_hits[func];
    if (hit.thread != host::ThreadId()) return kNoExit;
    const uint16_t id = hit.id;
    hit.thread = 0;
    hit.id = kNoExit;
    return id;
}

}  // namespace purah

// Written by the generated stubs (book_exits.hpp), which find them by name: one hit per function (8 bytes: thread, exit, padding), and for each
// patched branch the two addresses its stub jumps to (where the branch went, and the next instruction), filled in at install from the image base.
extern "C" {
purah::ExitHit purah_exit_hits[purah::book::kFunctionCount > 0 ? purah::book::kFunctionCount : 1];
uint64_t purah_edge_targets[2 * (purah::book::kPatchCount > 0 ? purah::book::kPatchCount : 1)];
}

// Where a hook-mode exit ends up (book_exits.hpp's stubs branch to purah_exit_common, which tail-calls this with the hook's register file and the exit's id).
extern "C" __attribute__((used)) void purah_exit_dispatch(void* context, uint32_t id) {
    (void)context;
    if (!purah::g_exitsActive || id >= purah::book::kExitCount) return;
    purah::ExitHit& hit = purah::purah_exit_hits[purah::book::kExits[id].func];
    hit.id = static_cast<uint16_t>(id);
    hit.thread = purah::host::ThreadId();
}
