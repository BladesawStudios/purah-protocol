// Starting and stopping a watch: placing the hooks the catalog's steps need, and answering the client.
#pragma once

#include "probes.hpp"

namespace purah {

struct WatchResult {
    proto::WatchStatus status;
    uint16_t armed;
    uint16_t refused;
    char note[160];
    uint16_t noteLength;
};

// Replaces a branch with a jump to its stub. The stub makes the branch's own decision, records the exit on the failing outcome, and jumps on to
// the branch's target or to the next instruction, whose addresses are filled in here. The write is checked: the branch's bytes must still be the
// ones the export saw.
inline bool PatchBranch(const book::Exit& e) {
    const uintptr_t at = host::S::ResolveTarget(e.offset, 0);
    if (!at) return false;
    const uint64_t base = g_imageBase;
    purah_edge_targets[2 * e.slot] = base + e.target;
    purah_edge_targets[2 * e.slot + 1] = base + e.offset + 4;
    const int64_t delta = static_cast<int64_t>(reinterpret_cast<uintptr_t>(book::kEdgeStubs[e.slot])) - static_cast<int64_t>(at);
    if (delta > 0x7FFFFFC || delta < -0x8000000) return false;  // a b reaches 128 MB
    const uint32_t branch = 0x14000000u | (static_cast<uint32_t>(delta >> 2) & 0x3FFFFFFu);
    const uint32_t expected = e.word;
    return host::S::Write(at, &branch, 4, &expected, 4) != 0;
}

// Instruments the exits of the mapped functions, once each: an inline hook where a block falls into a failure block, a patched branch where a branch
// leads there.
inline void InstallExits() {
    for (uint32_t i = 0; i < book::kExitCount; ++i) {
        if (g_exitInstalled[i]) continue;
        const book::Exit& e = book::kExits[i];
        if (e.mode == 1) {
            if (book::kEdgeStubs[e.slot] && PatchBranch(e)) g_exitInstalled[i] = true;
        } else if (book::kExitStubs[e.slot]) {
            const uintptr_t target = host::S::ResolveTarget(e.offset, 0);
            if (target && host::S::InstallInlineHook(target, reinterpret_cast<uintptr_t>(book::kExitStubs[e.slot]))) g_exitInstalled[i] = true;
        }
    }
}

// Hooks every step of the catalog (and the functions that scope an actor's initialisation) and starts following `name`.
inline WatchResult StartWatch(const char* name, uint16_t length) {
    WatchResult result = {proto::WatchStatus::Watching, 0, 0, {}, 0};
    if (length == 0 || length >= kNameMax) {
        result.status = proto::WatchStatus::RefusedName;
        TextBuf note(result.note, sizeof(result.note));
        note.Add("The actor name must be 1 to 47 characters.");
        result.noteLength = static_cast<uint16_t>(note.length());
        return result;
    }
    g_watch.active = false;
    {
        host::LockGuard guard(g_watch.lock);
        for (uint16_t i = 0; i < length; ++i) g_watch.name[i] = name[i];
        g_watch.nameLength = static_cast<uint8_t>(length);
        g_seenCount = 0;
        g_watch.requested = g_watch.open = false;
        g_watch.failCount = g_watch.warningCount = g_watch.noticeCount = 0;
        for (uint32_t i = 0; i < book::kStepCount; ++i) g_watch.stepThread[i] = 0;
    }
    for (uint32_t i = 0; i < book::kStepCount; ++i) {
        const proto::ProbeResult placed = Install(book::kSteps[i].row);
        if (placed == proto::ProbeResult::Applied) ++result.armed;
        else ++result.refused;
    }
    // The scope functions, and the game's two diagnostic channels, whose reports become the verdict's evidence.
    for (uint32_t i = 0; i < book::kCount; ++i)
        if (book::kRows[i].scope || book::kRows[i].kind == book::Kind::Notice || book::kRows[i].kind == book::Kind::LinkError) Install(i);

    if (result.refused > 0) {
        result.status = proto::WatchStatus::Partial;
        TextBuf note(result.note, sizeof(result.note));
        note.Add("Some steps could not be hooked in this game build; the ladder will skip them.");
        result.noteLength = static_cast<uint16_t>(note.length());
    }
    InstallExits();
    g_exitsActive = true;
    g_watch.active = true;
    return result;
}

inline void StopWatch() {
    g_watch.active = false;
    g_exitsActive = false;
}

}  // namespace purah
