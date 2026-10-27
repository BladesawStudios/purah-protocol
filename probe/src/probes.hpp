// The probe table and the generic hooks every book row shares.
//
// A probe is a row of the symbol book. Its hook is installed the first time a configuration arms it and stays
// (hooks are install-once); "off" is a mode, not an uninstall. A function hook takes twelve integer arguments - eight in
// registers and four from the caller's stack - and passes all twelve on, so a function with up to twelve integer
// arguments runs unchanged; a call site gets two inline hooks, one at the call (arguments) and one on the next
// instruction (the result in x0). The code is built general-regs-only so it never touches the floating-point
// argument registers.
#pragma once

#include <utility>

#include "book_stubs.hpp"
#include "diagnostics.hpp"
#include "entry.hpp"
#include "stops.hpp"

#pragma GCC push_options
#pragma GCC target("general-regs-only")

namespace purah {

constexpr uint32_t kSubjectMax = 48;

struct Regs {
    uint64_t x[31];
};

struct ProbeState {
    volatile proto::ProbeMode mode = proto::ProbeMode::Off;
    uint8_t flags = 0;
    uint8_t depth = 0;
    uint8_t subjectLength = 0;
    uint16_t rate = 0;
    uint32_t windowCount = 0;
    uint32_t stepOutThread = 0;  // a call-site probe: the thread to stop at the matching return
    uint64_t windowStart = 0;
    uint64_t forceValue = 0;
    volatile uintptr_t orig = 0;  // function probes: the trampoline into the game; 0 until installed
    volatile bool installed = false;
    bool refused = false;
    char subject[kSubjectMax] = {};
};

using SiteFn = void (*)(Regs*);

inline ProbeState g_probes[book::kCount];
inline SiteFn g_siteHits[book::kCount];
inline SiteFn g_siteReturns[book::kCount];

// What one hit decided: whether it was recorded, and what the thread was told to do.
struct Pass {
    bool active = false;
    bool force = false;
    bool stepOut = false;
    uint64_t forced = 0;
};

inline void Disarm(uint32_t id) {
    char text[64];
    TextBuf(text, sizeof(text)).Add("probe ").AddValue(id).Add(" disarmed: over its rate limit");
    g_probes[id].mode = proto::ProbeMode::Off;
    EmitLog(1, text);
}

// True when the probe may fire now; disarms it (and says so) when it exceeds its per-second limit.
inline bool RateAllows(uint32_t id, ProbeState& s) {
    if (s.rate == 0) return true;
    const uint64_t now = host::Tick();
    if (now - s.windowStart >= host::TickFrequency()) { s.windowStart = now; s.windowCount = 0; }
    if (++s.windowCount <= s.rate) return true;
    Disarm(id);
    return false;
}

inline void EmitHit(uint32_t id, const ProbeState& s, const uint64_t* args, uint64_t caller, uint64_t hitId, const SubjectName* name) {
    EventFrame f(proto::MessageType::ProbeHit);
    proto::ProbeHit hit;
    hit.probeId = id;
    hit.threadId = host::ThreadId();
    hit.tick = host::Tick();
    hit.caller = (s.flags & proto::kCaptureCaller) ? caller : 0;
    hit.hitId = hitId;
    hit.argc = (s.flags & proto::kCaptureArgs) ? proto::kMaxArgs : 0;
    for (uint8_t i = 0; i < hit.argc; ++i) hit.args[i] = args[i];
    if (name) hit.subject = {name->text, name->length};
    Write(f.w(), hit);
    f.Send();
}

inline void EmitReturn(uint32_t id, uint64_t value, bool failure, uint64_t hitId) {
    EventFrame f(proto::MessageType::ProbeReturn);
    Write(f.w(), proto::ProbeReturn{id, host::ThreadId(), host::Tick(), value, failure ? uint8_t(1) : uint8_t(0), hitId});
    f.Send();
}

// Decides what a hit does: filters by subject and rate, records it, and for Break mode stops the thread until the
// client answers.
inline void Before(uint32_t id, const uint64_t* args, uint64_t caller, Pass* pass) {
    ProbeState& s = g_probes[id];
    const proto::ProbeMode mode = s.mode;
    if (mode == proto::ProbeMode::Off || !g_clientConnected) return;

    SubjectName name;
    bool known = false;
    if (s.subjectLength > 0 || (s.flags & proto::kCaptureSubject))
        known = Resolve(book::kRows[id].resolver, args, &name) || CurrentScope(&name);
    if (s.subjectLength > 0 && !(known && Contains(name, s.subject, s.subjectLength))) return;
    if (!RateAllows(id, s)) return;

    const uint64_t hitId = mode == proto::ProbeMode::Break ? BeginStop() : 0;
    EmitHit(id, s, args, caller, hitId, known ? &name : nullptr);
    pass->active = true;
    if (hitId) {
        uint64_t value = 0;
        const StopAction action = WaitForStop(hitId, &value);
        pass->force = action == StopAction::ForceReturn;
        pass->forced = value;
        pass->stepOut = action == StopAction::StepOut;
    }
    if (mode == proto::ProbeMode::ForceReturn) { pass->force = true; pass->forced = s.forceValue; }
}

// Records the return, stops again at it if the client stepped out, and lets the client replace the value.
inline void After(uint32_t id, uint64_t* value, const Pass& pass) {
    if (!pass.active || !g_clientConnected) return;
    const ProbeState& s = g_probes[id];
    const bool failure = book::kRows[id].failZero && static_cast<uint32_t>(*value) == 0;
    const uint64_t hitId = pass.stepOut ? BeginStop() : 0;
    if ((s.flags & proto::kCaptureReturn) || hitId) EmitReturn(id, *value, failure, hitId);
    if (!hitId) return;
    uint64_t forced = 0;
    if (WaitForStop(hitId, &forced) == StopAction::ForceReturn) *value = forced;
}

// What a function hook does. purah_common (entry.hpp) saved the game's x0..x8 and stack arguments in `f` and calls this; purah_call
// runs the original function with them. The return value goes back to the game in x0 (and f->r1 in x1).
inline uint64_t DispatchHook(uint32_t id, Frame* f) {
    ProbeState& s = g_probes[id];
    while (!s.orig) {}
    const book::Row& row = book::kRows[id];
    const uint64_t* args = f->x;
    if (row.kind == book::Kind::Notice) {
        purah_call(s.orig, f);
        const bool send = s.mode != proto::ProbeMode::Off;
        if ((send || g_watch.active) && g_clientConnected) EmitNotice(args[0], send);
        return f->r0;
    }
    if (row.kind == book::Kind::LinkError) {
        const bool send = s.mode != proto::ProbeMode::Off;
        if ((send || g_watch.active) && g_clientConnected) EmitLinkError(args, send);
        purah_call(s.orig, f);
        return f->r0;
    }

    bool scoped = false;
    if (row.scope) {
        SubjectName own;
        if (Resolve(row.resolver, args, &own)) { PushScope(own); scoped = true; }
    }
    int watched = -1;
    if (row.step != book::kNoStep) watched = WatchEnter(id, args);
    Pass pass;
    Before(id, args, CallerReturnAddress(f), &pass);
    uint64_t r;
    if (pass.force) {
        r = pass.forced;
        f->r1 = 0;
    } else {
        purah_call(s.orig, f);
        r = f->r0;
    }
    After(id, &r, pass);
    if (watched >= 0) {
        // A function that returns its result through memory (the document loaders: x8 is the address of the result) is judged by what it wrote there.
        uint64_t seen = r;
        if (book::kSteps[watched].sret) seen = Readable(f->x8, 8) ? *reinterpret_cast<const uint64_t*>(f->x8) : 0;
        WatchExit(id, watched, &seen);
    }
    if (scoped) PopScope();
    return r;
}

// The hook at a call site, before the call: the callee's arguments are in x0..x7.
template <uint32_t N>
__attribute__((noinline)) void SiteHit(Regs* regs) {
    constexpr book::Row row = book::kRows[N];
    if constexpr (row.step != book::kNoStep) {
        const int watched = WatchEnter(N, regs->x);
        if (watched >= 0 && !row.noReturn) g_watch.stepThread[watched] = host::ThreadId();
    }
    Pass pass;
    Before(N, regs->x, 0, &pass);
    if (pass.stepOut) g_probes[N].stepOutThread = host::ThreadId();
}

// The hook on the instruction after the call: the callee's result is in x0.
template <uint32_t N>
__attribute__((noinline)) void SiteReturn(Regs* regs) {
    constexpr book::Row row = book::kRows[N];
    if constexpr (row.step != book::kNoStep) {
        if (g_watch.stepThread[row.step] == host::ThreadId()) {
            g_watch.stepThread[row.step] = 0;
            WatchExit(N, row.step, &regs->x[0]);
        }
    }
    ProbeState& s = g_probes[N];
    if (s.mode == proto::ProbeMode::Off || !g_clientConnected) return;
    Pass pass;
    pass.active = true;
    pass.stepOut = s.stepOutThread == host::ThreadId();
    if (pass.stepOut) s.stepOutThread = 0;
    if (!(s.flags & proto::kCaptureReturn) && !pass.stepOut) return;
    SubjectName scope;
    if (s.subjectLength > 0 && !(CurrentScope(&scope) && Contains(scope, s.subject, s.subjectLength))) return;
    After(N, &regs->x[0], pass);
}

template <uint32_t I>
inline void FillOne() {
    if constexpr (book::kRows[I].kind == book::Kind::Site) {
        g_siteHits[I] = &SiteHit<I>;
        g_siteReturns[I] = &SiteReturn<I>;
    }
}

template <uint32_t... I>
inline void FillCallbacks(std::integer_sequence<uint32_t, I...>) {
    (FillOne<I>(), ...);
}

// Installs the hook(s) of a book row if they are not installed yet; the result is what a configuration reports.
inline proto::ProbeResult Install(uint32_t id) {
    ProbeState& s = g_probes[id];
    const book::Row& row = book::kRows[id];
    if (s.installed) return proto::ProbeResult::Applied;
    if (s.refused) return proto::ProbeResult::RefusedPattern;
    const uintptr_t target = host::S::ResolveTarget(row.offset, 0);
    bool ok = target != 0;
    if (ok && row.kind == book::Kind::Site) {
        ok = host::S::InstallInlineHook(target, reinterpret_cast<uintptr_t>(g_siteHits[id])) != 0;
        if (ok && !row.noReturn) ok = host::S::InstallInlineHook(target + 4, reinterpret_cast<uintptr_t>(g_siteReturns[id])) != 0;
    } else if (ok) {
        const uintptr_t orig = host::S::InstallHook(target, reinterpret_cast<uintptr_t>(book::kStubs[id]));
        ok = orig != 0;
        s.orig = orig;
    }
    if (!ok) { s.refused = true; return proto::ProbeResult::RefusedPattern; }
    s.installed = true;
    return proto::ProbeResult::Applied;
}

}  // namespace purah

extern "C" __attribute__((used)) uint64_t purah_dispatch(uint32_t id, purah::Frame* frame) { return purah::DispatchHook(id, frame); }

#pragma GCC pop_options
