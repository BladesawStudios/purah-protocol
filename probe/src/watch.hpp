// Following one actor through its initialisation, and saying why it failed.
//
// The client names an actor (WatchActor). Every step in the catalog (data/<game>/<version>/steps.psv) is then tracked for calls that belong
// to that actor: a call belongs to it if its own `this` is the actor or one of its components, or if the calling thread is inside the
// actor's initialisation (subject.hpp). Each step is reported as it is entered and left (ActorStep), judged by its rule: a zero return
// is a failure, or any code but 1 for the initialisation itself. When the initialisation (BaseProc::initialize) returns, the verdict is
// built: the first step that failed is the cause - nested steps leave before the step that contains them, so the first failure to leave
// is the deepest one - everything that failed after it is fallout, and the game's own diagnostics raised during that initialisation are
// attached. A request that never leads to an initialisation within kNeverStartedMs ends as a verdict of its own.
#pragma once

#include "book_data.hpp"
#include "events.hpp"
#include "exits.hpp"
#include "subject.hpp"

namespace purah {

constexpr uint32_t kFailMax = 8;
constexpr uint32_t kNoticeMax = 6;
constexpr uint32_t kNoticeLength = 240;
constexpr uint32_t kLineMax = 12;
constexpr uint32_t kLineLength = 1000;
constexpr uint32_t kNeverStartedMs = 20000;

constexpr uint32_t kDetailMax = 120;   // a component name or a document path
constexpr uint32_t kDetailDepth = 6;

// BaseProc::finishInitialization(proc, code, arg) is called with the final code whatever happened; the init function itself only says true or false.
constexpr uint32_t kFinishInitialization = 0x7FD97C;

struct StepFail {
    uint16_t step;
    uint16_t count;  // how many times this same step failed with this same detail
    uint64_t value;
    char detail[kDetailMax];
    uint8_t detailLength;
};

struct WatchState {
    host::SpinLock lock;
    volatile bool active = false;
    char name[kNameMax] = {};
    uint8_t nameLength = 0;
    bool requested = false;
    uint64_t requestedTick = 0;
    bool open = false;  // an initialisation of the watched actor is in progress
    uint32_t stepsSeen = 0;
    StepFail fails[kFailMax];
    uint8_t failCount = 0;
    uint64_t initCode = 0;     // the code finishInitialization was called with
    bool codeKnown = false;
    uint16_t warnings[kFailMax] = {};
    uint8_t warningCount = 0;
    char notices[kNoticeMax][kNoticeLength] = {};
    uint16_t noticeLength[kNoticeMax] = {};
    uint8_t noticeCount = 0;
    // What the steps now open are about (a component, a document path), innermost last, kept from a step's start to its end.
    char stack[kDetailDepth][kDetailMax] = {};
    uint8_t stackLength[kDetailDepth] = {};
    uint8_t stackDepth = 0;
    volatile uint32_t stepThread[book::kStepCount] = {};  // thread that has a call-site step open
};

inline WatchState g_watch;
inline char g_lines[kLineMax][kLineLength];
inline uint8_t g_verdictFrame[20480];

constexpr const char* kUnreportedChecklist =
    "No step inside it reported a failure, so the failure is in a stage the game does not report separately. Check, in order: the Actor/<name> document exists at that exact path and loads; "
    "the actor has an ActorInfo row; every class in its Components list is one the game has; the GameParameter table's root document exists; the AI document exists and names at least one "
    "controller whose .ainb exists; the physics files it names exist.";

inline const char* CodeText(uint32_t code) {
    switch (code) {
    case 0: return "code 0: the prepare stage (slot +0x48) returned false, before anything was built.";
    case 2: return "code 2: a resource the initialisation had to wait for was not ready (a resource path problem).";
    case 5: return "code 5: the actor's instance heap could not be created. Its reserved heap size is too small for what it builds, or memory is short.";
    case 6: return "code 6: the setup stage (slot +0x60) returned false. For an actor this stage builds its components and loads its parameters, so this is the normal code for any component or parameter failure; the failed step above is the reason.";
    default: return "an initialisation code the game has not been mapped to a meaning for.";
    }
}

// The class of a component object, from its vtable: the game's component classes are listed in the book.
inline uint8_t ComponentName(uint64_t object, char* out) {
    if (!Readable(object, 8)) return 0;
    const uint64_t vptr = *reinterpret_cast<const uint64_t*>(object);
    if (vptr < g_imageBase) return 0;
    const uint64_t offset = vptr - g_imageBase;
    for (uint32_t i = 0; i < book::kVtableCount; ++i) {
        const uint64_t at = book::kVtables[i].offset;
        if (offset != at && offset != at + 0x10 && offset + 0x10 != at) continue;
        uint8_t n = 0;
        for (const char* p = book::kVtables[i].name; *p && uint32_t(n) + 1 < kNameMax; ++p) out[n++] = *p;
        return n;
    }
    return 0;
}

inline uint8_t ReadString(uint64_t p, char* out) { return static_cast<uint8_t>(ReadCString(p, out, kDetailMax - 1)); }

// A step named from its input (a component or a path it was given) keeps that name from its start to its end.
inline bool NamedFromInput(book::Named named) { return named == book::Named::Arg0 || named == book::Named::Path1; }

// What a step is about, from what the call was given: a component (its vtable, in the first argument) or a document (the second
// argument points at a pointer to its path).
inline uint8_t EnterDetail(const book::Step& step, const uint64_t* args, char* out) {
    if (step.named == book::Named::Arg0) return ComponentName(args[0], out);
    if (step.named == book::Named::Path1) return Readable(args[1], 8) ? ReadString(*reinterpret_cast<const uint64_t*>(args[1]), out) : uint8_t(0);
    return 0;
}

// ...and from what it returned: a component created, or a pointer to the string pointer of a name.
inline uint8_t ExitDetail(const book::Step& step, uint64_t value, char* out) {
    if (step.named == book::Named::Result && value) return ComponentName(value, out);
    if (step.named == book::Named::ResultStr && value && Readable(value, 8)) return ReadString(*reinterpret_cast<const uint64_t*>(value), out);
    return 0;
}

// Which exit a failing function took, as an event for the client; the client knows what each exit means.
inline void EmitExit(uint32_t step, uint16_t exit, const char* detail, uint8_t detailLength) {
    const book::Exit& e = book::kExits[exit];
    EventFrame f(proto::MessageType::ActorExit);
    Write(f.w(), proto::ActorExit{step, e.function, e.ordinal, e.count, {detail, detailLength}});
    f.Send();
}

// The exit-table function for a step: the component's stage function for a stage call site, the step's own function otherwise.
inline int ExitFunctionFor(const book::Step& step, uint32_t row, const char* detail, uint8_t detailLength) {
    if (step.stage) return ComponentStageFunction(detail, detailLength, step.stage);
    return FunctionIndex(book::kRows[row].offset);
}

inline void EmitStep(uint32_t step, uint8_t phase, proto::StepOutcome outcome, uint64_t value, const char* detail, uint8_t detailLength) {
    EventFrame f(proto::MessageType::ActorStep);
    Write(f.w(), proto::ActorStep{step, phase, outcome, host::ThreadId(), host::Tick(), value, {detail, detailLength}});
    f.Send();
}

inline bool WatchMatches(const book::Row& row, const uint64_t* args) {
    SubjectName name;
    const bool known = Resolve(row.resolver, args, &name) || CurrentScope(&name);
    return known && Contains(name, g_watch.name, g_watch.nameLength);
}

// What happened before the initialisation proper (the request, the ActorInfo lookup) is part of the same story, so an
// instance starts without forgetting it; the verdict is what clears the slate.
inline void BeginInstance() {
    g_watch.open = true;
    g_watch.requested = false;
    g_watch.stackDepth = 0;
}

inline void ClearInstance() {
    g_watch.codeKnown = false;
    g_watch.failCount = g_watch.warningCount = g_watch.noticeCount = 0;
    g_watch.stepsSeen = 0;
    g_watch.stackDepth = 0;
}

// Every distinct process name the game initialises while a watch is on is reported once (a Log event starting "seen: ", and the host log
// for the first few), so a name that never matches can be seen against what the game actually calls things.
constexpr uint32_t kSeenMax = 96;
inline uint32_t g_seenHashes[kSeenMax];
inline uint32_t g_seenCount = 0;

inline void NoteSeen(const SubjectName* name) {
    uint32_t hash = 0x811C9DC5;
    if (name) for (uint8_t i = 0; i < name->length; ++i) hash = (hash ^ static_cast<uint8_t>(name->text[i])) * 0x01000193;
    for (uint32_t i = 0; i < g_seenCount; ++i)
        if (g_seenHashes[i] == hash) return;
    if (g_seenCount >= kSeenMax) return;
    g_seenHashes[g_seenCount++] = hash;
    char text[kNameMax + 16];
    TextBuf line(text, sizeof(text));
    line.Add("seen: ");
    if (name) line.AddN(name->text, name->length); else line.Add("(name not readable)");
    EmitLog(0, text);
    if (g_seenCount <= 40) PURAH_LOG("purah: %s", text);
}

// A step began. Returns its catalog index when the call belongs to the watched actor, else -1.
inline int WatchEnter(uint32_t row, const uint64_t* args) {
    if (!g_watch.active || !g_clientConnected) return -1;
    const uint16_t index = book::kRows[row].step;
    if (index == book::kNoStep) return -1;
    if (book::kSteps[index].root) {
        SubjectName seen;
        NoteSeen(Resolve(book::kRows[row].resolver, args, &seen) ? &seen : nullptr);
    }
    if (!WatchMatches(book::kRows[row], args)) return -1;
    const book::Step& step = book::kSteps[index];

    host::LockGuard guard(g_watch.lock);
    if (step.root) BeginInstance();
    if (book::kRows[row].offset == kFinishInitialization) { g_watch.initCode = args[1]; g_watch.codeKnown = true; }
    char detail[kDetailMax];
    const uint8_t detailLength = EnterDetail(step, args, detail);
    const bool hasEnd = !(book::kRows[row].kind == book::Kind::Site && book::kRows[row].noReturn);
    const bool pushes = NamedFromInput(step.named) && hasEnd;
    if (pushes && g_watch.stackDepth < kDetailDepth) {
        for (uint8_t i = 0; i < detailLength; ++i) g_watch.stack[g_watch.stackDepth][i] = detail[i];
        g_watch.stackLength[g_watch.stackDepth++] = detailLength;
    }
    ++g_watch.stepsSeen;
    ClearExit(ExitFunctionFor(step, row, detail, detailLength));
    EmitStep(index, 0, proto::StepOutcome::None, 0, detail, detailLength);
    return index;
}

inline proto::StepOutcome Judge(const book::Step& step, uint64_t value) {
    const uint32_t low = static_cast<uint32_t>(value);
    switch (step.rule) {
    case book::Rule::Zero: return low == 0 ? proto::StepOutcome::Failed : proto::StepOutcome::Ok;
    case book::Rule::Code: return low != 1 ? proto::StepOutcome::Failed : proto::StepOutcome::Ok;
    case book::Rule::Warn: return low == 0 ? proto::StepOutcome::Warning : proto::StepOutcome::Ok;
    default: return proto::StepOutcome::Ok;
    }
}

inline void Finish(proto::VerdictOutcome outcome, uint32_t failedStep, uint64_t code, const char* summary, uint32_t lines) {
    proto::Writer w(g_verdictFrame, sizeof(g_verdictFrame));
    w.BeginFrame(proto::MessageType::ActorVerdict, proto::kEvent, __atomic_add_fetch(&g_eventSeq, 1, __ATOMIC_RELAXED));
    uint16_t summaryLength = 0;
    while (summary[summaryLength]) ++summaryLength;
    proto::BeginVerdict(w, outcome, failedStep, code, {summary, summaryLength}, static_cast<uint16_t>(lines));
    for (uint32_t i = 0; i < lines; ++i) w.Str(g_lines[i]);
    w.EndFrame();
    if (w.ok() && g_clientConnected) g_ring.Push(g_verdictFrame, w.length());
}

inline void AddNotices(uint32_t* lines) {
    for (uint32_t i = 0; i < g_watch.noticeCount && *lines < kLineMax; ++i) {
        TextBuf line(g_lines[(*lines)++], kLineLength);
        line.Add("The game reported: ").AddN(g_watch.notices[i], g_watch.noticeLength[i]);
    }
}

// What the decompiles say about the component named `name`, as a verdict line; nothing if the class has no entry.
inline void AddComponentReason(uint32_t* lines, const char* name, uint8_t length) {
    for (uint32_t i = 0; i < book::kReasonCount && *lines < kLineMax; ++i) {
        if (!SameText(name, length, book::kReasons[i].name)) continue;
        TextBuf(g_lines[(*lines)++], kLineLength).Add("About the component - ").Add(book::kReasons[i].text);
        return;
    }
}

inline void AddFailure(uint32_t* lines, const StepFail& f, const char* lead) {
    const book::Step& s = book::kSteps[f.step];
    TextBuf line(g_lines[(*lines)++], kLineLength);
    line.Add(lead).Add(book::kPhases[s.phase]).Add(": ").Add(s.label);
    if (f.detailLength) line.Add(" - ").AddN(f.detail, f.detailLength);
    line.Add(" (returned ").AddValue(f.value).Add(")");
    if (f.count > 1) line.Add(" x").AddValue(f.count);
}

// The initialisation ended with `code`. Builds and sends the verdict.
inline void ConcludeInstance(uint64_t code) {
    uint32_t lines = 0;
    const bool ok = static_cast<uint32_t>(code) == 1;
    char summary[200];
    TextBuf head(summary, sizeof(summary));
    head.AddN(g_watch.name, g_watch.nameLength);

    if (ok) {
        head.Add(" initialised: every tracked step passed.");
        TextBuf(g_lines[lines++], kLineLength).AddValue(g_watch.stepsSeen).Add(" steps ran and none failed.");
        for (uint32_t i = 0; i < g_watch.warningCount && lines < kLineMax; ++i)
            TextBuf(g_lines[lines++], kLineLength).Add("Warning - ").Add(book::kSteps[g_watch.warnings[i]].label).Add(": ").Add(book::kSteps[g_watch.warnings[i]].meaning);
        AddNotices(&lines);
        TextBuf(g_lines[lines++], kLineLength).Add("If it still misbehaves, the game says nothing about these: a missing GameParameter entry file (that entry silently reads as defaults), a misspelled or mistyped AI node input (the node runs with zero), a texture that is not found (the slot stays empty), and a malformed bfres (read wrongly, never rejected).");
        TextBuf(g_lines[lines++], kLineLength).Add("This watch ends when the actor is initialised. Whether it is then calculated and drawn (time-of-day and weather masks, distance, culling) is a separate question; use the Placement and Visibility probes.");
        Finish(proto::VerdictOutcome::Initialised, proto::kNoStep, code, summary, lines);
    } else if (g_watch.failCount > 0) {
        // The cause is the first step to fail that is not a container (a container fails because something inside it did); if only
        // containers failed, the innermost one is named and the checklist follows.
        uint32_t cause = 0;
        bool leaf = false;
        for (uint32_t i = 0; i < g_watch.failCount && !leaf; ++i)
            if (!book::kSteps[g_watch.fails[i].step].container) { cause = i; leaf = true; }
        const StepFail& first = g_watch.fails[cause];
        const book::Step& step = book::kSteps[first.step];
        head.Add(" failed to initialise: ").Add(step.label).Add(" failed.");
        TextBuf(g_lines[lines++], kLineLength).Add("Cause: ").Add(step.meaning);
        AddFailure(&lines, first, "Where: ");
        if (first.detailLength) AddComponentReason(&lines, first.detail, first.detailLength);
        TextBuf(g_lines[lines++], kLineLength).Add("Initialisation ended with ").Add(CodeText(static_cast<uint32_t>(code)));
        if (!leaf) TextBuf(g_lines[lines++], kLineLength).Add(kUnreportedChecklist);
        for (uint32_t i = 0; i < g_watch.failCount && lines < kLineMax - 2; ++i)
            if (i != cause) AddFailure(&lines, g_watch.fails[i], i < cause ? "Earlier failure - " : "Then also failed - ");
        AddNotices(&lines);
        Finish(proto::VerdictOutcome::Failed, first.step, code, summary, lines);
    } else {
        head.Add(" failed to initialise, but no tracked step reported a failure.");
        TextBuf(g_lines[lines++], kLineLength).Add("Initialisation ended with ").Add(CodeText(static_cast<uint32_t>(code)));
        TextBuf(g_lines[lines++], kLineLength).Add(kUnreportedChecklist);
        AddNotices(&lines);
        Finish(proto::VerdictOutcome::Failed, proto::kNoStep, code, summary, lines);
    }
    g_watch.open = false;
    ClearInstance();
}

// A step ended with `*value`. Judges it, reports it, and when it is the end of the initialisation builds the verdict.
inline void WatchExit(uint32_t row, int index, uint64_t* value) {
    const book::Step& step = book::kSteps[index];
    const proto::StepOutcome outcome = Judge(step, *value);

    host::LockGuard guard(g_watch.lock);
    char detail[kDetailMax];
    uint8_t detailLength = 0;
    const bool popped = NamedFromInput(step.named);
    if (popped) {
        if (g_watch.stackDepth > 0) {
            --g_watch.stackDepth;
            detailLength = g_watch.stackLength[g_watch.stackDepth];
            for (uint8_t i = 0; i < detailLength; ++i) detail[i] = g_watch.stack[g_watch.stackDepth][i];
        }
    } else {
        detailLength = ExitDetail(step, *value, detail);
    }
    const uint16_t exit = outcome == proto::StepOutcome::Failed ? TakeExit(ExitFunctionFor(step, row, detail, detailLength)) : kNoExit;
    if (outcome == proto::StepOutcome::Failed && !step.root) {
        // The same step failing with the same detail again is one failure seen more than once, not a new one.
        StepFail* same = nullptr;
        for (uint32_t i = 0; i < g_watch.failCount && !same; ++i) {
            StepFail& f = g_watch.fails[i];
            if (f.step != index || f.detailLength != detailLength) continue;
            uint8_t k = 0;
            while (k < detailLength && f.detail[k] == detail[k]) ++k;
            if (k == detailLength) same = &f;
        }
        if (same) {
            ++same->count;
        } else if (g_watch.failCount < kFailMax) {
            StepFail& f = g_watch.fails[g_watch.failCount++];
            f.step = static_cast<uint16_t>(index);
            f.count = 1;
            f.value = *value;
            f.detailLength = detailLength;
            for (uint8_t i = 0; i < detailLength; ++i) f.detail[i] = detail[i];
        }
    }
    if (outcome == proto::StepOutcome::Warning && g_watch.warningCount < kFailMax) g_watch.warnings[g_watch.warningCount++] = static_cast<uint16_t>(index);
    if (exit != kNoExit) EmitExit(static_cast<uint32_t>(index), exit, detail, detailLength);
    EmitStep(index, 1, outcome, *value, detail, detailLength);

    if (step.request) {
        if (outcome == proto::StepOutcome::Failed) {
            TextBuf summary(g_lines[0], kLineLength);
            summary.Add("Cause: ").Add(step.meaning);
            char text[200];
            TextBuf(text, sizeof(text)).AddN(g_watch.name, g_watch.nameLength).Add(" was never created: the request was refused.");
            Finish(proto::VerdictOutcome::NeverStarted, static_cast<uint32_t>(index), *value, text, 1);
            ClearInstance();
        } else {
            g_watch.requested = true;
            g_watch.requestedTick = host::Tick();
        }
    }
    if (step.root) ConcludeInstance(g_watch.codeKnown ? g_watch.initCode : *value);
}

// Called on every tick: a request that no initialisation ever followed is its own verdict.
inline void WatchTick() {
    if (!g_watch.active || !g_clientConnected || !g_watch.requested || g_watch.open) return;
    if (host::Tick() - g_watch.requestedTick < host::TickFrequency() * kNeverStartedMs / 1000) return;
    host::LockGuard guard(g_watch.lock);
    g_watch.requested = false;
    TextBuf(g_lines[0], kLineLength).Add("Cause: the game accepted the creation request but never began initialising the actor.");
    TextBuf(g_lines[1], kLineLength).Add("The request is dropped before initialisation if the actor's factory returns null (status 3) or the process has no unit (status 4), if something deletes it at once (a removal with reason 1 right after creation is an initialisation failure), or if it is never judged to exist. Check that the name has an ActorInfo row and an Actor/<name> file in the pack, that its class is one the game can construct, and that nothing kills it as it is created.");
    TextBuf(g_lines[2], kLineLength).Add("Probes that would show it: the BaseProc group (createProc, initializeProc, requestDelete) and the Create group.");
    char text[200];
    TextBuf(text, sizeof(text)).AddN(g_watch.name, g_watch.nameLength).Add(" was requested but never started initialising.");
    Finish(proto::VerdictOutcome::NeverStarted, proto::kNoStep, 0, text, 3);
    ClearInstance();
}

// The game said something (a parameter notice or an effects error) on this thread: if the thread is inside the watched actor's
// initialisation, it is evidence.
inline void WatchNotice(const char* file, uint16_t fileLength, const char* message, uint16_t messageLength, const char* path, uint16_t pathLength) {
    if (!g_watch.active) return;
    SubjectName scope;
    if (!CurrentScope(&scope) || !Contains(scope, g_watch.name, g_watch.nameLength)) return;
    host::LockGuard guard(g_watch.lock);
    if (g_watch.noticeCount >= kNoticeMax) return;
    TextBuf text(g_watch.notices[g_watch.noticeCount], kNoticeLength);
    text.AddN(file, fileLength).Add(": ").AddN(message, messageLength);
    if (pathLength) text.Add("  [").AddN(path, pathLength).Add("]");
    g_watch.noticeLength[g_watch.noticeCount++] = static_cast<uint16_t>(text.length());
}

}  // namespace purah
