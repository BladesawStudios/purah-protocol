// Which actor a call is about.
//
// A probe's subject filter ("only this actor") needs the actor behind each call. Three ways to find it, in order:
//   * the row's own resolver: the call's `this` is a BaseProc/ActorBase (name pointer at +0x18, length at +0x20), or
//     a component (its actor at +0x18), or the call takes a name (ActorMgr::requestCreateActor*, a char** in x1);
//   * the thread's scope: while a thread is inside BaseProc::initialize / ActorBase::initializeActor_ / initializeComponent
//     for an actor, every other probed call on that thread is about that actor (resources, parameters, physics and the
//     rest of the init chain run inside those calls);
//   * nothing: the call is about no known actor and a filter rejects it.
// Every dereference is preceded by a readable-bytes query, so a bad pointer costs a refusal, never a fault.
#pragma once

#include "book_data.hpp"
#include "events.hpp"

namespace purah {

constexpr uint32_t kNameMax = 48;
constexpr uint32_t kScopeThreads = 32;
constexpr uint32_t kScopeDepth = 4;

struct SubjectName {
    char text[kNameMax] = {};
    uint8_t length = 0;
};

// Copies a printable name of `length` bytes at `text` into `out`; false when it is not readable text.
inline bool CopyName(uint64_t text, uint32_t length, SubjectName* out) {
    if (length == 0 || length >= kNameMax || !Readable(text, length)) return false;
    const char* s = reinterpret_cast<const char*>(text);
    for (uint32_t i = 0; i < length; ++i) {
        if (!Printable(static_cast<uint8_t>(s[i]))) return false;
        out->text[i] = s[i];
    }
    out->length = static_cast<uint8_t>(length);
    return true;
}

// A zero-terminated string; names longer than kNameMax - 1 characters are cut to that. The room is asked of the host once, not per character.
inline bool CString(uint64_t text, SubjectName* out) {
    if (text < 0x10000) return false;
    const uint64_t room = host::S::ReadableBytes(text, kNameMax - 1);
    const char* s = reinterpret_cast<const char*>(text);
    uint32_t n = 0;
    while (n < room && s[n] != 0) ++n;
    return CopyName(text, n, out);
}

// A BaseProc (or anything derived: ActorBase, GameActor): a pointer to its name at +0x18. The length that sits beside it at +0x20 is NOT the
// name's length (it reads 3 or 4 for every name), so the name is read to its terminating zero.
inline bool ProcName(uint64_t proc, SubjectName* out) {
    if (!Readable(proc + 0x18, 8)) return false;
    return CString(*reinterpret_cast<const uint64_t*>(proc + 0x18), out);
}

inline bool Resolve(book::Resolver how, const uint64_t* args, SubjectName* out) {
    switch (how) {
    case book::Resolver::Proc: return ProcName(args[0], out);
    case book::Resolver::Component:
        return Readable(args[0] + 0x18, 8) && ProcName(*reinterpret_cast<const uint64_t*>(args[0] + 0x18), out);
    case book::Resolver::InfoName:
        return Readable(args[0] + 0x14, 8) && CString(args[0] + 0x14, out);
    case book::Resolver::NameArg:
        return Readable(args[1], 8) && CString(*reinterpret_cast<const uint64_t*>(args[1]), out);
    default: return false;
    }
}

// What each thread is currently inside. Slots are claimed by thread id and never released (a game has a few dozen
// threads); a stack per thread because an actor's init can nest (a component inside the actor).
struct ThreadScope {
    volatile uint32_t thread = 0;
    uint8_t depth = 0;
    SubjectName stack[kScopeDepth];
};

inline ThreadScope g_scopes[kScopeThreads];

inline ThreadScope* ScopeFor(uint32_t thread, bool create) {
    for (uint32_t i = 0; i < kScopeThreads; ++i) {
        const uint32_t idx = (thread + i) % kScopeThreads;
        uint32_t seen = g_scopes[idx].thread;
        if (seen == thread) return &g_scopes[idx];
        if (seen == 0 && create && __atomic_compare_exchange_n(&g_scopes[idx].thread, &seen, thread, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return &g_scopes[idx];
    }
    return nullptr;
}

inline void PushScope(const SubjectName& name) {
    ThreadScope* s = ScopeFor(host::ThreadId() | 1u << 31, true);
    if (!s) return;
    if (s->depth < kScopeDepth) s->stack[s->depth] = name;
    if (s->depth < 255) ++s->depth;
}

inline void PopScope() {
    ThreadScope* s = ScopeFor(host::ThreadId() | 1u << 31, false);
    if (s && s->depth > 0) --s->depth;
}

// The innermost subject of this thread, or false when it is inside none.
inline bool CurrentScope(SubjectName* out) {
    ThreadScope* s = ScopeFor(host::ThreadId() | 1u << 31, false);
    if (!s || s->depth == 0) return false;
    *out = s->stack[(s->depth > kScopeDepth ? kScopeDepth : s->depth) - 1];
    return true;
}

inline bool Contains(const SubjectName& name, const char* filter, uint8_t filterLength) {
    if (filterLength == 0) return true;
    for (uint32_t i = 0; i + filterLength <= name.length; ++i) {
        uint32_t k = 0;
        while (k < filterLength && name.text[i + k] == filter[k]) ++k;
        if (k == filterLength) return true;
    }
    return false;
}

}  // namespace purah
