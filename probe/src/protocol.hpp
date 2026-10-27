// purah-protocol wire protocol, version 1: the module's side.
//
// The specification is docs/protocol.md; Prism's mirror is its Prism.Debug project. This file is
// freestanding (no libc, no heap, no exceptions), so it builds as part of a .wxlm. It holds what the module
// needs: it decodes requests (Hello, Goodbye, Ping, SetConfig, Resume, StepOut, ForceReturn, ReadMem, Poke)
// and encodes responses and events. Every Reader/Writer call is bounds-checked and failure is sticky: check
// ok() once at the end rather than after every field.
#pragma once

#include <cstddef>
#include <cstdint>

namespace purah::proto {

constexpr uint16_t kPort = 54312;
constexpr uint16_t kVersion = 1;
constexpr uint32_t kHeaderSize = 12;
constexpr uint32_t kMaxPayload = 65536;
constexpr uint16_t kMaxString = 1024;
constexpr uint8_t kMaxArgs = 8;
constexpr uint16_t kMaxPokeBytes = 16;
constexpr uint32_t kMaxReadBytes = 4096;

enum class MessageType : uint16_t {
    Hello = 0x0001, Goodbye = 0x0002, Ping = 0x0003, Pong = 0x0004, Error = 0x00FF,
    GetConfig = 0x0010, Config = 0x0011, SetConfig = 0x0012, ConfigApplied = 0x0013,
    ListProbes = 0x0040, Probes = 0x0041,
    Resume = 0x0020, StepOut = 0x0021, ForceReturn = 0x0022,
    ReadMem = 0x0030, MemData = 0x0031, Poke = 0x0032, PokeResult = 0x0033,
    ProbeHit = 0x0100, ProbeReturn = 0x0101, Overflow = 0x0102, Log = 0x0103, Notice = 0x0104,
    WatchActor = 0x0050, WatchAck = 0x0051, ActorStep = 0x0105, ActorVerdict = 0x0106, ActorExit = 0x0107,
};

enum FrameFlags : uint16_t { kResponse = 1, kEvent = 2 };
enum class ProbeMode : uint8_t { Off = 0, Trace = 1, Break = 2, ForceReturn = 3 };
enum ProbeFlags : uint8_t { kCaptureArgs = 1, kCaptureReturn = 2, kCaptureCaller = 4, kCaptureSubject = 8 };
enum class ProbeResult : uint8_t {
    Applied = 0, RefusedPattern = 1, RefusedPoolFull = 2, RefusedNotInBuild = 3,
    RefusedUnknownProbe = 4, RefusedWriteDisabled = 5, RefusedBreakDisabled = 6, RefusedUnsupported = 7,
};
enum Capability : uint32_t { kCanWrite = 1, kCanBreak = 2 };

struct FrameHeader {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t seq;
};

// A string as it sits in a frame: bytes in the frame, not terminated.
struct StringView {
    const char* data;
    uint16_t length;
};

class Writer {
public:
    Writer(uint8_t* buffer, uint32_t capacity) : m_data(buffer), m_capacity(capacity) {}

    // Starts a frame; EndFrame patches its length. Nothing is written if the header does not fit.
    void BeginFrame(MessageType type, uint16_t flags, uint32_t seq) {
        m_frame = m_length;
        U32(0); U16(static_cast<uint16_t>(type)); U16(flags); U32(seq);
    }
    void EndFrame() {
        if (m_failed) return;
        const uint32_t payload = m_length - m_frame - kHeaderSize;
        if (payload > kMaxPayload) { m_failed = true; return; }
        Patch32(m_frame, payload);
    }

    void U8(uint8_t v) { Put(&v, 1); }
    void U16(uint16_t v) { uint8_t b[2] = {uint8_t(v), uint8_t(v >> 8)}; Put(b, 2); }
    void U32(uint32_t v) {
        uint8_t b[4] = {uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24)};
        Put(b, 4);
    }
    void U64(uint64_t v) { U32(uint32_t(v)); U32(uint32_t(v >> 32)); }
    void Bytes(const void* p, uint32_t n) { Put(static_cast<const uint8_t*>(p), n); }
    void Str(const char* text, uint16_t length) {
        if (length > kMaxString) { m_failed = true; return; }
        U16(length); Bytes(text, length);
    }
    void Str(const char* zeroTerminated) {
        uint16_t n = 0;
        while (zeroTerminated[n] != 0 && n <= kMaxString) ++n;
        Str(zeroTerminated, n);
    }

    bool ok() const { return !m_failed; }
    uint32_t length() const { return m_length; }
    void Rewind(uint32_t to) { m_length = to; m_failed = false; }

private:
    void Put(const uint8_t* p, uint32_t n) {
        if (m_failed || n > m_capacity - m_length) { m_failed = true; return; }
        for (uint32_t i = 0; i < n; ++i) m_data[m_length + i] = p[i];
        m_length += n;
    }
    void Patch32(uint32_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) m_data[at + i] = uint8_t(v >> (8 * i));
    }

    uint8_t* m_data;
    uint32_t m_capacity;
    uint32_t m_length = 0;
    uint32_t m_frame = 0;
    bool m_failed = false;
};

class Reader {
public:
    Reader(const uint8_t* data, uint32_t length) : m_data(data), m_length(length) {}

    uint8_t U8() { const uint8_t* p = Take(1); return p ? p[0] : 0; }
    uint16_t U16() { const uint8_t* p = Take(2); return p ? uint16_t(p[0] | p[1] << 8) : 0; }
    uint32_t U32() {
        const uint8_t* p = Take(4);
        return p ? uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24 : 0;
    }
    uint64_t U64() { const uint64_t lo = U32(); return lo | uint64_t(U32()) << 32; }
    const uint8_t* Bytes(uint32_t n) { return Take(n); }
    StringView Str() {
        const uint16_t n = U16();
        if (n > kMaxString) { m_failed = true; return {nullptr, 0}; }
        const uint8_t* p = Take(n);
        return {reinterpret_cast<const char*>(p), p ? n : uint16_t(0)};
    }

    // True when every field decoded and every byte was consumed.
    bool done() const { return !m_failed && m_pos == m_length; }
    bool ok() const { return !m_failed; }
    uint32_t remaining() const { return m_length - m_pos; }

private:
    const uint8_t* Take(uint32_t n) {
        if (m_failed || n > m_length - m_pos) { m_failed = true; return nullptr; }
        const uint8_t* p = m_data + m_pos;
        m_pos += n;
        return p;
    }

    const uint8_t* m_data;
    uint32_t m_length;
    uint32_t m_pos = 0;
    bool m_failed = false;
};

// Reads a frame header from `available` bytes. False means more bytes are needed, or (when `bad` is set)
// that the length is over the limit and the connection must be closed.
inline bool ParseHeader(const uint8_t* data, uint32_t available, FrameHeader* out, bool* bad) {
    *bad = false;
    if (available < kHeaderSize) return false;
    Reader r(data, kHeaderSize);
    out->length = r.U32(); out->type = r.U16(); out->flags = r.U16(); out->seq = r.U32();
    if (out->length > kMaxPayload) { *bad = true; return false; }
    return true;
}

struct Hello {
    uint16_t protocol = kVersion;
    uint16_t flags = 0;
    uint32_t buildFingerprint = 0;
    uint32_t moduleVersion = 0;
    uint32_t bookHash = 0;
    uint32_t capabilities = 0;
    StringView token = {nullptr, 0};
    uint64_t imageBase = 0;
};

inline void Write(Writer& w, const Hello& m) {
    w.U16(m.protocol); w.U16(m.flags); w.U32(m.buildFingerprint); w.U32(m.moduleVersion);
    w.U32(m.bookHash); w.U32(m.capabilities); w.Str(m.token.data, m.token.length); w.U64(m.imageBase);
}
inline bool Read(Reader& r, Hello* m) {
    m->protocol = r.U16(); m->flags = r.U16(); m->buildFingerprint = r.U32(); m->moduleVersion = r.U32();
    m->bookHash = r.U32(); m->capabilities = r.U32(); m->token = r.Str(); m->imageBase = r.U64();
    return r.done();
}

struct ProbeEntry {
    uint32_t probeId = 0;
    ProbeMode mode = ProbeMode::Off;
    uint8_t flags = 0;
    uint16_t rateLimitPerSecond = 0;
    uint8_t depth = 0;
    uint64_t forceValue = 0;
    StringView subject = {nullptr, 0};
};

inline void Write(Writer& w, const ProbeEntry& e) {
    w.U32(e.probeId); w.U8(uint8_t(e.mode)); w.U8(e.flags); w.U16(e.rateLimitPerSecond);
    w.U8(e.depth); w.U8(0); w.U64(e.forceValue); w.Str(e.subject.data, e.subject.length);
}
inline bool ReadEntry(Reader& r, ProbeEntry* e) {
    e->probeId = r.U32(); e->mode = ProbeMode(r.U8()); e->flags = r.U8(); e->rateLimitPerSecond = r.U16();
    e->depth = r.U8(); r.U8(); e->forceValue = r.U64(); e->subject = r.Str();
    return r.ok();
}

// SetConfig and Config share a layout: the header, then `count` entries read one at a time with ReadEntry.
struct ConfigHeader { uint32_t revision; uint16_t count; };
inline bool Read(Reader& r, ConfigHeader* h) { h->revision = r.U32(); h->count = r.U16(); return r.ok(); }

inline void WriteConfigApplied(Writer& w, uint32_t revision, uint16_t count) { w.U32(revision); w.U16(count); }
inline void WriteApplied(Writer& w, uint32_t probeId, ProbeResult result) { w.U32(probeId); w.U8(uint8_t(result)); }

struct ProbeHit {
    uint32_t probeId = 0;
    uint32_t threadId = 0;
    uint64_t tick = 0;
    uint64_t caller = 0;
    uint64_t hitId = 0;
    uint8_t argc = 0;
    uint64_t args[kMaxArgs] = {};
    StringView subject = {nullptr, 0};
};

inline void Write(Writer& w, const ProbeHit& m) {
    w.U32(m.probeId); w.U32(m.threadId); w.U64(m.tick); w.U64(m.caller); w.U64(m.hitId);
    const uint8_t argc = m.argc > kMaxArgs ? kMaxArgs : m.argc;
    w.U8(argc);
    for (uint8_t i = 0; i < argc; ++i) w.U64(m.args[i]);
    w.Str(m.subject.data, m.subject.length);
}

struct ProbeReturn { uint32_t probeId; uint32_t threadId; uint64_t tick; uint64_t value; uint8_t failure; uint64_t hitId; };
inline void Write(Writer& w, const ProbeReturn& m) {
    w.U32(m.probeId); w.U32(m.threadId); w.U64(m.tick); w.U64(m.value); w.U8(m.failure); w.U64(m.hitId);
}

struct Notice { uint8_t level; uint32_t category; uint32_t line; StringView file; StringView message; StringView path; };
inline void Write(Writer& w, const Notice& m) {
    w.U8(m.level); w.U32(m.category); w.U32(m.line);
    w.Str(m.file.data, m.file.length); w.Str(m.message.data, m.message.length); w.Str(m.path.data, m.path.length);
}

struct ReadMem { uint64_t address; uint32_t length; };
inline bool Read(Reader& r, ReadMem* m) { m->address = r.U64(); m->length = r.U32(); return r.done(); }
inline void WriteMemData(Writer& w, uint64_t address, uint8_t status, const uint8_t* bytes, uint32_t length) {
    w.U64(address); w.U8(status); w.U32(length); w.Bytes(bytes, length);
}

// Poke: the expected and the new bytes are views into the frame.
struct Poke { uint64_t address; uint16_t count; const uint8_t* expected; const uint8_t* replacement; };
inline bool Read(Reader& r, Poke* m) {
    m->address = r.U64(); m->count = r.U16();
    if (m->count > kMaxPokeBytes) return false;
    m->expected = r.Bytes(m->count); m->replacement = r.Bytes(m->count);
    return r.done();
}

// ---- watching one actor ---------------------------------------------------------------------------------------------

enum class WatchStatus : uint8_t { Watching = 0, Stopped = 1, RefusedName = 2, Partial = 3 };
enum class StepOutcome : uint8_t { None = 0, Ok = 1, Failed = 2, Warning = 3 };
enum class VerdictOutcome : uint8_t { Initialised = 0, Failed = 1, NeverStarted = 2 };
constexpr uint32_t kNoStep = 0xFFFFFFFFu;
constexpr uint16_t kMaxVerdictLines = 12;

struct WatchRequest { bool start; StringView name; };
inline bool Read(Reader& r, WatchRequest* m) { m->start = r.U8() != 0; m->name = r.Str(); return r.done(); }

struct WatchAck { WatchStatus status; uint16_t armed; uint16_t refused; StringView name; StringView note; };
inline void Write(Writer& w, const WatchAck& m) {
    w.U8(uint8_t(m.status)); w.U16(m.armed); w.U16(m.refused);
    w.Str(m.name.data, m.name.length); w.Str(m.note.data, m.note.length);
}

struct ActorStep { uint32_t stepId; uint8_t phase; StepOutcome outcome; uint32_t threadId; uint64_t tick; uint64_t value; StringView detail; };
inline void Write(Writer& w, const ActorStep& m) {
    w.U32(m.stepId); w.U8(m.phase); w.U8(uint8_t(m.outcome)); w.U32(m.threadId); w.U64(m.tick); w.U64(m.value);
    w.Str(m.detail.data, m.detail.length);
}

// Which way a failing function went out: the function's offset, the exit's number and how many exits the function has. Sent just before the
// leave event of the step that failed; `detail` is the component the step was about, if any.
struct ActorExit { uint32_t stepId; uint32_t function; uint16_t ordinal; uint16_t count; StringView detail; };
inline void Write(Writer& w, const ActorExit& m) {
    w.U32(m.stepId); w.U32(m.function); w.U16(m.ordinal); w.U16(m.count); w.Str(m.detail.data, m.detail.length);
}

// The verdict's lines are written one at a time between BeginVerdict and the last Str, so the module needs no array of them.
inline void BeginVerdict(Writer& w, VerdictOutcome outcome, uint32_t failedStep, uint64_t code, StringView summary, uint16_t lineCount) {
    w.U8(uint8_t(outcome)); w.U32(failedStep); w.U64(code); w.Str(summary.data, summary.length); w.U16(lineCount);
}

}  // namespace purah::proto
