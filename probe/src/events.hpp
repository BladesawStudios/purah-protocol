// Turns what the hooks see into finished event frames in the ring. Everything here runs on whichever game thread
// hit the probe, so it allocates nothing and takes only the ring's own lock.
#pragma once

#include "host.hpp"
#include "protocol.hpp"
#include "ring.hpp"
#include "text.hpp"

namespace purah {

inline EventRing g_ring;
inline uint32_t g_eventSeq = 0;
inline uint64_t g_imageBase = 0;
inline volatile bool g_clientConnected = false;

constexpr uint64_t kImageSpan = 0x6000000;  // TotK's main image plus its bss; reads outside it are refused.
constexpr uint32_t kEventMax = 1536;

inline bool InImage(uint64_t p) { return p >= g_imageBase && p < g_imageBase + kImageSpan; }

// One event frame under construction on the caller's stack.
class EventFrame {
public:
    explicit EventFrame(proto::MessageType type) : m_writer(m_bytes, sizeof(m_bytes)) {
        m_writer.BeginFrame(type, proto::kEvent, __atomic_add_fetch(&g_eventSeq, 1, __ATOMIC_RELAXED));
    }
    proto::Writer& w() { return m_writer; }

    // Ends the frame and queues it; nothing is queued when no client is connected or it did not fit.
    void Send() {
        m_writer.EndFrame();
        if (m_writer.ok() && g_clientConnected) g_ring.Push(m_bytes, m_writer.length());
    }

private:
    uint8_t m_bytes[kEventMax];
    proto::Writer m_writer;
};

inline void EmitLog(uint8_t level, const char* text) {
    EventFrame f(proto::MessageType::Log);
    f.w().U8(level);
    f.w().Str(text);
    f.Send();
}

inline bool Printable(uint8_t c) { return c >= 0x20 && c < 0x7F; }

// Whether `length` bytes from `address` are mapped and readable, asked of the host before any of them is touched.
inline bool Readable(uint64_t address, uint64_t length) {
    return address >= 0x10000 && host::S::ReadableBytes(address, length) >= length;
}

// Reads the printable zero-terminated string at `p`, at most `capacity` characters; 0 when `p` is not readable text.
inline uint16_t ReadCString(uint64_t p, char* out, uint16_t capacity) {
    if (p < 0x10000) return 0;
    const uint64_t room = host::S::ReadableBytes(p, capacity);
    const char* s = reinterpret_cast<const char*>(p);
    uint16_t n = 0;
    while (n < room && s[n] != 0 && Printable(static_cast<uint8_t>(s[n]))) { out[n] = s[n]; ++n; }
    return n;
}

// Reads text from `p`, which is either the characters themselves or an object holding a pointer to them at +8.
// Anything that is not readable text yields length 0.
inline uint16_t ReadText(uint64_t p, char* out, uint16_t capacity) {
    if (!Readable(p, 16)) return 0;
    const char* s = reinterpret_cast<const char*>(p);
    if (!Printable(static_cast<uint8_t>(s[0]))) {
        const uint64_t q = *reinterpret_cast<const uint64_t*>(p + 8);
        if (!Readable(q, 1) || !Printable(*reinterpret_cast<const uint8_t*>(q))) return 0;
        s = reinterpret_cast<const char*>(q);
    }
    const uint64_t room = host::S::ReadableBytes(reinterpret_cast<uint64_t>(s), capacity);
    uint16_t n = 0;
    while (n < capacity && n < room && Printable(static_cast<uint8_t>(s[n]))) { out[n] = s[n]; ++n; }
    return n;
}

}  // namespace purah
