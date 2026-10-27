// A byte ring of finished protocol frames, written by hooks on any thread and drained by the tick.
//
// Each record is a u32 length then that many bytes (one whole frame). A full ring drops the record and counts
// it; the count goes out as an Overflow event, so a slow client costs events, never frame time.
#pragma once

#include "host.hpp"

namespace purah {

class EventRing {
public:
    // `storage` must outlive the ring; `capacity` is a power of two.
    void Init(uint8_t* storage, uint32_t capacity) {
        m_data = storage;
        m_capacity = capacity;
    }

    void Push(const uint8_t* frame, uint32_t length) {
        host::LockGuard guard(m_lock);
        if (m_capacity - (m_head - m_tail) < length + 4) { ++m_dropped; return; }
        Put(reinterpret_cast<const uint8_t*>(&length), 4);
        Put(frame, length);
    }

    // Copies the oldest record into `out`; false when empty or `out` is too small (the record is then skipped).
    bool Pop(uint8_t* out, uint32_t outCapacity, uint32_t* length) {
        host::LockGuard guard(m_lock);
        if (m_head == m_tail) return false;
        uint32_t n = 0;
        Take(reinterpret_cast<uint8_t*>(&n), 4);
        if (n > outCapacity) { m_tail += n; return false; }
        Take(out, n);
        *length = n;
        return true;
    }

    uint32_t TakeDropped() {
        host::LockGuard guard(m_lock);
        const uint32_t d = m_dropped;
        m_dropped = 0;
        return d;
    }

    void Clear() {
        host::LockGuard guard(m_lock);
        m_tail = m_head;
        m_dropped = 0;
    }

private:
    void Put(const uint8_t* p, uint32_t n) {
        for (uint32_t i = 0; i < n; ++i) m_data[(m_head + i) & (m_capacity - 1)] = p[i];
        m_head += n;
    }
    void Take(uint8_t* p, uint32_t n) {
        for (uint32_t i = 0; i < n; ++i) p[i] = m_data[(m_tail + i) & (m_capacity - 1)];
        m_tail += n;
    }

    host::SpinLock m_lock;
    uint8_t* m_data = nullptr;
    uint32_t m_capacity = 0;
    uint32_t m_head = 0;
    uint32_t m_tail = 0;
    uint32_t m_dropped = 0;
};

}  // namespace purah
