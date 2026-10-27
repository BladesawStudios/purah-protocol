// Small text helpers that need neither libc nor the heap.
#pragma once

#include <cstdint>

namespace purah {

// Appends text to a fixed buffer, always leaving it terminated; what does not fit is dropped.
class TextBuf {
public:
    TextBuf(char* buffer, uint32_t capacity) : m_buffer(buffer), m_capacity(capacity) { m_buffer[0] = 0; }

    TextBuf& Add(const char* text) {
        while (*text && m_length + 1 < m_capacity) m_buffer[m_length++] = *text++;
        m_buffer[m_length] = 0;
        return *this;
    }

    TextBuf& AddN(const char* text, uint32_t length) {
        for (uint32_t i = 0; i < length && m_length + 1 < m_capacity; ++i) m_buffer[m_length++] = text[i];
        m_buffer[m_length] = 0;
        return *this;
    }

    // Decimal up to 0xFFFF and hexadecimal ("0x...") above, which is how the game's ids and codes read.
    TextBuf& AddValue(uint64_t value) {
        char digits[20];
        uint32_t count = 0;
        if (value > 0xFFFF) {
            Add("0x");
            do { digits[count++] = "0123456789ABCDEF"[value & 15]; value >>= 4; } while (value);
        } else {
            do { digits[count++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
        }
        while (count && m_length + 1 < m_capacity) m_buffer[m_length++] = digits[--count];
        m_buffer[m_length] = 0;
        return *this;
    }

    uint32_t length() const { return m_length; }

private:
    char* m_buffer;
    uint32_t m_capacity;
    uint32_t m_length = 0;
};

// Whether the first `length` bytes of `text` are exactly the zero-terminated `known`.
inline bool SameText(const char* text, uint32_t length, const char* known) {
    uint32_t i = 0;
    while (i < length && known[i] == text[i]) ++i;
    return i == length && known[i] == 0;
}

}  // namespace purah
