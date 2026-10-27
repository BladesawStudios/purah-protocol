// The game's own diagnostic channels, which the retail build compiles to nothing: the parameter system's
// sead::NoticeContext (about 400 call sites) and the effects system's xlink2::System::addError. Hooking the
// constructor and the empty function is what makes their reports readable.
#pragma once

#include "watch.hpp"

namespace purah {

// Text of the first argument after `from` that points at printable text inside the game image.
inline uint16_t FirstImageText(const uint64_t* args, uint32_t from, char* out, uint16_t capacity) {
    for (uint32_t i = from; i < 8; ++i) {
        if (!InImage(args[i]) || !Readable(args[i], 4)) continue;
        const uint16_t n = ReadText(args[i], out, capacity);
        if (n > 3) return n;
    }
    return 0;
}

// sead::NoticeContext::NoticeContext: once the constructor has run the object holds file (+8), message (+0x10), path (+0x20),
// line (+0x30), level (+0x34) and category (+0x38).
inline void EmitNotice(uint64_t self, bool send) {
    if (!Readable(self, 0x40)) return;
    char file[96], message[240], path[160];
    const auto* base = reinterpret_cast<const uint8_t*>(self);
    EventFrame f(proto::MessageType::Notice);
    proto::Notice n;
    n.level = static_cast<uint8_t>(*reinterpret_cast<const uint32_t*>(base + 0x34));
    n.category = *reinterpret_cast<const uint32_t*>(base + 0x38);
    n.line = *reinterpret_cast<const uint32_t*>(base + 0x30);
    n.file = {file, ReadText(*reinterpret_cast<const uint64_t*>(base + 8), file, sizeof(file))};
    n.message = {message, ReadText(*reinterpret_cast<const uint64_t*>(base + 0x10), message, sizeof(message))};
    n.path = {path, ReadText(*reinterpret_cast<const uint64_t*>(base + 0x20), path, sizeof(path))};
    Write(f.w(), n);
    if (send) f.Send();
    WatchNotice(n.file.data, n.file.length, n.message.data, n.message.length, n.path.data, n.path.length);
}

// xlink2::System::addError(category, link user, format, ...): the format string is whichever argument points into the
// image; the link user is named through the thread's scope when the call happens inside an actor's init.
inline void EmitLinkError(const uint64_t* args, bool send) {
    char message[240];
    const char file[] = "xlink2::System::addError";
    SubjectName scope;
    EventFrame f(proto::MessageType::Notice);
    proto::Notice n;
    n.level = 2;
    n.category = static_cast<uint32_t>(args[0]);
    n.line = 0;
    n.file = {file, sizeof(file) - 1};
    n.message = {message, FirstImageText(args, 1, message, sizeof(message))};
    n.path = CurrentScope(&scope) ? proto::StringView{scope.text, scope.length} : proto::StringView{nullptr, 0};
    Write(f.w(), n);
    if (send) f.Send();
    WatchNotice(n.file.data, n.file.length, n.message.data, n.message.length, n.path.data, n.path.length);
}

}  // namespace purah
