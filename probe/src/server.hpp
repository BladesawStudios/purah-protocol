// The server: one client at a time over wiixl.net, driven once per game tick. It never blocks - every
// socket call is non-blocking and each tick moves at most a bounded number of bytes - and it is the only code
// that touches the socket. Hooks never send; they queue frames in the ring and the tick drains it.
#pragma once

#include "config.hpp"
#include "memory.hpp"
#include "watch_control.hpp"

namespace purah {

constexpr uint32_t kFingerprint = 0x181D91D8;  // TotK 1.2.1 (WiiXLaunch targets/totk.json)
constexpr uint32_t kModuleVersion = 1;
constexpr uint32_t kRxCapacity = 0x11000;
constexpr uint32_t kTxCapacity = 0x10000;
constexpr uint32_t kReplyCapacity = 0x2000;
constexpr uint32_t kSendPerTick = 0x8000;
constexpr uint32_t kRetryTicks = 120;

class Server {
public:
    void Init(uint8_t* rx, uint8_t* tx, uint8_t* reply) {
        m_rx = rx;
        m_tx = tx;
        m_reply = reply;
    }

    void Tick() {
        if (!m_listener && !OpenListener()) return;
        if (!m_client) { AcceptClient(); return; }
        Receive();
        if (m_client) { DrainEvents(); Flush(); }
    }

private:
    bool OpenListener() {
        if (m_retry > 0) { --m_retry; return false; }
        m_retry = kRetryTicks;
        if (!host::S::Available()) return false;
        uint32_t h = 0;
        if (host::S::Open(&h) != 0) return false;
        const bool ok = host::S::SetReuseAddr(h) == 0 && host::S::Bind(h, proto::kPort) == 0 &&
                        host::S::Listen(h, 1) == 0 && host::S::SetNonBlocking(h) == 0;
        if (!ok) {
            PURAH_LOG("purah: could not listen on %u (platform error %d)", unsigned(proto::kPort), int(host::S::LastError()));
            host::S::Close(h);
            return false;
        }
        m_listener = h;
        PURAH_LOG("purah: listening on port %u", unsigned(proto::kPort));
        return true;
    }

    void AcceptClient() {
        uint32_t h = 0;
        if (host::S::Accept(m_listener, &h) != 0) return;
        host::S::SetNonBlocking(h);
        m_client = h;
        m_rxLength = m_txLength = 0;
        m_greeted = false;
        g_ring.Clear();
        PURAH_LOG("purah: client connected");
    }

    void Drop(uint16_t reason) {
        if (reason != 0xFFFF) { Reply(proto::MessageType::Goodbye, 0, 0, [&](proto::Writer& w) { w.U16(reason); }); Flush(); }
        host::S::Shutdown(m_client, 1);
        host::S::Close(m_client);
        m_client = 0;
        g_clientConnected = false;
        g_ring.Clear();
        config::DowngradeOnDisconnect();
        StopWatch();
        PURAH_LOG("purah: client gone");
    }

    void Receive() {
        const int32_t n = host::S::Recv(m_client, m_rx + m_rxLength, kRxCapacity - m_rxLength);
        if (n == 0) { Drop(0xFFFF); return; }
        if (n > 0) m_rxLength += static_cast<uint32_t>(n);
        for (;;) {
            proto::FrameHeader h;
            bool bad = false;
            if (!proto::ParseHeader(m_rx, m_rxLength, &h, &bad)) {
                if (bad) { SendError(0, 5, "frame too long"); Drop(1); }
                return;
            }
            if (m_rxLength < proto::kHeaderSize + h.length) return;
            const bool ok = Dispatch(h, m_rx + proto::kHeaderSize);
            const uint32_t used = proto::kHeaderSize + h.length;
            memmove(m_rx, m_rx + used, m_rxLength - used);
            m_rxLength -= used;
            if (!ok) return;  // the connection was dropped
        }
    }

    // False when the connection was dropped.
    bool Dispatch(const proto::FrameHeader& h, const uint8_t* payload) {
        proto::Reader r(payload, h.length);
        const auto type = static_cast<proto::MessageType>(h.type);
        if (!m_greeted && type != proto::MessageType::Hello) { SendError(h.seq, 5, "Hello first"); Drop(1); return false; }
        switch (type) {
        case proto::MessageType::Hello: return OnHello(h, r);
        case proto::MessageType::Goodbye: Drop(0xFFFF); return false;
        case proto::MessageType::Ping: {
            const uint64_t token = r.U64();
            if (!r.done()) break;
            Reply(proto::MessageType::Pong, h.seq, 0, [&](proto::Writer& w) { w.U64(token); });
            return true;
        }
        case proto::MessageType::GetConfig: SendConfig(h.seq); return true;
        case proto::MessageType::SetConfig: return OnSetConfig(h, r);
        case proto::MessageType::ListProbes: SendProbes(h.seq); return true;
        case proto::MessageType::WatchActor: return OnWatch(h, r);
        case proto::MessageType::ReadMem: return OnReadMem(h, r);
        case proto::MessageType::Poke: return OnPoke(h, r);
        case proto::MessageType::Resume: return OnStopAnswer(h, r, StopAction::Resume);
        case proto::MessageType::StepOut: return OnStopAnswer(h, r, StopAction::StepOut);
        case proto::MessageType::ForceReturn: return OnStopAnswer(h, r, StopAction::ForceReturn);
        default: SendError(h.seq, 1, "unknown message"); return true;
        }
        SendError(h.seq, 5, "malformed");
        Drop(1);
        return false;
    }

    bool OnHello(const proto::FrameHeader& h, proto::Reader& r) {
        proto::Hello in;
        if (!proto::Read(r, &in)) { SendError(h.seq, 5, "malformed Hello"); Drop(1); return false; }
        if (in.protocol != proto::kVersion) { SendError(h.seq, 3, "protocol version"); Drop(1); return false; }
        m_greeted = true;
        g_clientConnected = true;
        proto::Hello out;
        out.buildFingerprint = kFingerprint;
        out.moduleVersion = kModuleVersion;
        out.bookHash = book::kHash;
        out.capabilities = proto::kCanWrite | proto::kCanBreak;
        out.imageBase = g_imageBase;
        Reply(proto::MessageType::Hello, h.seq, proto::kResponse, [&](proto::Writer& w) { Write(w, out); });
        return true;
    }

    bool OnSetConfig(const proto::FrameHeader& h, proto::Reader& r) {
        if (!config::Apply(r, [&](const config::Applied* results, uint32_t count, uint32_t revision) {
                Reply(proto::MessageType::ConfigApplied, h.seq, proto::kResponse, [&](proto::Writer& w) {
                    proto::WriteConfigApplied(w, revision, static_cast<uint16_t>(count));
                    for (uint32_t i = 0; i < count; ++i) proto::WriteApplied(w, results[i].probeId, results[i].result);
                });
            })) {
            SendError(h.seq, 5, "malformed SetConfig");
            Drop(1);
            return false;
        }
        return true;
    }

    // WatchActor: start following one actor (hooks are placed now, on this thread, before the answer goes out) or stop.
    bool OnWatch(const proto::FrameHeader& h, proto::Reader& r) {
        proto::WatchRequest request;
        if (!proto::Read(r, &request)) { SendError(h.seq, 5, "malformed WatchActor"); Drop(1); return false; }
        WatchResult result = {proto::WatchStatus::Stopped, 0, 0, {}, 0};
        if (request.start) {
            result = StartWatch(request.name.data, request.name.length);
            PURAH_LOG("purah: watching an actor (%u steps hooked, %u refused)", unsigned(result.armed), unsigned(result.refused));
        } else {
            StopWatch();
        }
        Reply(proto::MessageType::WatchAck, h.seq, proto::kResponse, [&](proto::Writer& w) {
            proto::Write(w, proto::WatchAck{result.status, result.armed, result.refused, request.name, {result.note, result.noteLength}});
        });
        return true;
    }

    // Resume / StepOut carry a hit id; ForceReturn also the value to return.
    bool OnStopAnswer(const proto::FrameHeader& h, proto::Reader& r, StopAction action) {
        const uint64_t hitId = r.U64();
        const uint64_t value = action == StopAction::ForceReturn ? r.U64() : 0;
        if (!r.done()) { SendError(h.seq, 5, "malformed stop answer"); Drop(1); return false; }
        if (!AnswerStop(hitId, action, value)) SendError(h.seq, 9, "no thread is stopped at that hit");
        return true;
    }

    bool OnReadMem(const proto::FrameHeader& h, proto::Reader& r) {
        proto::ReadMem m;
        if (!proto::Read(r, &m)) { SendError(h.seq, 5, "malformed ReadMem"); Drop(1); return false; }
        uint8_t status = 0;
        uint32_t length = 0;
        if (m.length > proto::kMaxReadBytes) status = 2;
        else if ((length = ReadGame(m.address, m.length, m_mem)) == 0) status = 1;
        Reply(proto::MessageType::MemData, h.seq, proto::kResponse, [&](proto::Writer& w) {
            proto::WriteMemData(w, m.address, status, m_mem, length);
        });
        return true;
    }

    bool OnPoke(const proto::FrameHeader& h, proto::Reader& r) {
        proto::Poke p;
        if (!proto::Read(r, &p)) { SendError(h.seq, 5, "malformed Poke"); Drop(1); return false; }
        const uint8_t status = PokeGame(p);
        if (status == 0) EmitLog(0, "memory written by the client");
        Reply(proto::MessageType::PokeResult, h.seq, proto::kResponse, [&](proto::Writer& w) { w.U64(p.address); w.U8(status); });
        return true;
    }

    void SendConfig(uint32_t seq) {
        Reply(proto::MessageType::Config, seq, proto::kResponse, [&](proto::Writer& w) { config::WriteCurrent(w); });
    }

    void SendProbes(uint32_t seq) {
        Reply(proto::MessageType::Probes, seq, proto::kResponse, [&](proto::Writer& w) {
            w.U16(static_cast<uint16_t>(book::kCount));
            for (uint32_t i = 0; i < book::kCount; ++i) {
                const uint8_t state = g_probes[i].refused ? 2 : (g_probes[i].installed ? 1 : 0);
                w.U32(i);
                w.U8(state);
                w.U8(g_probes[i].refused ? 1 : 0);
            }
        });
    }

    void SendError(uint32_t seq, uint16_t code, const char* text) {
        Reply(proto::MessageType::Error, seq, proto::kResponse, [&](proto::Writer& w) { w.U16(code); w.Str(text); });
    }

    // Builds one frame in the scratch buffer and appends it to the send queue.
    template <typename Body>
    void Reply(proto::MessageType type, uint32_t seq, uint16_t flags, Body body) {
        proto::Writer w(m_reply, kReplyCapacity);
        w.BeginFrame(type, flags, seq);
        body(w);
        w.EndFrame();
        if (w.ok() && m_txLength + w.length() <= kTxCapacity) {
            memcpy(m_tx + m_txLength, m_reply, w.length());
            m_txLength += w.length();
        }
    }

    void DrainEvents() {
        const uint32_t dropped = g_ring.TakeDropped();
        if (dropped) {
            const uint32_t seq = __atomic_add_fetch(&g_eventSeq, 1, __ATOMIC_RELAXED);
            Reply(proto::MessageType::Overflow, seq, proto::kEvent, [&](proto::Writer& w) { w.U32(dropped); });
        }
        uint32_t length = 0;
        while (m_txLength + kEventMax <= kTxCapacity && g_ring.Pop(m_tx + m_txLength, kTxCapacity - m_txLength, &length))
            m_txLength += length;
    }

    void Flush() {
        if (m_txLength == 0) return;
        const uint32_t chunk = m_txLength < kSendPerTick ? m_txLength : kSendPerTick;
        const int32_t n = host::S::Send(m_client, m_tx, chunk);
        if (n <= 0) return;
        memmove(m_tx, m_tx + n, m_txLength - static_cast<uint32_t>(n));
        m_txLength -= static_cast<uint32_t>(n);
    }

    uint8_t* m_rx = nullptr;
    uint8_t* m_tx = nullptr;
    uint8_t* m_reply = nullptr;
    uint8_t m_mem[proto::kMaxReadBytes];
    uint32_t m_rxLength = 0;
    uint32_t m_txLength = 0;
    uint32_t m_listener = 0;
    uint32_t m_client = 0;
    uint32_t m_retry = 0;
    bool m_greeted = false;
};

}  // namespace purah
