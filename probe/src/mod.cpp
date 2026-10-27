// purah-protocol: a live debugger module for Tears of the Kingdom, driven over TCP by Prism's Debugger tab.
// This file is the entry point and the per-frame tick; the work is in server.hpp (the socket), config.hpp (what is
// armed), probes.hpp (the hooks) and watch.hpp (following one actor through its initialisation).
#include "server.hpp"

namespace {

constexpr uint32_t kRingCapacity = 0x10000;  // a power of two

purah::Server g_server;
bool g_ready = false;

void ServeOnce() { g_server.Tick(); }

}  // namespace

extern "C" __attribute__((used)) void WiiXLaunch_ModTick() {
    if (!g_ready) return;
    purah::g_tickThread = purah::host::ThreadId();
    g_server.Tick();
    purah::WatchTick();
}

extern "C" __attribute__((used)) void WiiXLaunch_ModEntry() {
    using namespace purah;
    auto* ring = static_cast<uint8_t*>(host::S::Alloc(kRingCapacity, 16));
    auto* rx = static_cast<uint8_t*>(host::S::Alloc(kRxCapacity, 16));
    auto* tx = static_cast<uint8_t*>(host::S::Alloc(kTxCapacity, 16));
    auto* reply = static_cast<uint8_t*>(host::S::Alloc(kReplyCapacity, 16));
    if (!ring || !rx || !tx || !reply) {
        PURAH_LOG("purah: could not allocate buffers - not starting");
        return;
    }
    g_imageBase = host::S::ImageBase();
    g_serve = &ServeOnce;
    g_ring.Init(ring, kRingCapacity);
    g_server.Init(rx, tx, reply);
    FillCallbacks(std::make_integer_sequence<uint32_t, book::kCount>{});
    if (!host::S::RegisterTick(&WiiXLaunch_ModTick)) {
        PURAH_LOG("purah: RegisterTick refused - not starting");
        return;
    }
    g_ready = true;
    PURAH_LOG("purah: ready, %u probes in the book (hash %08X)", unsigned(book::kCount), unsigned(book::kHash));
}
