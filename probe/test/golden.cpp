// Host-side check of protocol.hpp. Build: g++ -std=c++17 -Wall -Wextra -Werror -I ../src golden.cpp -o golden
// It prints the bytes of three messages (compare with Prism: dotnet run --project src/Prism.DevTools/ProtocolCheck) and checks a few failure cases.
#include <cstdio>
#include <cstring>
#include "protocol.hpp"

using namespace purah::proto;

static void Show(const char* name, const uint8_t* data, uint32_t length) {
    std::printf("%s ", name);
    for (uint32_t i = 0; i < length; ++i) std::printf("%02X", data[i]);
    std::printf("\n");
}

int main() {
    uint8_t buffer[512];

    Writer ping(buffer, sizeof(buffer));
    ping.BeginFrame(MessageType::Ping, 0, 7);
    ping.U64(0x0102030405060708ull);
    ping.EndFrame();
    Show("ping", buffer, ping.length());

    Writer hello(buffer, sizeof(buffer));
    hello.BeginFrame(MessageType::Hello, 0, 1);
    Hello h;
    h.buildFingerprint = 0x181D91D8; h.moduleVersion = 1; h.bookHash = 0xAABBCCDD; h.capabilities = 3;
    h.token = {"x", 1}; h.imageBase = 0x7100000000ull;
    Write(hello, h);
    hello.EndFrame();
    Show("hello", buffer, hello.length());

    // Decode the hello it just wrote.
    Reader r(buffer + kHeaderSize, hello.length() - kHeaderSize);
    Hello back;
    const bool good = Read(r, &back) && back.bookHash == 0xAABBCCDD && back.token.length == 1 && back.token.data[0] == 'x';
    std::printf("hello roundtrip %s\n", good ? "ok" : "FAILED");

    Writer hit(buffer, sizeof(buffer));
    hit.BeginFrame(MessageType::ProbeHit, kEvent, 9);
    ProbeHit p;
    p.probeId = 5; p.threadId = 2; p.tick = 0x1122334455667788ull; p.caller = 0x71007FD97Cull; p.hitId = 0;
    p.argc = 2; p.args[0] = 0x10; p.args[1] = 0x20; p.subject = {"ab", 2};
    Write(hit, p);
    hit.EndFrame();
    Show("hit", buffer, hit.length());

    Writer watch(buffer, sizeof(buffer));
    watch.BeginFrame(MessageType::WatchActor, 0, 3);
    watch.U8(1); watch.Str("AB");
    watch.EndFrame();
    Show("watch", buffer, watch.length());

    Writer step(buffer, sizeof(buffer));
    step.BeginFrame(MessageType::ActorStep, kEvent, 4);
    Write(step, ActorStep{3, 1, StepOutcome::Failed, 9, 0x10, 0, {"PC", 2}});
    step.EndFrame();
    Show("step", buffer, step.length());

    Writer verdict(buffer, sizeof(buffer));
    verdict.BeginFrame(MessageType::ActorVerdict, kEvent, 5);
    BeginVerdict(verdict, VerdictOutcome::Failed, 5, 0, {"s", 1}, 1);
    verdict.Str("l");
    verdict.EndFrame();
    Show("verdict", buffer, verdict.length());

    Writer exitEvent(buffer, sizeof(buffer));
    exitEvent.BeginFrame(MessageType::ActorExit, kEvent, 6);
    Write(exitEvent, ActorExit{3, 0x70775C, 2, 17, {"PC", 2}});
    exitEvent.EndFrame();
    Show("exit", buffer, exitEvent.length());

    Writer ack(buffer, sizeof(buffer));
    ack.BeginFrame(MessageType::WatchAck, kResponse, 3);
    Write(ack, WatchAck{WatchStatus::Watching, 40, 2, {"AB", 2}, {"n", 1}});
    ack.EndFrame();
    Show("ack", buffer, ack.length());

    FrameHeader header;
    bool bad = false;
    const bool parsed = ParseHeader(buffer, hit.length(), &header, &bad);
    std::printf("header %s length=%u type=%04X flags=%04X seq=%u\n", parsed ? "ok" : "FAILED", header.length, header.type, header.flags, header.seq);

    // A truncated payload must fail, and an over-long length must be flagged bad.
    Reader shortRead(buffer + kHeaderSize, 10);
    ProbeEntry entry;
    std::printf("truncated read %s\n", ReadEntry(shortRead, &entry) ? "WRONGLY OK" : "rejected");
    uint8_t huge[kHeaderSize] = {0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0};
    ParseHeader(huge, kHeaderSize, &header, &bad);
    std::printf("oversize length %s\n", bad ? "flagged" : "NOT FLAGGED");
    return 0;
}
