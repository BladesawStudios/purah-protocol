// What the module takes from the WiiXLaunch host (wiixl.core, wiixl.call, wiixl.net) and from the CPU.
//
// Every host symbol is bound through WXL_USE, which keeps the call indirect: a direct call to a host address
// cannot be relocated in a .wxlm (docs/framework/modules.md in WiiXLaunch).
#pragma once

#include <wiixlaunch/mod_log.h>
#include <wiixlaunch/mod_runtime.h>
#include <wiixlaunch/imports/wiixl_call.h>
#include <wiixlaunch/imports/wiixl_core.h>
#include <wiixlaunch/imports/wiixl_net.h>
#include <wiixlaunch/imports/wiixl_patch.h>

#include <cstddef>
#include <cstdint>

namespace purah::host {

namespace S {
WXL_USE_wiixl_core(InstallHook);
WXL_USE_wiixl_core(Alloc);
WXL_USE_wiixl_core(ImageBase);
WXL_USE_wiixl_core(RegisterTick);
WXL_USE_wiixl_core(InstallInlineHook);
WXL_USE_wiixl_core(ReadableBytes);
WXL_USE_wiixl_core(WritableBytes);
WXL_USE_wiixl_core(SleepNanos);
WXL_USE_wiixl_patch(Write);
WXL_USE_wiixl_call(ResolveTarget);
WXL_USE_wiixl_net(Available);
WXL_USE_wiixl_net(Open);
WXL_USE_wiixl_net(SetNonBlocking);
WXL_USE_wiixl_net(SetReuseAddr);
WXL_USE_wiixl_net(Bind);
WXL_USE_wiixl_net(Listen);
WXL_USE_wiixl_net(Accept);
WXL_USE_wiixl_net(Recv);
WXL_USE_wiixl_net(Send);
WXL_USE_wiixl_net(Shutdown);
WXL_USE_wiixl_net(Close);
WXL_USE_wiixl_net(ResultName);
WXL_USE_wiixl_net(LastError);
}  // namespace S

#define PURAH_LOG(...) ::WiiXLaunch::ModLog::LogFormat(__VA_ARGS__)

// The game's system tick (the ARM generic counter) and the calling thread's id.
inline uint64_t Tick() {
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
inline uint64_t TickFrequency() {
    uint64_t v;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}
inline uint32_t ThreadId() {
    uint64_t v;
    asm volatile("mrs %0, tpidrro_el0" : "=r"(v));
    return static_cast<uint32_t>(v >> 4);
}

// A test-and-set lock: hooks run on any game thread, and none of them may sleep.
class SpinLock {
public:
    void Lock() { while (__atomic_test_and_set(&m_flag, __ATOMIC_ACQUIRE)) {} }
    void Unlock() { __atomic_clear(&m_flag, __ATOMIC_RELEASE); }

private:
    volatile bool m_flag = false;
};

struct LockGuard {
    explicit LockGuard(SpinLock& l) : lock(l) { lock.Lock(); }
    ~LockGuard() { lock.Unlock(); }
    SpinLock& lock;
};

}  // namespace purah::host
