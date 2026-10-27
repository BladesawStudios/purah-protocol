// The live configuration: which probes are armed, in what mode. A client sends the whole desired set with a
// revision number; this makes it true and reports, per probe, what happened. Run on the game tick, never on a
// hook, so installing a hook never races another install.
#pragma once

#include "probes.hpp"

namespace purah::config {

struct Applied {
    uint32_t probeId;
    proto::ProbeResult result;
};

inline uint32_t g_revision = 0;
inline proto::ProbeEntry g_entries[book::kCount];
inline Applied g_results[book::kCount];

inline void Store(ProbeState& s, const proto::ProbeEntry& e) {
    s.flags = e.flags;
    s.depth = e.depth;
    s.rate = e.rateLimitPerSecond;
    s.forceValue = e.forceValue;
    s.windowCount = 0;
    s.subjectLength = e.subject.length < kSubjectMax ? static_cast<uint8_t>(e.subject.length) : kSubjectMax;
    for (uint8_t i = 0; i < s.subjectLength; ++i) s.subject[i] = e.subject.data[i];
    s.mode = e.mode;  // last, so a hit never sees a half-written probe
}

inline proto::ProbeResult Arm(const proto::ProbeEntry& e) {
    if (e.probeId >= book::kCount) return proto::ProbeResult::RefusedUnknownProbe;
    if (e.mode == proto::ProbeMode::Off) { g_probes[e.probeId].mode = proto::ProbeMode::Off; return proto::ProbeResult::Applied; }
    const book::Row& row = book::kRows[e.probeId];
    const bool diagnostic = row.kind == book::Kind::Notice || row.kind == book::Kind::LinkError;
    // A diagnostic channel only reports; a call site cannot skip its call; a filter has to fit the stored name.
    if (diagnostic && e.mode != proto::ProbeMode::Trace) return proto::ProbeResult::RefusedUnsupported;
    if (row.kind == book::Kind::Site && e.mode == proto::ProbeMode::ForceReturn) return proto::ProbeResult::RefusedUnsupported;
    if (e.subject.length > kSubjectMax) return proto::ProbeResult::RefusedUnsupported;
    const proto::ProbeResult installed = Install(e.probeId);
    if (installed != proto::ProbeResult::Applied) return installed;
    Store(g_probes[e.probeId], e);
    return proto::ProbeResult::Applied;
}

// A subject filter relies on knowing which actor a thread is working on, so while any armed probe filters, the rows
// that open an actor's scope are hooked too (they stay hooked; with no filter they only cost a name lookup).
inline void TrackScopes(uint16_t count) {
    bool filtered = false;
    for (uint16_t i = 0; i < count; ++i) filtered |= g_entries[i].mode != proto::ProbeMode::Off && g_entries[i].subject.length > 0;
    if (!filtered) return;
    for (uint32_t i = 0; i < book::kCount; ++i)
        if (book::kRows[i].scope) Install(i);
}

// Parses a SetConfig and applies it. False means the payload was malformed (nothing was changed). `reply` is
// called once with the per-probe results and the revision now in force.
template <typename Reply>
bool Apply(proto::Reader& r, Reply reply) {
    proto::ConfigHeader header;
    if (!proto::Read(r, &header) || header.count > book::kCount) return false;
    for (uint16_t i = 0; i < header.count; ++i)
        if (!proto::ReadEntry(r, &g_entries[i])) return false;
    if (!r.done()) return false;

    if (header.revision <= g_revision) { reply(g_results, 0, g_revision); return true; }
    for (uint32_t i = 0; i < book::kCount; ++i) g_probes[i].mode = proto::ProbeMode::Off;
    for (uint16_t i = 0; i < header.count; ++i) {
        g_results[i].probeId = g_entries[i].probeId;
        g_results[i].result = Arm(g_entries[i]);
    }
    g_revision = header.revision;
    TrackScopes(header.count);
    reply(g_results, header.count, g_revision);
    return true;
}

inline void WriteCurrent(proto::Writer& w) {
    uint16_t count = 0;
    for (uint32_t i = 0; i < book::kCount; ++i) count += g_probes[i].mode != proto::ProbeMode::Off;
    w.U32(g_revision);
    w.U16(count);
    for (uint32_t i = 0; i < book::kCount; ++i) {
        const ProbeState& s = g_probes[i];
        if (s.mode == proto::ProbeMode::Off) continue;
        proto::ProbeEntry e;
        e.probeId = i;
        e.mode = s.mode;
        e.flags = s.flags;
        e.rateLimitPerSecond = s.rate;
        e.depth = s.depth;
        e.forceValue = s.forceValue;
        e.subject = {s.subject, s.subjectLength};
        proto::Write(w, e);
    }
}

// Break and ForceReturn must not outlive the client that asked for them.
inline void DowngradeOnDisconnect() {
    g_revision = 0;  // the next client numbers its configurations from 1
    for (uint32_t i = 0; i < book::kCount; ++i)
        if (g_probes[i].mode == proto::ProbeMode::ForceReturn || g_probes[i].mode == proto::ProbeMode::Break)
            g_probes[i].mode = proto::ProbeMode::Trace;
}

}  // namespace purah::config
