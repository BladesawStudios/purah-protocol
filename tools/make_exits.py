"""Writes probe/src/book_exits.hpp: how to tell which way each mapped function returns false.

    python tools/make_exits.py <data/game/version/return_sites.tsv> <probe/src/book_exits.hpp>

return_sites.tsv comes from tools/ghidra/ExportReturnSites.py: every EDGE into a block that returns false, numbered per function in address order.
Two kinds of exit are instrumented:

  hook   a block that falls into the failure block: an ordinary inline hook (a stub that records the exit).
  patch  a branch (b, b.cond, cbz, cbnz, tbz, tbnz) one of whose outcomes is the failure block. An inline hook cannot sit on a branch, so the module
         replaces the branch with `b stub`; the stub makes the same decision with the same condition, records the exit on the failing outcome, and
         jumps on to where the original branch would have gone (addresses filled in at install, from the image base).

The module only records "function F left through exit N". What an exit means is the client's business (return_sites.tsv and exits.psv in the data
folder). A missing return_sites.tsv gives an empty table.
"""
import os
import sys

sites_file, target = sys.argv[1:3]

CONDITIONS = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def register(number, wide):
    return ("xzr" if wide else "wzr") if number == 31 else ("x%d" if wide else "w%d") % number


def decode(word, address):
    """(branch text with {label} for the target, unconditional, target address), or None when the word is not a branch the stub can copy."""
    if (word >> 26) == 0b000101:
        return ("", True, address + signed(word & 0x3FFFFFF, 26) * 4)
    if (word & 0xFF000010) == 0x54000000:
        return ("b.%s {label}" % CONDITIONS[word & 0xF], False, address + signed((word >> 5) & 0x7FFFF, 19) * 4)
    if (word & 0x7E000000) == 0x34000000:
        name = "cbnz" if (word >> 24) & 1 else "cbz"
        return ("%s %s, {label}" % (name, register(word & 0x1F, bool(word >> 31))), False, address + signed((word >> 5) & 0x7FFFF, 19) * 4)
    if (word & 0x7E000000) == 0x36000000:
        name = "tbnz" if (word >> 24) & 1 else "tbz"
        bit = ((word >> 31) << 5) | ((word >> 19) & 0x1F)
        return ("%s %s, #%d, {label}" % (name, register(word & 0x1F, bit >= 32), bit), False, address + signed((word >> 5) & 0x3FFF, 14) * 4)
    return None


rows = []
if os.path.exists(sites_file):
    for line in open(sites_file, encoding="utf-8"):
        p = line.rstrip("\r\n").split("\t")
        if len(p) < 9 or p[0] == "function":
            continue
        ordinal = int(p[2])
        if ordinal == 0:
            continue
        rows.append({"function": int(p[0], 16), "ordinal": ordinal, "offset": int(p[3], 16), "mode": p[6],
                     "word": int(p[7], 16) if p[7] else 0, "edge": p[8]})

counts = {}
for row in rows:
    counts[row["function"]] = max(counts.get(row["function"], 0), row["ordinal"])

usable = []
for row in sorted(rows, key=lambda r: (r["function"], r["ordinal"])):
    if row["mode"] == "hook":
        usable.append(row)
    elif row["mode"] == "patch":
        decoded = decode(row["word"], row["offset"])
        if decoded is not None:
            row["decoded"] = decoded
            usable.append(row)

functions = sorted({r["function"] for r in usable})
func_of = {f: i for i, f in enumerate(functions)}
hooks = [r for r in usable if r["mode"] == "hook"]
patches = [r for r in usable if r["mode"] == "patch"]
for k, r in enumerate(hooks):
    r["slot"] = k
for k, r in enumerate(patches):
    r["slot"] = k
exit_id = {id(r): i for i, r in enumerate(usable)}


def record(identifier, func):
    offset = func * 8
    return ["adrp  x16, purah_exit_hits+%d" % offset, "add   x16, x16, :lo12:purah_exit_hits+%d" % offset,
            "mrs   x17, tpidrro_el0", "lsr   x17, x17, #4", "str   w17, [x16]", "mov   w17, #%d" % identifier, "strh  w17, [x16, #4]"]


def jump(slot, which):
    offset = slot * 16 + which * 8
    return ["adrp  x17, purah_edge_targets+%d" % offset, "ldr   x17, [x17, :lo12:purah_edge_targets+%d]" % offset, "br    x17"]


asm = [".text", ".balign 4", ".global purah_exit_common", "purah_exit_common:", "mov   w1, w16", "b     purah_exit_dispatch"]
for r in hooks:
    asm += [".balign 4", ".global purah_exit_stub_%d" % r["slot"], "purah_exit_stub_%d:" % r["slot"], "mov   w16, #%d" % exit_id[id(r)], "b     purah_exit_common"]
for r in patches:
    text, unconditional, _ = r["decoded"]
    k, identifier, func = r["slot"], exit_id[id(r)], func_of[r["function"]]
    asm += [".balign 4", ".global purah_edge_stub_%d" % k, "purah_edge_stub_%d:" % k]
    if unconditional:
        asm += record(identifier, func) + jump(k, 0)
    else:
        asm.append(text.format(label=".Lpurah_taken_%d" % k))
        if r["edge"] == "notTaken":
            asm += record(identifier, func)
        asm += jump(k, 1)
        asm.append(".Lpurah_taken_%d:" % k)
        if r["edge"] == "taken":
            asm += record(identifier, func)
        asm += jump(k, 0)

out = ["// GENERATED by tools/make_exits.py. Do not edit.", "#pragma once", "#include <cstdint>", ""]
out += ['asm(R"(', "\n".join(a if a.endswith(":") else "    " + a for a in asm), ')");', "", 'extern "C" {']
out += ["void purah_exit_stub_%d();" % r["slot"] for r in hooks] + ["void purah_edge_stub_%d();" % r["slot"] for r in patches]
out += ["}", "", "namespace purah::book {", "",
        "// offset: the instruction hooked or patched. function: the function's offset. ordinal/count: this exit's number and how many exits the function",
        "// has (counting the ones that cannot be instrumented). func: index into kFunctions. mode: 0 hook, 1 patch. slot: index into kExitStubs",
        "// or kEdgeStubs. word: the branch's original instruction (patch). target: where the branch goes when taken (patch).",
        "struct Exit { uint32_t offset; uint32_t function; uint16_t ordinal; uint16_t count; uint16_t func; uint8_t mode; uint16_t slot; uint32_t word; uint32_t target; };",
        "using StubFn = void (*)();", "",
        "constexpr uint32_t kExitCount = %d;" % len(usable),
        "constexpr uint32_t kHookCount = %d;" % len(hooks),
        "constexpr uint32_t kPatchCount = %d;" % len(patches),
        "constexpr uint32_t kFunctionCount = %d;" % len(functions), "",
        "constexpr uint32_t kFunctions[%d] = {%s};" % (max(1, len(functions)), ", ".join("0x%X" % f for f in functions) if functions else "0"), "",
        "constexpr Exit kExits[%d] = {" % max(1, len(usable))]
for r in usable:
    is_patch = r["mode"] == "patch"
    out.append("    {0x%X, 0x%X, %d, %d, %d, %d, %d, 0x%08X, 0x%X}," % (
        r["offset"], r["function"], r["ordinal"], counts[r["function"]], func_of[r["function"]], 1 if is_patch else 0, r["slot"],
        r["word"] if is_patch else 0, (r["decoded"][2] if is_patch else 0)))
if not usable:
    out.append("    {0, 0, 0, 0, 0, 0, 0, 0, 0},")
out += ["};", "", "constexpr StubFn kExitStubs[%d] = {" % max(1, len(hooks))]
out += ["    &purah_exit_stub_%d," % r["slot"] for r in hooks] or ["    nullptr,"]
out += ["};", "", "constexpr StubFn kEdgeStubs[%d] = {" % max(1, len(patches))]
out += ["    &purah_edge_stub_%d," % r["slot"] for r in patches] or ["    nullptr,"]
out += ["};", "", "}  // namespace purah::book", ""]
open(target, "w", encoding="utf-8", newline="\n").write("\n".join(out))
print("%d exits instrumented (%d hooks, %d patched branches) in %d functions; %d exits listed in all" % (len(usable), len(hooks), len(patches), len(functions), len(rows)))
