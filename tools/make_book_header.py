"""Turns the symbol book of a game version into probe/src/book_data.hpp.

    python tools/make_book_header.py <data/game/version> <tools/ghidra folder> <probe/src/book_data.hpp>

The version folder supplies book.tsv, steps.psv, components.psv and component_vtables.tsv; the Ghidra folder supplies failure_sites.tsv and the
bulk decompile (exported/decomp_*.c).

Per row the module needs an offset, a kind, how to find the actor the call is about, whether the row opens a thread scope
(see probe/src/subject.hpp), and whether a zero return means failure. The client keeps the names. The probe id is the row's
position among the data rows, so call sites stay in place.

How each fact is decided (all from the books, nothing guessed per row):
  * resolver  - by the class the function belongs to: BaseProc / ActorBase / GameActor methods take the actor as `this`
                (name at +0x18, length at +0x20); component methods take the component, whose actor is at +0x18;
                ActorMgr::requestCreateActor* take a char** name in x1.
  * scope     - the functions whose `this` is the actor for the whole of its init: BaseProc::initialize,
                ActorBase::initialize, initializeActor_, initializeComponent.
  * failZero  - the function has a recorded return-false site (tools/ghidra/failure_sites.tsv), or it returns a pointer and
                the decompile returns a value and has a `return 0` path in a group where that means failure (not predicates such as isCalc), or (for a call site) its book note says a false return fails.
  * noReturn  - a call site whose next instruction tests the result itself (tbz/tbnz/cbz) and so cannot take a second hook.
"""
import re
import sys

version, ghidra, target = sys.argv[1:4]
source = version + "/book.tsv"
steps_file = version + "/steps.psv"
components_file = version + "/components.psv"
vtables_file = version + "/component_vtables.tsv"

HEAD = re.compile(r"^//// ([0-9a-f]+) (\S+) \((\d+) bytes\)")
NOTE_MARKERS = ("false", "null", "fail", "refus")
FAIL_GROUPS = {"create", "baseproc", "actorinit", "actorinfo", "gameparam", "params", "afterinit", "resource", "physics"}
# A zero here means "nothing to do" or "already there", not a failure.
BENIGN_ZERO = {"requestSleep", "requestPause", "tryAddDependency"}
NO_RETURN = {0x7FD904, 0xE59DE8, 0xD5F04C}   # the instruction after the blr is a tbz on w0 (disassembled)
SCOPE_NAMES = {"shaft::baseproc::BaseProc::initialize", "engine::actor::ActorBase::initialize",
               "engine::actor::ActorBase::initializeActor_", "engine::actor::ActorBase::initializeComponent"}


def failure_sites():
    found = set()
    for line in open(ghidra + "/failure_sites.tsv", encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) > 2 and p[0] != "class":
            found.add(p[0] + "::" + p[1])
    return found


def zero_returners():
    """Offsets of functions that return a value and have a path that returns zero (false or null), from the bulk decompile."""
    found = set()
    for name in ("baseproc", "actor", "components", "model", "resource", "phive", "ai", "links", "events", "lod"):
        try:
            handle = open("%s/exported/decomp_%s.c" % (ghidra, name), encoding="utf-8", errors="replace")
        except OSError:
            continue
        current, typed, zero, void = None, False, False, False
        for line in handle:
            m = HEAD.match(line)
            if m:
                if current is not None and typed and zero and not void:
                    found.add(current)
                current, typed, zero, void = int(m.group(1), 16), False, False, False
            elif current is not None:
                if not typed and line.strip() and not line.startswith(("{", "}", " ")):
                    typed = True
                    void = bool(re.match(r"^(void|float|double)", line))
                if re.search(r"return (\(\w[\w ]*\**\))?0(x0)?;", line):
                    zero = True
        if current is not None and typed and zero and not void:
            found.add(current)
    return found


def resolver_for(name):
    if name.startswith(("engine::actor::ActorMgr::requestCreateActorAsync", "engine::actor::ActorMgr::requestCreateActorSync")):
        return "NameArg"
    cls = name.rsplit("::", 1)[0]
    if cls == "engine::actor::ActorInfo" and name.endswith(("::loadActorInfo", "::loadActorParam")):
        return "InfoName"
    if cls.endswith(("::PreCalcJob", "::PostCalcJob", "::SleepCalcJob")):
        return "None"
    if cls in ("shaft::baseproc::BaseProc", "engine::actor::ActorBase", "game::actor::GameActor"):
        return "Proc"
    if "::component::" in cls and cls.endswith("Component"):
        return "Component"
    return "None"


sites = failure_sites()
zeros = zero_returners()
rows = []
for line in open(source, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#") or line.startswith("group\t"):
        continue
    p = line.split("\t")
    group, name, kind, offset = p[0], p[1], p[2], int(p[4], 16)
    note = p[5] if len(p) > 5 else ""
    if name == "sead::NoticeContext::NoticeContext":
        k = "Notice"
    elif name == "xlink2::System::addError":
        k = "LinkError"
    elif kind == "site":
        k = "Site"
    else:
        k = "Function"
    method = name.rsplit("::", 1)[-1]
    predicate = method.startswith(("is", "get", "calc", "check", "find", "has", "parse", "can")) or method in BENIGN_ZERO
    judged = group in FAIL_GROUPS and not predicate
    fail = (k == "Function" and (name in sites or (judged and offset in zeros))) or (k == "Site" and any(m in note.lower() for m in NOTE_MARKERS))
    scope = k == "Function" and name in SCOPE_NAMES
    rows.append((offset, k, resolver_for(name) if k == "Function" else "None", scope, fail, offset in NO_RETURN, name))

def cpp(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


steps = []
offset_row = {}
for i, r in enumerate(rows):
    offset_row.setdefault(r[0], i)
for line in open(steps_file, encoding="utf-8"):
    line = line.rstrip("\r\n")
    if not line or line.startswith("#"):
        continue
    p = line.split("|")
    if len(p) != 7:
        raise SystemExit("steps.psv: seven columns needed: " + line[:60])
    off = int(p[0], 16)
    if off not in offset_row:
        raise SystemExit("steps.psv: %s is not in the book" % p[0])
    steps.append((offset_row[off], p[1], p[2], p[3], p[4], p[5], p[6]))
row_step = {s[0]: i for i, s in enumerate(steps)}
PHASES = []
for s in steps:
    if s[1] not in PHASES:
        PHASES.append(s[1])

vtables = []
for line in open(vtables_file, encoding="utf-8"):
    p = line.rstrip("\n").split("\t")
    if len(p) > 2 and p[0] != "vptr_offset":
        vtables.append((int(p[0], 16), p[1].rsplit("::", 1)[-1]))

fnv = 0x811C9DC5
# The hash covers the book's offsets and then the step catalog's, so a module and a Prism built from different step lists disagree.
for offset in [r[0] for r in rows] + [rows[s[0]][0] for s in steps]:
    for b in offset.to_bytes(8, "little"):
        fnv = ((fnv ^ b) * 0x01000193) & 0xFFFFFFFF

out = ["// GENERATED by tools/make_book_header.py from the symbol book. Do not edit.",
       "#pragma once", "#include <cstdint>", "",
       "namespace purah::book {", "",
       "enum class Kind : uint8_t { Function, Site, Notice, LinkError };",
       "enum class Resolver : uint8_t { None, Proc, Component, NameArg, InfoName };", "",
       "constexpr uint16_t kNoStep = 0xFFFF;", "struct Row { uint32_t offset; Kind kind; Resolver resolver; bool scope; bool failZero; bool noReturn; uint16_t step; };", "",
       "constexpr uint32_t kCount = %d;" % len(rows),
       "constexpr uint32_t kHash = 0x%08X;" % fnv, "",
       "constexpr Row kRows[kCount] = {"]
for i, (offset, k, r, scope, fail, noret, name) in enumerate(rows):
    out.append("    {0x%X, Kind::%s, Resolver::%s, %s, %s, %s, %s},  // %d %s" % (
        offset, k, r, str(scope).lower(), str(fail).lower(), str(noret).lower(),
        str(row_step[i]) if i in row_step else "kNoStep", i, name))
out += ["};", ""]
out += ["enum class Rule : uint8_t { Zero, Code, Warn, None };",
        "enum class Named : uint8_t { No, Arg0, Result, Path1, ResultStr, Item };",
        "struct Step { uint32_t row; uint8_t phase; Rule rule; Named named; bool root; bool request; bool container; bool sret; uint8_t stage; const char* label; const char* meaning; };", "",
        "constexpr uint32_t kStepCount = %d;" % len(steps),
        "constexpr const char* kPhases[] = {%s};" % ", ".join(cpp(x) for x in PHASES), "",
        "constexpr Step kSteps[kStepCount] = {"]
for s in steps:
    rule = {"zero": "Zero", "code": "Code", "warn": "Warn", "none": "None"}[s[2]]
    named = {"-": "No", "arg0": "Arg0", "result": "Result", "path1": "Path1", "resultstr": "ResultStr", "item": "Item"}[s[3]]
    stage = 1 if "stage=preload" in s[4] else 2 if "stage=initialize" in s[4] else 3 if "stage=post" in s[4] else 0
    out.append("    {%d, %d, Rule::%s, Named::%s, %s, %s, %s, %s, %d, %s, %s}," % (
        s[0], PHASES.index(s[1]), rule, named, str("root" in s[4]).lower(), str("request" in s[4]).lower(),
        str("container" in s[4]).lower(), str("sret" in s[4]).lower(), stage, cpp(s[5]), cpp(s[6])))
reasons = []
for line in open(components_file, encoding="utf-8"):
    line = line.rstrip("\r\n")
    if line and not line.startswith("#"):
        name, _, text = line.partition("|")
        reasons.append((name, text))
out += ["};", "", "struct ComponentReason { const char* name; const char* text; };",
        "constexpr uint32_t kReasonCount = %d;" % len(reasons), "constexpr ComponentReason kReasons[kReasonCount] = {"]
for name, text in reasons:
    out.append("    {%s, %s}," % (cpp(name), cpp(text)))
stage_functions = []
for line in open(vtables_file, encoding="utf-8"):
    cols = line.rstrip(chr(10)).split(chr(9))
    if len(cols) > 12 and cols[0] != "vptr_offset":
        def slot(i):
            return int(cols[i].split(":")[0], 16) if cols[i] != "-" and ":" in cols[i] else 0
        stage_functions.append((cols[1].rsplit("::", 1)[-1], slot(6), slot(11), slot(12)))
out += ["};", "", "struct ComponentStages { const char* name; uint32_t preload; uint32_t initialize; uint32_t post; };",
        "constexpr uint32_t kStageCount = %d;" % len(stage_functions), "constexpr ComponentStages kComponentStages[kStageCount] = {"]
for name, a, b, c in stage_functions:
    out.append("    {%s, 0x%X, 0x%X, 0x%X}," % (cpp(name), a, b, c))
out += ["};", "", "struct Vtable { uint32_t offset; const char* name; };",
        "constexpr uint32_t kVtableCount = %d;" % len(vtables), "constexpr Vtable kVtables[kVtableCount] = {"]
for off, name in vtables:
    out.append("    {0x%X, %s}," % (off, cpp(name)))
out += ["};", "", "}  // namespace purah::book", ""]
open(target, "w", encoding="utf-8", newline="\n").write("\n".join(out))
print("%d rows, %d steps, %d vtables, hash %08X, %d failZero, %d scope, %d resolvable" % (
    len(rows), len(steps), len(vtables), fnv, sum(r[4] for r in rows), sum(r[3] for r in rows), sum(1 for r in rows if r[2] != "None")))
