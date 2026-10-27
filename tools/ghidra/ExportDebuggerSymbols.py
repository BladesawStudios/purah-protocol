# Exports what the live debugger's symbol book needs from the open Ghidra program (TotK 1.2.1).
#
# Run it from Ghidra's Script Manager. It asks for an output folder and writes:
#
#   functions.tsv          offset<TAB>name        every function; offset = address minus the image base
#   component_slots.tsv    one row per component class, the slots the actor init loop calls
#   component_vtables.tsv  the same classes, the whole vtable from +0x00 to +0xE0
#   component_report.txt   classes with no vtable found, classes with more than one candidate, counts
#   scene_candidates.tsv   scene components (the *Mgr classes): raw vtable neighbourhoods per candidate vptr
#
# How the vtables are found. Every component class overrides some of the methods below, and each override
# is stored at a fixed slot of the class's vtable (the slot layout was read from PhysicsComponent and Death). Each data reference to one of a class's own methods therefore
# votes for "the vtable pointer is this address minus that slot". The vptr with the most votes wins, and
# the vote count is written next to it so a weak result is visible. Seeding from many methods (not only
# postInitialize) is what lets this find classes that inherit the base initialize/postInitialize.
#
#   +0x00 checkDerivedRuntimeTypeInfo   +0x08 getRuntimeTypeInfo
#   +0x20 preloadPrepare                +0x38 getBlackboardTables   +0x40 getInitializeCount
#   +0x48 initialize                    +0x50 postInitialize        +0x58 finalize
#   +0xC8 getComponentName              +0xD0 getHostIOIcon
#
# Offsets everywhere are what WiiXLaunch uses (address - image base).
#
# @category Prism.Debugger

from collections import defaultdict

IMAGE_BASE = 0x7100000000

VOTING = {
    "checkDerivedRuntimeTypeInfo": 0x00,
    "getRuntimeTypeInfo": 0x08,
    "preloadPrepare": 0x20,
    "getBlackboardTables": 0x38,
    "getInitializeCount": 0x40,
    "initialize": 0x48,
    "postInitialize": 0x50,
    "finalize": 0x58,
    "getComponentName": 0xC8,
    "getHostIOIcon": 0xD0,
}

COLUMNS = [
    (0x20, "preloadPrepare"),
    (0x38, "getBlackboardTables"),
    (0x40, "getInitializeCount"),
    (0x48, "initialize"),
    (0x50, "postInitialize"),
    (0x58, "finalize"),
    (0xC8, "getComponentName"),
    (0xD0, "getHostIOIcon"),
]

VTABLE_SPAN = 0xE0


def off(address):
    return address.getOffset() - IMAGE_BASE


def is_component_class(name):
    return "component" in name.lower()


# Actor components are engine::component::X or game::component::X. Their params (X Param), refs, managers
# and the interface/base classes are not components and would only add noise.
ACTOR_NAMESPACES = ("engine::component::", "game::component::")
NOT_COMPONENTS = ("Param", "Ref", "Mgr")
INTERFACES = ("engine::component::IActorComponent", "engine::component::ActorComponentSet")


def is_actor_component(name):
    if not name.startswith(ACTOR_NAMESPACES) or name.count("::") != 2 or name in INTERFACES:
        return False
    return not name.endswith(NOT_COMPONENTS)


# Scene components (the *Mgr classes) have a different vtable layout from actor components, so the slots
# above are wrong for them. They are written raw, per candidate vptr, for the layout to be read off.
def is_scene_component(name):
    return "::scene::component::" in name and name.count("::") >= 3


def cell(memory, fm, vptr, slot):
    try:
        target = memory.getLong(vptr.add(slot))
        function = fm.getFunctionAt(toAddr(target))
        if function is None:
            return "-"
        return "%x:%s" % (target - IMAGE_BASE, function.getName(True))
    except Exception:
        return "-"


folder = askDirectory("Output folder for debugger exports", "Select")
base = folder.getAbsolutePath()

fm = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
refs = currentProgram.getReferenceManager()

count = 0
with open(base + "/functions.tsv", "w") as out:
    for function in fm.getFunctions(True):
        out.write("%x\t%s\n" % (off(function.getEntryPoint()), function.getName(True)))
        count += 1
println("functions.tsv: %d functions" % count)

# class -> {vptr offset: votes}, and class -> number of seed methods it has
votes = defaultdict(lambda: defaultdict(int))
seeds = defaultdict(int)
classes_seen = set()
vptrs = {}

for function in fm.getFunctions(True):
    full = function.getName(True)
    marker = full.rfind("::")
    if marker < 0:
        continue
    klass, method = full[:marker], full[marker + 2:]
    if not is_component_class(klass):
        continue
    classes_seen.add(klass)
    if method not in VOTING:
        continue
    slot = VOTING[method]
    seeds[klass] += 1
    for ref in refs.getReferencesTo(function.getEntryPoint()):
        if not ref.getReferenceType().isData():
            continue
        vptr = ref.getFromAddress().subtract(slot)
        votes[klass][vptr.getOffset()] += 1
        vptrs[vptr.getOffset()] = vptr

rows, slot_rows, missing, contested, scene_rows = [], [], [], [], []
for klass in sorted(classes_seen):
    if is_scene_component(klass) and klass in votes:
        for key, count in sorted(votes[klass].items(), key=lambda kv: -kv[1]):
            vptr = vptrs[key]
            scene_rows.append("%x\t%s\t%d\t%s" % (off(vptr), klass, count,
                                                  "\t".join(cell(memory, fm, vptr, s) for s in range(-0x10, 0x68, 8))))
        continue
    if not is_actor_component(klass):
        continue
    if klass not in votes:
        if seeds[klass]:
            missing.append(klass)
        continue
    ranked = sorted(votes[klass].items(), key=lambda kv: -kv[1])
    best_key, best_votes = ranked[0]
    if len(ranked) > 1:
        contested.append("%s: %s" % (klass, ", ".join("%x=%d" % (k - IMAGE_BASE, v) for k, v in ranked)))
    vptr = vptrs[best_key]
    cells = [cell(memory, fm, vptr, slot) for slot, _ in COLUMNS]
    slot_rows.append("%x\t%s\t%d\t%d\t%s" % (off(vptr), klass, best_votes, seeds[klass], "\t".join(cells)))
    whole = [cell(memory, fm, vptr, s) for s in range(0, VTABLE_SPAN + 8, 8)]
    rows.append("%x\t%s\t%s" % (off(vptr), klass, "\t".join(whole)))

head = "vptr_offset\tclass\tvotes\tseed_methods\t%s\n" % "\t".join("%s(+0x%x)" % (n, s) for s, n in COLUMNS)
with open(base + "/component_slots.tsv", "w") as out:
    out.write(head)
    for row in slot_rows:
        out.write(row + "\n")

with open(base + "/component_vtables.tsv", "w") as out:
    out.write("vptr_offset\tclass\t%s\n" % "\t".join("+0x%x" % s for s in range(0, VTABLE_SPAN + 8, 8)))
    for row in rows:
        out.write(row + "\n")

with open(base + "/scene_candidates.tsv", "w") as out:
    out.write("vptr_offset\tclass\tvotes\t%s\n" % "\t".join("%+#x" % s for s in range(-0x10, 0x68, 8)))
    for row in scene_rows:
        out.write(row + "\n")

with open(base + "/component_report.txt", "w") as out:
    out.write("component classes seen (any method): %d\n" % len(classes_seen))
    out.write("with a vtable found: %d\n" % len(slot_rows))
    out.write("had seed methods but no vtable reference: %d\n" % len(missing))
    out.write("with more than one candidate vptr: %d\n\n" % len(contested))
    out.write("== no vtable found (had seed methods) ==\n")
    for klass in missing:
        out.write(klass + "\n")
    out.write("\n== contested (vptr offset = votes) ==\n")
    for line in contested:
        out.write(line + "\n")

println("component_slots.tsv: %d classes; %d without a vtable reference; %d contested" % (len(slot_rows), len(missing), len(contested)))

# ---- scene components ---------------------------------------------------------------------------
# ISceneComponent layout, read from BancLoadMgr / ResidentActorMgr / OwnedHorseMgr in scene_candidates.tsv:
# +0x00 checkDerivedRuntimeTypeInfo, +0x08 getRuntimeTypeInfo, +0x10/+0x18 destructors, +0x20 initialize,
# +0x28 start, +0x30 finalize, +0x38 update, +0x40 registerForDebug, +0x48 getName, +0x50 getHostIOIcon.
# The candidate with the most votes is the real vtable (the others are neighbouring vtables hit by the actor
# slot offsets), so it is chosen here.
SCENE_COLUMNS = [(0x20, "initialize"), (0x28, "start"), (0x30, "finalize"), (0x38, "update"), (0x48, "getName")]
scene_out = []
for klass in sorted(classes_seen):
    if not is_scene_component(klass) or klass not in votes:
        continue
    key, count = sorted(votes[klass].items(), key=lambda kv: -kv[1])[0]
    vptr = vptrs[key]
    scene_out.append("%x\t%s\t%d\t%s" % (off(vptr), klass, count,
                                         "\t".join(cell(memory, fm, vptr, s) for s, _ in SCENE_COLUMNS)))
with open(base + "/scene_slots.tsv", "w") as out:
    out.write("vptr_offset\tclass\tvotes\t%s\n" % "\t".join("%s(+0x%x)" % (n, s) for s, n in SCENE_COLUMNS))
    for row in scene_out:
        out.write(row + "\n")
println("scene_slots.tsv: %d scene components" % len(scene_out))

# ---- parameter schemas --------------------------------------------------------------------------
# Every param class describes its properties in loopProps / formatProps (and nested structs in
# loopComposites / formatComposites / loopEmbeds) as one visitor call per property with the property name
# as a C string, in declaration order. The strings referenced by each of those functions, in instruction
# order, are therefore the property names in order. Types and offsets need the decompiler and are not
# exported here. Rows: class, method, index, string.
PARAM_METHODS = ("loopProps", "formatProps", "loopComposites", "formatComposites", "loopEmbeds", "parseParameters_")
listing = currentProgram.getListing()


def strings_in(function):
    found, seen = [], set()
    for instruction in listing.getInstructions(function.getBody(), True):
        for ref in instruction.getReferencesFrom():
            if not ref.getReferenceType().isData():
                continue
            data = listing.getDataAt(ref.getToAddress())
            if data is None or not data.hasStringValue():
                continue
            value = data.getValue()
            if value is None:
                continue
            key = (instruction.getAddress().getOffset(), str(value))
            if key in seen:
                continue
            seen.add(key)
            found.append(str(value))
    return found


schema_rows, schema_functions = 0, 0
with open(base + "/param_schemas.tsv", "w") as out:
    out.write("class\tmethod\tindex\tstring\n")
    for function in fm.getFunctions(True):
        full = function.getName(True)
        marker = full.rfind("::")
        if marker < 0 or full[marker + 2:] not in PARAM_METHODS:
            continue
        schema_functions += 1
        for index, text in enumerate(strings_in(function)):
            out.write("%s\t%s\t%d\t%s\n" % (full[:marker], full[marker + 2:], index, text))
            schema_rows += 1
println("param_schemas.tsv: %d strings from %d functions" % (schema_rows, schema_functions))
