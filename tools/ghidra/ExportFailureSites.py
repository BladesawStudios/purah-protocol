# Finds the places where actor-system functions return false, and what led there. TotK 1.2.1.
#
# Run from Ghidra's Script Manager after ExportDebuggerSymbols.py. Asks for an output folder and writes
#
#   failure_sites.tsv   class<TAB>method<TAB>site<TAB>return_block<TAB>call_before<TAB>strings
#
# Every component stage (preloadPrepare / initialize / postInitialize) and every function in LIFECYCLE below
# is a bool, and a failure is a block that sets w0 to zero and returns. For each such block this lists:
#   site          the branch that reaches the block (or the block itself when it is reached by falling through)
#   return_block  the instruction that sets w0 = 0
#   call_before   the nearest `bl` before the site, by name: "fails right after <this> was called"
#   strings       defined strings referenced between that call and the site (names, paths, keys)
# These are candidate explainers for the symbol book: a failing address becomes "after Foo::load returned 0,
# near 'ContactCollectionName'". They are candidates, not conclusions: read the function before trusting one.
#
# Heuristic limits: only `mov w0,wzr` and `mov w0,#0` are recognised as "return false"; a function that
# returns false through another encoding is missed; shared epilogues give one row per incoming branch.
#
# @category Prism.Debugger

IMAGE_BASE = 0x7100000000

STAGE_METHODS = ("preloadPrepare", "initialize", "postInitialize")

LIFECYCLE = [
    "engine::actor::ActorBase::initialize",
    "engine::actor::ActorBase::initializeActor_",
    "engine::actor::ActorBase::initializeComponent",
    "engine::actor::ActorInfo::loadActorInfo",
    "engine::actor::ActorInfo::loadActorParam",
    "engine::component::GameParameterTable::loadComponents",
    "engine::ai::AIControllerSet::initialize",
    "phive::ControllerSetConfig::initialize",
    "phive::ControllerSet::initialize",
    "phive::CreateControllerSetConfig",
    "phive::CreateControllerSet",
    "phive::CreateRigidBodyControllerEntity",
    "phive::CreateRigidBodyEntity",
    "ares::ResourceUnit::loadFile",
    "ares::ResourceUnit::initializeResource",
    "game::scene::component::LimiterActorCountMgr::registerActor",
]

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refs = currentProgram.getReferenceManager()


def off(address):
    return address.getOffset() - IMAGE_BASE


def is_actor_component(name):
    if not name.startswith(("engine::component::", "game::component::")) or name.count("::") != 2:
        return False
    return not name.endswith(("Param", "Ref", "Mgr"))


def name_of(address):
    function = fm.getFunctionAt(address)
    return function.getName(True) if function is not None else "FUN_%x" % off(address)


def string_at(ref):
    data = listing.getDataAt(ref.getToAddress())
    if data is not None and data.hasStringValue() and data.getValue() is not None:
        return str(data.getValue())
    return None


def is_false_return(instruction):
    if instruction.getMnemonicString().lower() != "mov":
        return False
    if instruction.getDefaultOperandRepresentation(0) != "w0":
        return False
    return instruction.getDefaultOperandRepresentation(1) in ("wzr", "#0x0", "0x0")


def sites_in(function):
    instructions = list(listing.getInstructions(function.getBody(), True))
    rows = []
    last_call, last_call_index = "", -1
    for index, instruction in enumerate(instructions):
        if instruction.getMnemonicString().lower() == "bl":
            flows = instruction.getFlows()
            if flows:
                last_call, last_call_index = name_of(flows[0]), index
        if not is_false_return(instruction):
            continue
        incoming = [r.getFromAddress() for r in refs.getReferencesTo(instruction.getAddress())
                    if r.getReferenceType().isFlow() and not r.getReferenceType().isFallthrough()]
        for site in incoming or [instruction.getAddress()]:
            call, strings = "", []
            start = None
            for back in range(len(instructions) - 1, -1, -1):
                if instructions[back].getAddress().compareTo(site) <= 0:
                    start = back
                    break
            if start is not None:
                for k in range(start, max(start - 80, -1), -1):
                    candidate = instructions[k]
                    if candidate.getMnemonicString().lower() == "bl":
                        flows = candidate.getFlows()
                        call = name_of(flows[0]) if flows else ""
                        break
                    for ref in candidate.getReferencesFrom():
                        text = string_at(ref)
                        if text is not None and text not in strings:
                            strings.append(text)
            rows.append((off(site), off(instruction.getAddress()), call, strings))
    return rows


folder = askDirectory("Output folder for failure_sites.tsv", "Select")
targets = []
for function in fm.getFunctions(True):
    full = function.getName(True)
    marker = full.rfind("::")
    if marker < 0:
        continue
    klass, method = full[:marker], full[marker + 2:]
    if full in LIFECYCLE or (method in STAGE_METHODS and is_actor_component(klass)):
        targets.append((klass, method, function))

TEST_MNEMONICS = ("tbz", "tbnz", "cbz", "cbnz")


def callee_of(instructions, index):
    # A direct call names its target; an indirect one (blr) is described by the vtable slot loaded just before it.
    instruction = instructions[index]
    if instruction.getMnemonicString().lower() == "bl":
        flows = instruction.getFlows()
        return name_of(flows[0]) if flows else "?"
    for k in range(index - 1, max(index - 6, -1), -1):
        text = str(instructions[k])
        if text.lower().startswith("ldr") and "#0x" in text:
            return "indirect slot+0x%s" % text.split("#0x")[-1].split("]")[0].strip()
    return "indirect"


def strings_before(instructions, index, window=40):
    found = []
    for k in range(index, max(index - window, -1), -1):
        for ref in instructions[k].getReferencesFrom():
            text = string_at(ref)
            if text is not None and text not in found:
                found.append(text)
    return found


def checked_calls_in(function):
    # Every call whose result (w0/x0) is tested within the next few instructions: the places a callee's
    # failure is noticed. The branch target says where the failure goes.
    instructions = list(listing.getInstructions(function.getBody(), True))
    rows = []
    for index, instruction in enumerate(instructions):
        if instruction.getMnemonicString().lower() not in ("bl", "blr"):
            continue
        for k in range(index + 1, min(index + 5, len(instructions))):
            test = instructions[k]
            if test.getMnemonicString().lower() not in TEST_MNEMONICS:
                continue
            if test.getDefaultOperandRepresentation(0) not in ("w0", "x0"):
                continue
            flows = test.getFlows()
            target = off(flows[0]) if flows else 0
            rows.append((off(instruction.getAddress()), callee_of(instructions, index), off(test.getAddress()),
                         test.getMnemonicString().lower(), target, strings_before(instructions, index)))
            break
    return rows


checked = 0
with open(folder.getAbsolutePath() + "/checked_calls.tsv", "w") as out:
    out.write("class\tmethod\tcall\tcallee\ttest\ttest_kind\tbranch_target\tstrings\n")
    for klass, method, function in targets:
        try:
            rows = checked_calls_in(function)
        except Exception as problem:
            println("skipped %s::%s: %s" % (klass, method, problem))
            continue
        for call, callee, test, kind, target, strings in rows:
            out.write("%s\t%s\t%x\t%s\t%x\t%s\t%x\t%s\n" % (klass, method, call, callee, test, kind, target, " | ".join(strings[:4])))
            checked += 1
println("checked_calls.tsv: %d rows from %d functions" % (checked, len(targets)))

count = 0
with open(folder.getAbsolutePath() + "/failure_sites.tsv", "w") as out:
    out.write("class\tmethod\tsite\treturn_block\tcall_before\tstrings\n")
    for klass, method, function in targets:
        try:
            rows = sites_in(function)
        except Exception as problem:
            println("skipped %s::%s: %s" % (klass, method, problem))
            continue
        for site, block, call, strings in rows:
            out.write("%s\t%s\t%x\t%x\t%s\t%s\n" % (klass, method, site, block, call, " | ".join(strings[:6])))
            count += 1
println("failure_sites.tsv: %d rows from %d functions" % (count, len(targets)))
