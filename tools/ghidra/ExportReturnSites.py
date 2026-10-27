# Finds every way a function can return false, so the debugger can say which check failed.
#
# Run from Ghidra's Script Manager (Jython 2) and pick the version's data folder (data/<game>/<version>). It reads
#
#   exit_functions.txt       the step functions to map, one "offset name" per line
#   component_vtables.tsv    the class vtables from ExportDebuggerSymbols.py; the preloadPrepare, initialize and postInitialize
#                            function of every component class is mapped as well
#
# and writes
#
#   return_sites.tsv         one row per exit: function, name, ordinal, exit, hookable, kind, mode, word, edge
#   return_sites_report.tsv  one row per function: how many failure edges the search saw, how many exits it made of them, and why it dropped the rest
#                            (a working file: it quotes the functions' return statements, so it is not committed)
#
# A function usually has a few blocks that carry the value 0 into a return (failure blocks) and many branches that jump into them. Each of those
# branches is a failure mode: it is what a failing run takes. The exits are therefore the edges into the failure blocks.
#
#   exit      the address of the branch instruction (mode patch) or of the instruction to hook (mode hook)
#   mode      patch  a branch (b, b.cond, cbz, cbnz, tbz, tbnz) one of whose outcomes leads to the failure block; the module replaces it with a
#                    jump to a stub that makes the same decision and records the exit on the failing outcome
#             hook   a block that falls into the failure block and has no other way out; an inline hook at its first safe instruction
#             none   listed so the numbering is complete, but indistinguishable from other paths (hookable 0)
#   word      the branch instruction's four bytes as a hex word; the module checks them before patching
#   edge      taken: the failure block is the branch's target; notTaken: it is the fall-through
#
# A failure block entered through a block that is only a jump is looked through, so the exit is the real decision. Exits are numbered per
# function in address order; the debugger reports "failure mode ordinal/count". exits.psv in the same folder holds the reason for each.
# A function that cannot be decompiled gets one row with kind "decompile-failed" so it stays visible.
#
# @category Prism.Debugger

import re

from ghidra.app.decompiler import DecompInterface, ClangTokenGroup, ClangBreak
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

IMAGE_BASE = 0x7100000000
DECOMPILE_TIMEOUT = 600
MAX_DEPTH = 6

# Columns of component_vtables.tsv holding the stages the game calls and judges by a bool: preloadPrepare, initialize, postInitialize.
# Each cell is "offset:name".
STAGE_COLUMNS = (6, 11, 12)

# Instructions an inline hook cannot relocate because they depend on where they sit.
PC_RELATIVE = ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "adr", "adrp")
LOADS_FROM_CODE = ("ldr", "ldrsw", "prfm")
# Branches the module can replace with a stub.
PATCHABLE = ("b", "cbz", "cbnz", "tbz", "tbnz")

ZERO_TO_RESULT = re.compile(r"^(mov|movz)\s+[wx]0,\s*(wzr|xzr|#0x0|#0)$")
WRITES_RESULT = re.compile(r"^\w+\s+[wx]0,")
NOT_A_WRITE = ("st", "cmp", "cmn", "tst", "cb", "tb", "ccm", "prf")

# An instruction scan that finds more than this many times the decompiler's own failure count is noise (a huge function full of "w0 = 0; ret").
SCAN_FACTOR = 2
SCAN_SLACK = 4
# A jump chain longer than this is not a trampoline.
JUMP_DEPTH = 4

functions = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
blocks = SimpleBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()

# Why failure edges were not turned into instrumentable exits, for the function being mapped.
gaps = {}


def note_gap(reason):
    gaps[reason] = gaps.get(reason, 0) + 1


def address_of(offset):
    return toAddr(IMAGE_BASE + offset)


def name_of(function):
    return function.getName(True) if function else "?"


def printable(text):
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)


def mnemonic_of(instruction):
    return instruction.getMnemonicString().lower()


def text_of(instruction):
    return instruction.toString().lower().replace("  ", " ")


def is_branch(mnemonic):
    return mnemonic in PATCHABLE or mnemonic.startswith("b.")


def word_of(instruction):
    value = 0
    for i, b in enumerate(instruction.getBytes()):
        value |= (b & 0xFF) << (8 * i)
    return value


# ---- what the function can return, from the decompiler's p-code

def is_zero(varnode, depth=0):
    """True when the value is the constant 0 once copies and widening are looked through."""
    if depth > MAX_DEPTH or varnode is None:
        return False
    if varnode.isConstant():
        return varnode.getOffset() == 0
    definition = varnode.getDef()
    if definition is None:
        return False
    opcode = definition.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE, PcodeOp.CAST):
        return is_zero(definition.getInput(0), depth + 1)
    if opcode == PcodeOp.INT_AND:
        return is_zero(definition.getInput(0), depth + 1) or is_zero(definition.getInput(1), depth + 1)
    return False


def failure_edges(high):
    """(predecessor, join) for every edge of the decompiler's control-flow graph that carries a constant 0 into a return. A return of a
    constant 0 makes every edge into its block one; a constant 0 flowing into a join (a phi) makes the edge it flows along one."""
    found = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.RETURN or op.getNumInputs() < 2:
            continue
        value = op.getInput(1)
        block = op.getParent()
        if is_zero(value):
            if block.getInSize() == 0:
                found.append((None, block))
            for i in range(block.getInSize()):
                found.append((block.getIn(i), block))
        else:
            follow_value(value, found, 0)
    return found


def follow_value(varnode, found, depth):
    if depth > MAX_DEPTH or varnode is None or varnode.isConstant():
        return
    definition = varnode.getDef()
    if definition is None:
        return
    opcode = definition.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE, PcodeOp.CAST, PcodeOp.INT_AND):
        follow_value(definition.getInput(0), found, depth + 1)
    elif opcode == PcodeOp.MULTIEQUAL:
        join = definition.getParent()
        for i in range(definition.getNumInputs()):
            if is_zero(definition.getInput(i)):
                found.append((join.getIn(i), join))
            else:
                follow_value(definition.getInput(i), found, depth + 1)


def real_last_instruction(block):
    """The instruction of the last p-code op of a decompiler block that has one (the decompiler's own blocks can end on nothing real)."""
    found = None
    iterator = block.getIterator()
    while iterator.hasNext():
        instruction = listing.getInstructionContaining(iterator.next().getSeqnum().getTarget())
        if instruction is not None:
            found = instruction
    return found


# ---- the instruction-level control-flow graph

def prepare_body(function, results):
    """Ghidra's own body for a function can be just its entry when the code was never disassembled, so take the address ranges from the
    decompiler's blocks, disassemble them and return them as the function's body."""
    body = AddressSet()
    for block in results.getHighFunction().getBasicBlocks():
        try:
            if block.getStart().getOffset() != 0:
                body.addRange(block.getStart(), block.getStop())
        except Exception:
            pass
    body.add(function.getBody())
    for span in body.getAddressRanges():
        if listing.getInstructionContaining(span.getMinAddress()) is None:
            disassemble(span.getMinAddress())
    return body


def safe_instruction(start, stop):
    """The first instruction in [start, stop] an inline hook can sit on, or None."""
    instruction = listing.getInstructionAt(start)
    while instruction is not None and instruction.getAddress().compareTo(stop) <= 0:
        mnemonic = mnemonic_of(instruction)
        position_dependent = mnemonic in PC_RELATIVE or mnemonic.startswith("b.")
        if mnemonic in LOADS_FROM_CODE and len(instruction.getReferencesFrom()) > 0:
            position_dependent = True
        if not position_dependent:
            return instruction.getAddress()
        instruction = instruction.getNext()
    return None


def incoming(block):
    references = []
    iterator = block.getSources(monitor)
    while iterator.hasNext():
        references.append(iterator.next())
    return references


def is_only_a_jump(block):
    """True for a block that is a single unconditional jump: a shared trampoline, not a decision."""
    if block.getNumAddresses() != 4:
        return False
    instruction = listing.getInstructionAt(block.getMinAddress())
    return instruction is not None and mnemonic_of(instruction) == "b"


def entry_edges(block, depth, seen):
    """The references that enter the block, looking through blocks that are only a jump."""
    edges = []
    for reference in incoming(block):
        flow = reference.getFlowType()
        if flow.isCall() or flow.isTerminal():
            continue
        source = reference.getSourceBlock()
        key = (reference.getReferent().getOffset(), block.getMinAddress().getOffset())
        if key in seen:
            continue
        seen.add(key)
        if depth < JUMP_DEPTH and is_only_a_jump(source) and flow.isJump() and not flow.isConditional():
            edges.extend(entry_edges(source, depth + 1, seen))
        else:
            edges.append((reference, block))
    return edges


def always_failing_blocks(body):
    """Blocks that set w0 to 0 and leave the function without a call or another write to w0. The compiler duplicates an epilogue for each early
    return, so this finds failures the decompiler's shared return hides."""
    found = []
    seen = set()
    iterator = listing.getInstructions(body, True)
    while iterator.hasNext():
        instruction = iterator.next()
        if not ZERO_TO_RESULT.match(text_of(instruction)):
            continue
        block = blocks.getFirstCodeBlockContaining(instruction.getAddress(), monitor)
        if block is None or block.getMinAddress().getOffset() in seen:
            continue
        if keeps_zero(block, instruction):
            seen.add(block.getMinAddress().getOffset())
            found.append(block)
    return found


def keeps_zero(block, zero):
    last = zero
    following = zero.getNext()
    while following is not None and following.getAddress().compareTo(block.getMaxAddress()) <= 0:
        mnemonic = mnemonic_of(following)
        if mnemonic in ("bl", "blr"):
            return False
        if WRITES_RESULT.match(text_of(following)) and not mnemonic.startswith(NOT_A_WRITE):
            return False
        last = following
        following = following.getNext()
    return mnemonic_of(last) in ("ret", "b")


# ---- turning failure edges into exits. An exit is (address, mode, kind, word, edge).

def add_branch_exit(exits, instruction, edge):
    at = instruction.getAddress()
    if is_branch(mnemonic_of(instruction)):
        exits[(at.getOffset(), edge)] = (at, "patch", "branch", word_of(instruction), edge)
    else:
        exits[(at.getOffset(), edge)] = (at, "none", "branch", 0, edge)
        note_gap("branch-cannot-be-patched:" + mnemonic_of(instruction))


def block_exits(block, exits):
    """The exits that lead into a block that always fails: its entering branches, or the block itself when it is only entered by falling in."""
    edges = entry_edges(block, 0, set())
    if not edges:
        hook = safe_instruction(block.getMinAddress(), block.getMaxAddress())
        if hook is not None:
            exits[(hook.getOffset(), "entry")] = (hook, "hook", "entry", 0, "")
        else:
            note_gap("entered-only-by-falling-in-and-unhookable")
        return
    for reference, target in edges:
        at = reference.getReferent()
        instruction = listing.getInstructionAt(at)
        if instruction is None:
            continue
        if is_branch(mnemonic_of(instruction)):
            taken = target.getMinAddress().getOffset() in [f.getOffset() for f in instruction.getFlows()]
            add_branch_exit(exits, instruction, "taken" if taken else "notTaken")
            continue
        source = reference.getSourceBlock()
        hook = safe_instruction(source.getMinAddress(), source.getMaxAddress())
        if hook is not None and source.getNumDestinations(monitor) == 1:
            exits[(hook.getOffset(), "fall")] = (hook, "hook", "fall", 0, "")
        else:
            exits[(at.getOffset(), "fall")] = (at, "none", "fall", 0, "")
            note_gap("fall-in-has-no-safe-hook")


def outcome_into(predecessor, join, last):
    """Which outcome of the branch `last`, ending `predecessor`, leads to `join`: taken, notTaken, or None when it cannot be told."""
    flows = [f.getOffset() for f in last.getFlows()]
    fall_through = last.getFallThrough()
    if join.getStart().getOffset() in flows:
        return "taken"
    if fall_through is not None and fall_through.getOffset() == join.getStart().getOffset():
        return "notTaken"
    # The join can be a block the decompiler made up, with no address of its own; its graph says which outcome leads there.
    try:
        if predecessor.getTrueOut().equals(join):
            return "taken" if len(flows) > 0 else None
        if predecessor.getFalseOut().equals(join):
            return "notTaken"
    except Exception:
        pass
    return None


def edge_exit(predecessor, join, exits, depth=0):
    """The exit for the decompiler's edge predecessor -> join, found at the instruction that ends the predecessor."""
    if predecessor is None:
        raw = blocks.getFirstCodeBlockContaining(join.getStart(), monitor)
        if raw is not None:
            block_exits(raw, exits)
        else:
            note_gap("entry-block-has-no-code")
        return

    last = listing.getInstructionContaining(predecessor.getStop()) or real_last_instruction(predecessor)
    if last is None:
        # A block the decompiler made up: the failing edges are the ones entering it, or failing that the branches entering the failure block.
        if depth < JUMP_DEPTH and predecessor.getInSize() > 0:
            for i in range(predecessor.getInSize()):
                edge_exit(predecessor.getIn(i), predecessor, exits, depth + 1)
            return
        before = len(exits)
        raw = blocks.getFirstCodeBlockContaining(join.getStart(), monitor)
        if raw is not None:
            block_exits(raw, exits)
        if len(exits) == before:
            note_gap("predecessor-ends-in-no-instruction")
        return

    if predecessor.getOutSize() >= 2 and is_branch(mnemonic_of(last)):
        edge = outcome_into(predecessor, join, last)
        if edge is None:
            exits[(last.getAddress().getOffset(), "unclear")] = (last.getAddress(), "none", "branch", 0, "")
            note_gap("branch-target-is-not-the-failure-block")
        else:
            add_branch_exit(exits, last, edge)
        return

    # The predecessor has one way out, so running it is failing: the exits are the ways into it, when it is a block of its own.
    raw = blocks.getFirstCodeBlockContaining(predecessor.getStop(), monitor)
    if raw is None:
        note_gap("predecessor-has-no-block")
    elif raw.getMinAddress().equals(predecessor.getStart()):
        block_exits(raw, exits)
    else:
        exits[(raw.getMinAddress().getOffset(), "shared")] = (raw.getMinAddress(), "none", "shared", 0, "")
        note_gap("predecessor-shares-a-block")


def exits_of(function, results, body):
    """Every exit of the function in address order."""
    exits = {}
    for predecessor, join in failure_edges(results.getHighFunction()):
        edge_exit(predecessor, join, exits)
    scanned = always_failing_blocks(body)
    if len(scanned) <= SCAN_FACTOR * len(exits) + SCAN_SLACK:
        for block in scanned:
            block_exits(block, exits)
    return sorted(exits.values(), key=lambda item: item[0].getOffset())


# ---- the decompiled C, for the report

def flatten(node, out):
    if isinstance(node, ClangTokenGroup):
        for i in range(node.numChildren()):
            flatten(node.Child(i), out)
    else:
        out.append(node)


def c_lines(results):
    """The decompiled C as lines."""
    tokens = []
    flatten(results.getCCodeMarkup(), tokens)
    lines, text = [], []
    for token in tokens:
        if isinstance(token, ClangBreak):
            lines.append("".join(text).strip())
            text = []
        else:
            text.append(token.getText())
    lines.append("".join(text).strip())
    return lines


# ---- inputs and output

def read_step_functions(folder):
    """(offset, name) for each line of exit_functions.txt."""
    found = []
    for line in open(folder + "/exit_functions.txt"):
        line = line.strip()
        if line and not line.startswith("#"):
            offset, _, name = line.partition(" ")
            found.append((int(offset, 16), name.strip()))
    return found


def read_component_stages(folder):
    """(offset, name) of every component stage function in component_vtables.tsv; a function shared by several classes appears once."""
    found = {}
    for line in open(folder + "/component_vtables.tsv"):
        columns = line.rstrip("\r\n").split("\t")
        if len(columns) <= max(STAGE_COLUMNS) or columns[0] == "vptr_offset":
            continue
        for column in STAGE_COLUMNS:
            cell = columns[column]
            if cell == "-" or ":" not in cell:
                continue
            offset = int(cell.split(":")[0], 16)
            if offset not in found:
                found[offset] = cell.split(":", 1)[1]
    return sorted(found.items())


def coverage_row(offset, function, results, lines, exits, body):
    """The function's row of the report: what the search saw, what it made of it, what it dropped, and the C return statements (a function with
    no exits is explained by what it returns: a call's result, a flag, a constant)."""
    instrumentable = len([e for e in exits if e[1] != "none"])
    returns = []
    for statement in lines:
        if statement.startswith("return") and statement not in returns:
            returns.append(statement[:60])
    dropped = ",".join("%s=%d" % (k, v) for k, v in sorted(gaps.items()))
    return "%X\t%s\t%d\t%d\t%d\t%d\t%s\t%s" % (
        offset, name_of(function), len(failure_edges(results.getHighFunction())), len(always_failing_blocks(body)),
        len(exits), instrumentable, dropped, printable(" | ".join(returns[:5])))


def main():
    folder = askDirectory("The version's data folder (data/<game>/<version>)", "Select").getAbsolutePath()
    step_functions = read_step_functions(folder)
    listed = set(offset for offset, _ in step_functions)
    work = [(offset, True) for offset, _ in step_functions]
    work += [(offset, False) for offset, _ in read_component_stages(folder) if offset not in listed]

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    rows = []
    report = []
    for offset, required in work:
        function = functions.getFunctionAt(address_of(offset))
        if function is None:
            if required:
                rows.append("%X\t?\t0\t0\t0\tno-function\t\t\t" % offset)
            continue
        println("%s ..." % name_of(function))
        results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT, monitor)
        if not results.decompileCompleted():
            rows.append("%X\t%s\t0\t0\t0\tdecompile-failed\t\t\t" % (offset, name_of(function)))
            continue

        gaps.clear()
        try:
            body = prepare_body(function, results)
            lines = c_lines(results)
            exits = exits_of(function, results, body)
            report.append(coverage_row(offset, function, results, lines, exits, body))
        except Exception as problem:
            println("  error in %s: %s" % (name_of(function), problem))
            rows.append("%X\t%s\t0\t0\t0\terror\t\t\t" % (offset, name_of(function)))
            continue

        for ordinal, (address, mode, kind, word, edge) in enumerate(exits, 1):
            rows.append("%X\t%s\t%d\t%X\t%d\t%s\t%s\t%08X\t%s" % (
                offset, name_of(function), ordinal, address.getOffset() - IMAGE_BASE, 1 if mode != "none" else 0, kind, mode, word, edge))
        if not exits and required:
            rows.append("%X\t%s\t0\t0\t0\tno-exit-found\t\t\t" % (offset, name_of(function)))

    write_table(folder + "/return_sites_report.tsv", "function\tname\tfailure_edges\tzero_blocks\texits\tinstrumentable\tdrops\treturns_in_c", report)
    write_table(folder + "/return_sites.tsv", "function\tname\tordinal\texit\thookable\tkind\tmode\tword\tedge", rows)
    println("wrote %d exits for %d functions to %s" % (len(rows), len(report), folder))


def write_table(path, header, rows):
    handle = open(path, "w")
    handle.write(header + "\n")
    for row in rows:
        handle.write(row + "\n")
    handle.close()


main()
