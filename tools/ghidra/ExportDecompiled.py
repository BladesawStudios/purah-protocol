# Decompiles whole areas of the TotK 1.2.1 actor system to text files, so they can be read and searched offline.
#
# Run from Ghidra's Script Manager. It asks for an output folder and which sets to export (comma separated;
# empty means all), then writes, for each set, `decomp_<set>.c` (every function's C, one after another) and
# appends to `decomp_index.tsv` (set, offset, name, status, lines). Files are flushed function by function, so
# a set can be read while the script is still running, and a cancelled run keeps what it finished.
#
# Sets (named functions only; templates and FUN_ names are skipped):
#   model       nn::g3d2::, gsys::, agl::g3d::           the bfres / model setup and drawing
#   baseproc    shaft::baseproc::, ares::, engine::resource::   processes, the job graph, resource loading
#   actor       engine::actor::, game::actor::           actors, pre-actors, placement
#   lod         every function whose class name mentions LOD
#   components  engine::component::, game::component::   every actor component
#   ai          ai::, engine::ai::                        the AI graph
#   links       xlink2::                                  effect / sound / element links
#   events      engine::event::                           events and event actors
#   phive       phive::                                   physics
#
# Order matters if you cannot wait for everything: model, baseproc, actor, lod, then the rest.
#
# @category Prism.Debugger

import io
from ghidra.app.decompiler import DecompInterface

IMAGE_BASE = 0x7100000000
TIMEOUT_SECONDS = 40


def class_part(name):
    marker = name.rfind("::")
    return name[:marker] if marker >= 0 else ""


SETS = [
    ("model", lambda n: n.startswith(("nn::g3d2::", "gsys::", "agl::g3d::"))),
    ("baseproc", lambda n: n.startswith(("shaft::baseproc::", "ares::", "engine::resource::"))),
    ("actor", lambda n: n.startswith(("engine::actor::", "game::actor::"))),
    ("lod", lambda n: "LOD" in class_part(n)),
    ("components", lambda n: n.startswith(("engine::component::", "game::component::"))),
    ("ai", lambda n: n.startswith(("ai::", "engine::ai::"))),
    ("links", lambda n: n.startswith("xlink2::")),
    ("events", lambda n: n.startswith("engine::event::")),
    ("phive", lambda n: n.startswith("phive::")),
]

folder = askDirectory("Output folder for decompiled sets", "Select")
base = folder.getAbsolutePath()
wanted = askString("Sets", "Sets to export, comma separated, or 'all':", "all").strip()
chosen = [name for name, _ in SETS] if wanted.lower() in ("", "all") else [s.strip() for s in wanted.split(",") if s.strip()]

fm = currentProgram.getFunctionManager()
interface = DecompInterface()
interface.openProgram(currentProgram)

functions = [(f.getName(True), f) for f in fm.getFunctions(True)]
functions = [(n, f) for n, f in functions if "<" not in n and not n.startswith("FUN_")]

index = io.open(base + "/decomp_index.tsv", "a", encoding="utf-8")
for name, predicate in SETS:
    if name not in chosen:
        continue
    members = [(n, f) for n, f in functions if predicate(n)]
    println("%s: %d functions" % (name, len(members)))
    done = 0
    with io.open("%s/decomp_%s.c" % (base, name), "w", encoding="utf-8") as out:
        for full, function in members:
            if monitor.isCancelled():
                break
            offset = function.getEntryPoint().getOffset() - IMAGE_BASE
            size = function.getBody().getNumAddresses()
            status, code = "ok", u""
            try:
                result = interface.decompileFunction(function, TIMEOUT_SECONDS, monitor)
                if result.decompileCompleted():
                    code = result.getDecompiledFunction().getC()
                else:
                    status = "failed: %s" % result.getErrorMessage()
            except Exception as problem:
                status = "error: %s" % problem
            out.write(u"//// %x %s (%d bytes) [%s]\n%s\n" % (offset, full, size, status, code))
            out.flush()
            index.write(u"%s\t%x\t%s\t%s\t%d\n" % (name, offset, full, status, code.count(u"\n")))
            done += 1
            if done % 200 == 0:
                println("  %s: %d / %d" % (name, done, len(members)))
                index.flush()
    index.flush()
    println("%s done: %d functions" % (name, done))
index.close()
interface.dispose()
println("ExportDecompiled finished")
