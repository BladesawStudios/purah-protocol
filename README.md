# purah-protocol

A live debugger for *The Legend of Zelda: Tears of the Kingdom*. It is a [WiiXLaunch](https://github.com/TKVSC-Team/WiiXLaunch) `.wxlm`
module that listens on TCP port 54312 inside the running game, and the Debugger tab of Prism connects to it.

It can trace calls, stop threads, read and write memory, and follow one actor through its initialisation:
Prism sends an actor name, the module tracks every step of that actor's initialisation, and when one fails it reports which step, which of the
function's failure exits it took, and what the game said on the way.

Target: TotK 1.2.1 on Ryujinx. The module needs the host's Switch socket backend (`wiixl.net`) and WiiXLaunch core v1.7.

## Layout

| | |
| --- | --- |
| `probe/` | the module: `mod.json`, `src/` (the C++), `test/golden.cpp` (host-side check of the wire format) |
| `data/<game>/<version>/` | what is known about one game build; see below |
| `tools/` | generators for the module's data headers |
| `tools/ghidra/` | Ghidra scripts (Jython) that export that knowledge from an open program |
| `docs/protocol.md` | the wire protocol, which Prism implements as well |

### The data folder

Everything version-specific lives in `data/<game>/<version>/`; the module's code does not mention a function by address.

| file | what it is |
| --- | --- |
| `version.json` | game, version, build fingerprint |
| `book.tsv` | the symbol book: every hookable function and call site, by offset from the image base |
| `steps.psv` | the initialisation steps the watch follows, and how each is judged |
| `components.psv` | one line of meaning per component class |
| `component_vtables.tsv` | each component class's vtable, which is how a component is named at run time |
| `exit_functions.txt` | the functions whose failure exits are mapped, besides every component stage function |
| `return_sites.tsv` | every exit of those functions, found by `ExportReturnSites.py` |
| `exits.psv` | what each exit means, written by hand: `function|exit number|reason; reason` |

## Building

`probe/src/book_data.hpp`, `book_stubs.hpp` and `book_exits.hpp` are generated from the data folder and are committed, so the module builds
without Ghidra. After changing the data, regenerate them:

```sh
python tools/generate.py data/totk/121 tools/ghidra
```

Then build with WiiXLaunch's `scripts/build_mod.py --source probe --wiixlaunch <WiiXLaunch checkout>` and put the `.wxlm` in
`romfs/WiiXLaunch/mods/` of the WiiXLaunch install for the game.

The wire format is checked from the host: `g++ -std=c++17 -Wall -Wextra -Werror -I probe/src probe/test/golden.cpp`, compared with Prism's
`ProtocolCheck` output.

## Refreshing the data

1. Open the game's main module in Ghidra and run `tools/ghidra/ExportDebuggerSymbols.py`, then `ExportFailureSites.py` and `ExportDecompiled.py`
   (the outputs go in `tools/ghidra/`, which is not committed). Copy `component_vtables.tsv` into the data folder.
2. Run `ExportReturnSites.py` and pick the data folder. It rewrites `return_sites.tsv` and writes `return_sites_report.tsv`, which says how many of the
   failure paths it found were turned into instrumentable exits and why the rest were not.
3. Run `tools/generate.py`, rebuild, and add reasons to `exits.psv` for the exits that show as "Unknown reason".

Exit numbers depend on the exact code, so a new game version needs its own export; a reason is only reused where the code around the exit is the same.

## Licence

GPL-3.0; see `LICENSE`.
