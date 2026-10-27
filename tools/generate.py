"""Regenerates the module's three data headers (probe/src/book_*.hpp) from a game version's data folder.

    python tools/generate.py [data/totk/121] [tools/ghidra]

book_data.hpp needs the Ghidra folder as well (failure_sites.tsv and the bulk decompile); the other two headers come from the data folder alone.
"""
import os
import subprocess
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
version = os.path.join(root, sys.argv[1] if len(sys.argv) > 1 else "data/totk/121")
ghidra = os.path.join(root, sys.argv[2] if len(sys.argv) > 2 else "tools/ghidra")
source = os.path.join(root, "probe", "src")


def run(script, *arguments):
    subprocess.check_call([sys.executable, os.path.join(root, "tools", script), *arguments])


run("make_book_header.py", version, ghidra, os.path.join(source, "book_data.hpp"))
run("make_stubs.py", os.path.join(source, "book_data.hpp"), os.path.join(source, "book_stubs.hpp"))
run("make_exits.py", os.path.join(version, "return_sites.tsv"), os.path.join(source, "book_exits.hpp"))
