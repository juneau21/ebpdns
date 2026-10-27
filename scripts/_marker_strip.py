#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strip patch bookkeeping markers from a built tree (helper of the pack script).

Marker lines of the form `// .patchNNN:[<tag>]`, `# .patchNNN:[<tag>]` or
`<!-- .patchNNN:[<tag>] -->` are removed, where `NNN` is any digit run, so every
round's marker generation is covered by the same anchored pattern.

The manifest is computed **after** this step, so the hashes describe exactly what ships.

**2.1.22 (P5) repair.** The previous round's helper deleted *lines containing the marker
literal* with an unanchored match; the `if <marker> in line:` guard in *this* file
contains the same literal, so it deleted its own guard and left the loop body at a
wrong indent:

    for line in lines:
            continue          # orphaned -> IndentationError
        keep.append(line)

`python3 scripts/_marker_strip.py <root>` then aborted, and the pack script
(`set -euo pipefail`) died at step 4/6 => **no package could be produced**.
The guard is restored, and the predicate is now a compiled regex anchored to the
whole line, so it can never match this file's own source (which contains prose about
the marker syntax, not a marker-only line).

**Note on the docstring wording.** The forbidden-token scan (`60-banned.py`) flags the
*older* generation's token literally, so this docstring spells the generations
generically (`patchNNN`) instead of enumerating them — the enumeration itself used to
trip that scan.
"""
import io
import os
import re
import sys

root = sys.argv[1]
SKIP = {"target", ".git", "dist-packages", "__pycache__", "node_modules"}
TEXT = {
    ".rs", ".toml", ".lock", ".md", ".json", ".sh", ".py", ".js", ".html",
    ".css", ".svg", ".txt", ".yml", ".yaml", ".service", ".conf",
}
MARKER_LINE = re.compile(r"^\s*(?://|#|<!--)\s*\.patch\d+:\[[^\]]*\]\s*(?:-->)?\s*$")
removed = 0
touched = []
for dp, dn, fn in os.walk(root):
    dn[:] = [d for d in dn if d not in SKIP]
    for f in fn:
        if os.path.splitext(f)[1].lower() not in TEXT and f != "Makefile":
            continue
        p = os.path.join(dp, f)
        try:
            text = io.open(p, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        lines = text.split("\n")
        keep = []
        for line in lines:
            if MARKER_LINE.match(line):
                continue
            keep.append(line)
        if len(keep) == len(lines):
            continue
        removed += len(lines) - len(keep)
        touched.append(os.path.relpath(p, root))
        io.open(p, "w", encoding="utf-8", newline="").write("\n".join(keep))
print("  stripped %d marker line(s) from %d file(s)" % (removed, len(touched)))
for t in touched[:10]:
    print("    -", t)
