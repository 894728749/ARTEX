#!/usr/bin/env python3
"""Extract the exact version section from RELEASES.md for GitHub Releases."""
import pathlib
import re
import sys

tag = sys.argv[1] if len(sys.argv) == 2 else ""
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("Expected a stable vX.Y.Z tag")
notes = (pathlib.Path(__file__).resolve().parents[1] / "RELEASES.md").read_text(encoding="utf-8")
match = re.search(r"^## `" + re.escape(tag) + r"`\s*\n(.*?)(?=^## |\Z)", notes, re.M | re.S)
if not match or not match[1].strip():
    raise SystemExit(f"Add specific release notes under '## `{tag}`' in RELEASES.md before publishing")
print(match[1].strip())
