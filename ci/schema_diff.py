#!/usr/bin/env python3
"""Report schema changes that need a traust-core change in the same push.

A report, not a gate: no versions or tags. Compares every JSON schema with its
copy at the merge base of HEAD and BASE (default origin/development) and lists
removed properties, newly required properties and removed enum values.

    python3 ci/schema_diff.py [BASE]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
GLOBS = (
    "artifacts_schema/v1/*.schema.json",
    "config/v1/*.schema.json",
    "views_schema/v1/*.schema.json",
)


def git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout


def facts(node: Any, path: str = "") -> dict[str, set[str]]:
    """Per JSON pointer: its properties, required names and enum values."""
    out: dict[str, set[str]] = {}
    if isinstance(node, dict):
        if isinstance(node.get("properties"), dict):
            out[f"{path}#properties"] = set(node["properties"])
        if isinstance(node.get("required"), list):
            out[f"{path}#required"] = set(node["required"])
        if isinstance(node.get("enum"), list):
            out[f"{path}#enum"] = {json.dumps(v) for v in node["enum"]}
        for key, child in node.items():
            out |= facts(child, f"{path}/{key}")
    elif isinstance(node, list):
        for i, child in enumerate(node):
            out |= facts(child, f"{path}/{i}")
    return out


def changes(old: Any, new: Any) -> list[str]:
    before, after = facts(old), facts(new)
    found = []
    for key, values in before.items():
        pointer, kind = key.rsplit("#", 1)
        now = after.get(key, set())
        if kind in ("properties", "enum") and (gone := values - now):
            found.append(f"{pointer or '/'}: removed {kind} {sorted(gone)}")
    for key, values in after.items():
        pointer, kind = key.rsplit("#", 1)
        if kind == "required" and (added := values - before.get(key, set())):
            found.append(f"{pointer or '/'}: newly required {sorted(added)}")
    return found


def main(argv: list[str]) -> int:
    base = git("merge-base", "HEAD", argv[0] if argv else "origin/development").strip()
    reported = 0
    for pattern in GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            rel = path.relative_to(ROOT).as_posix()
            try:
                old = json.loads(git("show", f"{base}:{rel}"))
            except subprocess.CalledProcessError:
                continue
            for line in changes(old, json.loads(path.read_text(encoding="utf-8"))):
                print(f"{rel} {line}")
                reported += 1
    print(f"{reported} change(s) vs {base[:12]} that traust-core may need to absorb")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
