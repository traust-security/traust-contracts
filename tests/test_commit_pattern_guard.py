"""Commit-id patterns refuse a trailing newline: Python's `$` matches before a final one."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMAS = ("cve-replay", "finding-intake")


def _sites() -> list[tuple[str, dict]]:
    out = []
    for name in SCHEMAS:
        schema = json.loads((ROOT / f"artifacts_schema/v1/{name}.schema.json").read_text())
        stack = [schema]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if node.get("pattern") == "^(?:[0-9a-f]{40}|[0-9a-f]{64})$":
                    out.append((name, node))
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    return out


def test_every_commit_site_is_found() -> None:
    assert [name for name, _ in _sites()].count("cve-replay") == 2
    assert [name for name, _ in _sites()].count("finding-intake") == 1


@pytest.mark.parametrize("value", ["a" * 40, "b" * 64])
@pytest.mark.parametrize(("name", "site"), _sites())
def test_a_full_object_id_passes(name: str, site: dict, value: str) -> None:
    Draft202012Validator(site).validate(value)


@pytest.mark.parametrize("value", ["a" * 40 + "\n", "b" * 64 + "\n", "a" * 39, "A" * 40])
@pytest.mark.parametrize(("name", "site"), _sites())
def test_a_trailing_newline_or_malformed_id_is_refused(name: str, site: dict, value: str) -> None:
    with pytest.raises(ValidationError):
        Draft202012Validator(site).validate(value)
