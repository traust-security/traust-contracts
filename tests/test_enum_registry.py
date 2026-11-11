"""Registry gate: enums/v1 metadata must be derivable from the schemas.

`source_schema` and `used_in_schemas` were hand-written and drifted (a source
naming a schema file that does not exist, a usage list claiming a schema that
defines a different enum). ci/enum_registry.py derives them; this test fails
when a registered file disagrees with what it derives.

The optional `definitions`, `standard` and `deprecated` fields are checked
against a small synthetic registry (one rename, merge, split and one-way
drop) and against every real file.

Every schema enum must also be registered: a site whose value set matches no
enums/v1 file fails the build, so a new vocabulary cannot enter a schema without
entering the registry (and, through it, the generated SDK enum types).
"""

from __future__ import annotations

import copy
import csv
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("enum_registry", ROOT / "ci" / "enum_registry.py")
enum_registry = importlib.util.module_from_spec(_spec)
sys.modules["enum_registry"] = enum_registry  # dataclasses resolve annotations via sys.modules
_spec.loader.exec_module(enum_registry)


def test_registry_metadata_matches_schemas():
    found = enum_registry.problems(enum_registry.load_schemas(), enum_registry.load_registry())
    assert not found, "run `python3 ci/enum_registry.py --write`, then fix:\n" + "\n".join(found)


def test_every_schema_enum_is_registered():
    loose = enum_registry.unregistered(enum_registry.load_schemas(), enum_registry.load_registry())
    assert not loose, (
        "schema enums with no enums/v1 file (add one, then run "
        "`python3 ci/enum_registry.py --write`):\n" + "\n".join(site.ref for site in loose)
    )


def test_resolve_follows_json_pointer_escapes():
    schemas = {"a.schema.json": {"$defs": {"x/y": {"enum": ["p", "q"]}}}}
    hit = enum_registry.resolve(schemas, "a.schema.json#/$defs/x~1y", "")
    assert hit is not None
    assert enum_registry._string_values(hit[1]) == frozenset({"p", "q"})


def test_usage_follows_refs_across_files():
    schemas = {
        "a.schema.json": {"$defs": {"level": {"enum": ["low", "high"]}}},
        "b.schema.json": {"properties": {"s": {"$ref": "a.schema.json#/$defs/level"}}},
        "c.schema.json": {"properties": {"t": {"$ref": "b.schema.json#/properties/s"}}},
        "d.schema.json": {"if": {"properties": {"s": {"enum": ["low", "high"]}}}},
    }
    reach = enum_registry.reachable(schemas)
    used = enum_registry.derived_used_in(frozenset({"low", "high"}), reach)
    # d only names the values inside an `if` condition; it does not validate them.
    assert used == ["a.schema.json", "b.schema.json", "c.schema.json"]


def test_canonical_schema_id_resolves_without_filename_or_host_guessing():
    schema_id = "https://contracts.example.test/v1/a.schema.json"
    target = {"enum": ["p", "q"]}
    schemas = {"a.schema.json": {"$id": schema_id, "$defs": {"level": target}}}
    assert enum_registry.resolve(schemas, f"{schema_id}#/$defs/level", "") == (
        "a.schema.json",
        target,
    )
    assert (
        enum_registry.resolve(
            schemas, "https://other.example.test/v1/a.schema.json#/$defs/level", ""
        )
        is None
    )


def test_registry_usage_follows_canonical_schema_id_across_distinct_base_uris():
    schema_id = "https://contracts.example.test/v1/a.schema.json"
    schemas = {
        "a.schema.json": {
            "$id": schema_id,
            "$defs": {"level": {"enum": ["p", "q"]}},
        },
        "b.schema.json": {
            "$id": "https://other.example.test/schemas/b.schema.json",
            "properties": {"level": {"$ref": f"{schema_id}#/$defs/level"}},
        },
    }
    reach = enum_registry.reachable(schemas)
    assert enum_registry.derived_used_in(frozenset({"p", "q"}), reach) == [
        "a.schema.json",
        "b.schema.json",
    ]


# --- Optional fields: definitions, standard, deprecated -------------------
#
# A small synthetic registry, deliberately unrelated to any real vocabulary,
# with one example of each kind of replacement: rename (crimson -> red), merge
# (crimson and scarlet -> red), split (navy -> colour.blue + shade.dark), a
# one-way drop (teal, with no replacement) and a retired value (maroon: removed
# from values in a major release, but its mapping kept for old events).


def _synthetic() -> dict[str, dict]:
    fixture = json.loads((ROOT / "tests/fixtures/enum-normalization.json").read_text())
    return {f"{document['name']}.json": document for document in fixture["registry"]}


def test_synthetic_registry_with_every_replacement_kind_passes():
    assert enum_registry.format_problems(_synthetic()) == []


def test_real_registry_files_pass_the_format_checks():
    assert enum_registry.format_problems(enum_registry.load_registry()) == []


def _colour(files):
    return files["colour.json"]


@pytest.mark.parametrize(
    ("case", "mutate", "expected"),
    [
        (
            "definitions cover every value",
            lambda f: _colour(f)["definitions"].pop("blue"),
            "definitions missing ['blue']",
        ),
        (
            "definitions are not empty",
            lambda f: _colour(f)["definitions"].__setitem__("red", ""),
            "definitions are empty for ['red']",
        ),
        (
            "an adapted standard needs a note",
            lambda f: _colour(f)["standard"].pop("note"),
            "adapted standard needs a note",
        ),
        (
            "a standard needs a name",
            lambda f: _colour(f).__setitem__("standard", {"relationship": "exact"}),
            "standard needs a name",
        ),
        (
            "only the file's own values can be deprecated",
            lambda f: _colour(f)["deprecated"].__setitem__("green", {"replaced_by": []}),
            "deprecated 'green' is not one of the file's values",
        ),
        (
            "every deprecation says what replaces it",
            lambda f: _colour(f)["deprecated"].__setitem__("teal", {"note": "gone"}),
            "deprecated 'teal' needs a replaced_by list",
        ),
        (
            "replacements name a real enum",
            lambda f: _colour(f)["deprecated"]["crimson"]["replaced_by"].__setitem__(
                0, {"enum": "hue", "value": "red"}
            ),
            "replaced by unknown enum 'hue'",
        ),
        (
            "replacements name a real value",
            lambda f: _colour(f)["deprecated"]["crimson"]["replaced_by"].__setitem__(
                0, {"enum": "colour", "value": "green"}
            ),
            "which is not a value of 'colour'",
        ),
        (
            "replacements do not chain",
            lambda f: _colour(f)["deprecated"]["crimson"]["replaced_by"].__setitem__(
                0, {"enum": "colour", "value": "scarlet"}
            ),
            "which is itself deprecated",
        ),
        (
            "a split lands in each enum once",
            lambda f: _colour(f)["deprecated"]["navy"]["replaced_by"].append(
                {"enum": "shade", "value": "light"}
            ),
            "is replaced twice in 'shade'",
        ),
        (
            "a retired value has left values",
            lambda f: _colour(f)["values"].append("maroon"),
            "retired 'maroon' is still in values",
        ),
        (
            "a value removed from values must be marked retired",
            lambda f: _colour(f)["deprecated"]["maroon"].pop("retired"),
            'mark it "retired": true',
        ),
        (
            "retired is a boolean",
            lambda f: _colour(f)["deprecated"]["maroon"].__setitem__("retired", "yes"),
            "retired must be true or false",
        ),
        (
            "nothing is replaced by a retired value",
            lambda f: _colour(f)["deprecated"]["crimson"]["replaced_by"].__setitem__(
                0, {"enum": "colour", "value": "maroon"}
            ),
            "which is not a value of 'colour'",
        ),
        (
            "unknown keys are typos",
            lambda f: _colour(f).__setitem__("definiton", {}),
            "unknown keys ['definiton']",
        ),
    ],
)
def test_each_format_rule_rejects_a_violation(case, mutate, expected):
    files = copy.deepcopy(_synthetic())
    mutate(files)
    found = enum_registry.format_problems(files)
    assert any(expected in p for p in found), f"{case}: got {found}"


def test_review_sheet_preserves_every_current_and_retired_registry_value():
    registry = enum_registry.load_registry()
    rows = list(csv.DictReader(io.StringIO(enum_registry.review_sheet(registry))))
    expected = {
        (entry["name"], value)
        for entry in registry.values()
        for value in set(entry["values"]) | set(entry.get("deprecated", {}))
    }
    assert {(row["enum"], row["value"]) for row in rows} == expected
    assert len(rows) == len(expected)


def test_review_sheet_is_deterministic_and_preserves_split_drop_and_retired_metadata():
    registry = _synthetic()
    colour = _colour(registry)
    colour["definitions"]["blue"] = 'A "blue", tone\nwith a second line.'
    sheet = enum_registry.review_sheet(registry)
    shuffled = dict(reversed(list(copy.deepcopy(registry).items())))
    for entry in shuffled.values():
        entry["values"].reverse()
        entry["used_in_schemas"] = list(reversed(entry.get("used_in_schemas", [])))
        for metadata in entry.get("deprecated", {}).values():
            metadata["replaced_by"].reverse()
    assert enum_registry.review_sheet(shuffled) == sheet
    rows = {(row["enum"], row["value"]): row for row in csv.DictReader(io.StringIO(sheet))}
    assert rows["colour", "blue"]["definition"] == colour["definitions"]["blue"]
    assert rows["colour", "blue"]["status"] == "current"
    assert rows["colour", "navy"]["status"] == "deprecated"
    assert json.loads(rows["colour", "navy"]["replaced_by"]) == [
        {"enum": "colour", "value": "blue"},
        {"enum": "shade", "value": "dark"},
    ]
    assert json.loads(rows["colour", "teal"]["replaced_by"]) == []
    assert rows["colour", "maroon"]["status"] == "retired"
    assert json.loads(rows["colour", "maroon"]["replaced_by"]) == [
        {"enum": "colour", "value": "red"}
    ]
    assert json.loads(rows["colour", "blue"]["standard"]) == colour.get("standard")


def test_review_sheet_cli_generates_actual_csv_file_and_stdout(tmp_path, monkeypatch, capsys):
    registry = _synthetic()
    monkeypatch.setattr(enum_registry, "load_registry", lambda: registry)
    target = tmp_path / "review.csv"
    assert enum_registry.main(["--sheet", str(target)]) == 0
    expected = enum_registry.review_sheet(registry)
    assert target.read_text(encoding="utf-8") == expected
    assert enum_registry.main(["--sheet", "-"]) == 0
    assert capsys.readouterr().out == expected
