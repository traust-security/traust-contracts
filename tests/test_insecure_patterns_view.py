from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
VIEWS = ROOT / "views_schema/v1"
SCHEMA = VIEWS / "insecure-patterns.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (json.loads(p.read_text()) for p in sorted(VIEWS.glob("*.schema.json")))
    ]
    registry = Registry().with_resources(resources)
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


def _counts(**counts: int) -> dict[str, int]:
    keys = ("critical", "high", "medium", "low", "informational", "unrated")
    return {k: counts.get(k, 0) for k in keys}


def _pattern() -> dict[str, Any]:
    return {
        "cwe": "CWE-89",
        "asvs": "V5.3.4",
        "repositories": 2,
        "occurrences": 3,
        "severities": _counts(high=2, unrated=1),
        "examples": [
            {
                "repository_url": "https://forge.example/o/a",
                "path": "pkg/db/query.go",
                "line_start": 42,
                "line_end": 44,
                "symbol": "buildQuery",
            }
        ],
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-11-15T00:00:00Z",
        "cuts": [
            {"ownership": "owned", "without_cwe": 1, "patterns": [_pattern()]},
            {"ownership": None, "without_cwe": 2, "patterns": []},
        ],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "cut": ("cuts", 0),
    "pattern": ("cuts", 0, "patterns", 0),
    "example": ("cuts", 0, "patterns", 0, "examples", 0),
}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def _set(document: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_current_view_of_nothing_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"as_of": None, "cuts": []})


@pytest.mark.parametrize("scope", OBJECTS)
def test_every_serialized_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    for field in list(_object(document, scope)):
        broken = copy.deepcopy(document)
        del _object(broken, scope)[field]
        with pytest.raises(ValidationError):
            validator.validate(broken)


@pytest.mark.parametrize("scope", OBJECTS)
def test_unknown_fields_are_rejected_at_every_object_boundary(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    _object(document, scope)["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("as_of",), "2026-11-15"),
        (OBJECTS["cut"] + ("ownership",), "partner"),
        (OBJECTS["cut"] + ("without_cwe",), -1),
        (OBJECTS["pattern"] + ("repositories",), 0),
        (OBJECTS["pattern"] + ("occurrences",), 0),
        (OBJECTS["pattern"] + ("severities",), {"high": 1}),
        (OBJECTS["pattern"] + ("examples",), [_pattern()["examples"][0]] * 7),
        (OBJECTS["example"] + ("line_start",), "42"),
        (OBJECTS["cut"] + ("patterns",), None),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_an_empty_cut_is_never_listed(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["cuts"][1]["without_cwe"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (OBJECTS["pattern"] + ("asvs",), None),
        (OBJECTS["pattern"] + ("cwe",), ""),
        (OBJECTS["example"] + ("path",), ""),
        (OBJECTS["example"] + ("line_start",), None),
        (OBJECTS["example"] + ("line_end",), None),
        (OBJECTS["example"] + ("symbol",), None),
        (OBJECTS["pattern"] + ("examples",), []),
    ],
)
def test_raw_values_and_nulls_core_serves_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], value: Any
) -> None:
    _set(document, path, value)
    validator.validate(document)


def test_ownership_is_the_census_registry_definition() -> None:
    cut = json.loads(SCHEMA.read_text())["$defs"]["cut"]["properties"]["ownership"]
    assert cut["oneOf"][0]["$ref"].endswith("census.schema.json#/$defs/ownership")
    values = json.loads((ROOT / "enums/v1/ownership.json").read_text())["values"]
    census = json.loads((VIEWS / "census.schema.json").read_text())["$defs"]["ownership"]
    assert census["enum"] == values
