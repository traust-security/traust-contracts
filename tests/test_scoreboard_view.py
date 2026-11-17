from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/scoreboard.schema.json"
COUNTS = [
    "repositories", "reported", "dispositioned", "repositories_with_critical",
    "repositories_with_high", "credential_leaks", "resolved", "risk_accepted",
    "false_positives", "hardening", "execution_proven", "threat_models", "threats",
    "open_threats", "filed",
]  # fmt: skip


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (json.loads(p.read_text()) for p in sorted(SCHEMA.parent.glob("*.schema.json")))
    ]
    return Draft202012Validator(
        schema, registry=Registry().with_resources(resources), format_checker=FormatChecker()
    )


def _point() -> dict[str, Any]:
    rated = dict.fromkeys(("critical", "high", "medium", "low", "informational"), 0)
    return {
        "bucket": "2026-11-01T00:00:00Z",
        "open_by_severity": {**rated, "critical": 1, "high": 2},
        "new": 2,
        "resolved": 1,
        "accepted": 1,
        "hardening": 0,
        "false_positives": 1,
        "regressions": 0,
        "decisions": 2,
        "mttr_days": 3.5,
        "risk_index": 15.2,
        "accepted_risk_index": 9.5,
        "reported": 2,
        "dispositioned": 1,
        "fp_rate": 50.0,
        "coverage": 50.0,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-11-17T00:00:00Z",
        "repositories": 4,
        "reported": 3,
        "dispositioned": 2,
        "open": {
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "unrated": 1,
        },
        "repositories_with_critical": 1,
        "repositories_with_high": 2,
        "credential_leaks": 1,
        "resolved": 5,
        "risk_accepted": 1,
        "false_positives": 2,
        "hardening": 3,
        "execution_proven": 1,
        "themes": {"injection": 2, "authn": 1, "crypto": 1},
        "trend": _point(),
        "threat_models": 2,
        "threats": 9,
        "open_threats": 4,
        "filed": 3,
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_empty_scope_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    document |= dict.fromkeys(COUNTS, 0) | {"themes": {}, "trend": None}
    document["open"] = dict.fromkeys(document["open"], 0)
    validator.validate(document)


@pytest.mark.parametrize("field", list(json.loads(SCHEMA.read_text())["required"]))
def test_every_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"x": 1})


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        *(((field,), -1) for field in COUNTS),
        *(((field,), None) for field in COUNTS),
        (("as_of",), "yesterday"),
        (("as_of",), None),
        (("open", "critical"), -1),
        (("open", "total"), 3),
        (("themes",), {"a": 1, "b": 1, "c": 1, "d": 1}),
        (("themes", "injection"), 0),
        (("trend", "new"), -1),
        (("trend", "x"), 1),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    target = broken
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


@pytest.mark.parametrize(
    "change",
    [
        {"open": {"critical": 0}},
        {"open": {"high": 0}},
        {"threat_models": 0},
        {"threats": 0},
    ],
)
def test_counts_that_imply_one_another(
    validator: Draft202012Validator, document: dict[str, Any], change: dict[str, Any]
) -> None:
    for key, value in change.items():
        if isinstance(value, dict):
            document[key] |= value
        else:
            document[key] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_component_shapes_are_the_composed_views() -> None:
    props = json.loads(SCHEMA.read_text())["properties"]
    assert props["open"]["$ref"].endswith("findings-rollup.schema.json#/$defs/severity_counts")
    assert props["themes"]["$ref"].endswith("executive-summary.schema.json#/$defs/theme_counts")
    assert props["trend"]["oneOf"][0]["$ref"].endswith("findings-trend.schema.json#/$defs/point")
