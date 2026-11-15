from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/compliance.schema.json"
KEYS = (
    "total_in_scope",
    "deterministic",
    "evidence_review",
    "organizational",
    "satisfied",
    "not_satisfied",
    "not_applicable",
    "not_assessed",
)


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def _coverage(**counts: int) -> dict[str, int]:
    return {k: counts.get(k, 0) for k in KEYS}


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "by_framework": [
            {
                "key": "nist-800-53-rev5",
                "pairs": 2,
                "assessed": 1,
                "coverage": {"nist-800-53-rev5": _coverage(total_in_scope=10, satisfied=6)},
            }
        ],
        "by_scope": [
            {
                "key": "tenant-data-plane",
                "pairs": 2,
                "assessed": 1,
                "coverage": {
                    "nist-800-53-rev5": _coverage(total_in_scope=10, satisfied=6),
                    "pci-dss-v4": _coverage(),
                },
            }
        ],
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_undeclared_estate_is_empty(validator: Draft202012Validator) -> None:
    validator.validate({"by_framework": [], "by_scope": []})


@pytest.mark.parametrize("field", ["by_framework", "by_scope"])
def test_both_lists_are_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["key", "pairs", "assessed", "coverage"])
def test_every_row_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["by_scope"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "row", "counts"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    row = document["by_scope"][0]
    {"view": document, "row": row, "counts": row["coverage"]["pci-dss-v4"]}[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("by_scope", 0, "pairs"), 0),
        (("by_scope", 0, "assessed"), -1),
        (("by_scope", 0, "coverage"), {}),
        (("by_scope", 0, "coverage"), {"iso-27001": _coverage()}),
        (("by_scope", 0, "coverage", "pci-dss-v4", "satisfied"), -1),
        (("by_framework", 0, "key"), "tenant-data-plane"),
        (
            ("by_framework", 0, "coverage"),
            {"nist-800-53-rev5": _coverage(), "pci-dss-v4": _coverage()},
        ),
        (("by_framework", 0, "coverage"), {"pci-dss-v4": _coverage()}),
        (("by_framework", 0, "key"), ""),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    target: Any = broken
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


def test_some_counts_missing_is_refused(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    del document["by_scope"][0]["coverage"]["pci-dss-v4"]["not_assessed"]
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_frameworks_match_the_compliance_framework_registry() -> None:
    values = json.loads((ROOT / "enums/v1/compliance-framework.json").read_text())["values"]
    schema = json.loads(SCHEMA.read_text())
    assert schema["$defs"]["framework"]["enum"] == values
    rows = schema["allOf"][0]["then"]["properties"]["by_framework"]["items"]
    assert rows["properties"]["key"]["enum"] == values
    assert [b["if"]["properties"]["key"]["const"] for b in rows["allOf"]] == values


def test_the_coverage_counts_are_the_assessments_own_block() -> None:
    ref = json.loads(SCHEMA.read_text())["$defs"]["coverage"]["$ref"]
    assert ref.endswith(
        "artifacts_schema/v1/compliance-assessment.schema.json#/properties/coverage/additionalProperties"
    )


def test_a_declared_boundary_may_be_named_with_the_empty_string(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["by_scope"][0]["key"] = ""
    validator.validate(document)


@pytest.mark.parametrize(
    "framework", json.loads((ROOT / "enums/v1/compliance-framework.json").read_text())["values"]
)
def test_each_framework_row_covers_its_own_framework(
    validator: Draft202012Validator, document: dict[str, Any], framework: str
) -> None:
    row = document["by_framework"][0]
    row["key"], row["coverage"] = framework, {framework: _coverage()}
    validator.validate(document)
    others = [
        f for f in json.loads(SCHEMA.read_text())["$defs"]["framework"]["enum"] if f != framework
    ]
    row["coverage"] = {others[0]: _coverage()}
    with pytest.raises(ValidationError):
        validator.validate(document)
