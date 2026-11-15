from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/validation-fuzz.schema.json"
UUID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    url = "https://forge.example/o/parser"
    return {
        "as_of": "2026-11-15T00:00:00Z",
        "targets": [
            {
                "repository": url,
                "target": "parser",
                "language": "go",
                "assessment_id": UUID,
                "occurred_at": "2026-11-14T00:00:00Z",
                "engines": ["go_native"],
                "outcomes": {"crashed": 1, "clean": 2},
                "execs": 120000,
                "crashers": 1,
                "lines_covered": 800,
                "lines_total": 1000,
                "gaps": 1,
            }
        ],
        "crashers": [
            {
                "repository": url,
                "target": "parser",
                "harness": "FuzzParse",
                "crasher": "C1",
                "title": "Index out of range in Parse",
                "crash_class": "index_out_of_range",
                "severity": "medium",
                "cvss": 5.3,
                "cwes": ["CWE-129"],
                "reproducer_sha256": "a" * 64,
                "confirms_finding_id": None,
            }
        ],
        "gaps": [
            {
                "repository": url,
                "target": "parser",
                "surface": "pkg/net",
                "reason": "needs_live_environment",
                "harness": None,
                "note": None,
            }
        ],
        "validation": [{"key": url, "findings": 3, "by_verdict": {"confirmed": 2, "refuted": 1}}],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "target": ("targets", 0),
    "crasher": ("crashers", 0),
    "gap": ("gaps", 0),
    "validation": ("validation", 0),
}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_campaign_of_nothing_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"as_of": None, "targets": [], "crashers": [], "gaps": [], "validation": []})


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
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    _object(document, scope)["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("scope", "field", "invalid"),
    [
        ("target", "target", "-bad"),
        ("target", "engines", ["fuzzilli"]),
        ("target", "outcomes", {"exploded": 1}),
        ("target", "outcomes", {"clean": 0}),
        ("target", "execs", -1),
        ("target", "lines_total", None),
        ("target", "occurred_at", "yesterday"),
        ("crasher", "crash_class", "segfault"),
        ("crasher", "severity", "unrated"),
        ("crasher", "cvss", 10.5),
        ("crasher", "cwes", ["129"]),
        ("crasher", "reproducer_sha256", "A" * 64),
        ("crasher", "confirms_finding_id", "nope"),
        ("gap", "reason", "lazy"),
        ("gap", "surface", ""),
        ("validation", "findings", 0),
        ("validation", "by_verdict", {}),
        ("validation", "by_verdict", {"confirmed": 0}),
        ("validation", "by_verdict", {"maybe": 1}),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], scope: str, field: str, invalid: Any
) -> None:
    _object(document, scope)[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("scope", "field", "value"),
    [
        ("target", "execs", None),
        ("crasher", "cvss", None),
        ("crasher", "cwes", []),
        ("crasher", "confirms_finding_id", UUID),
        ("gap", "harness", "FuzzParse"),
        ("gap", "note", "needs a cluster"),
    ],
)
def test_nulls_and_values_core_serves_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], scope: str, field: str, value: Any
) -> None:
    _object(document, scope)[field] = value
    validator.validate(document)


def test_unmeasured_coverage_has_neither_count(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    target = _object(document, "target")
    target["lines_covered"] = target["lines_total"] = None
    validator.validate(document)


def test_verdicts_match_the_validation_verdict_registry() -> None:
    values = json.loads((ROOT / "enums/v1/validation-verdict.json").read_text())["values"]
    row = json.loads(SCHEMA.read_text())["$defs"]["validation"]
    assert row["properties"]["by_verdict"]["propertyNames"]["enum"] == values


def test_fuzz_fields_reference_the_fuzz_report_rather_than_copy_it() -> None:
    text = SCHEMA.read_text()
    for definition in ("engine", "outcome", "crash_class", "gap_reason", "name"):
        assert f"fuzz-report.schema.json#/$defs/{definition}" in text
