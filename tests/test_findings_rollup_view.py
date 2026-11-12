from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/findings-rollup.schema.json"
SEVERITIES = ("critical", "high", "medium", "low", "informational")


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _counts(**values: int) -> dict[str, int]:
    return {s: values.get(s, 0) for s in (*SEVERITIES, "unrated")}


def _tally() -> dict[str, Any]:
    return {
        "open": _counts(critical=1, high=2, unrated=1),
        "hardening": 3,
        "resolved": 4,
        "risk_accepted": 1,
        "false_positive": 2,
        "execution_proven": 1,
        "unverified": 2,
        "decided": 7,
        "remediated": _counts(high=3, unrated=1),
        "tracked": 12,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-11-01T00:00:00Z",
        "total": _tally(),
        "products": [
            {
                "product_id": "00000000-0000-4000-8000-000000000001",
                "slug": "example-product",
                "name": "Example Product",
                "repositories": 1,
                "tally": _tally(),
            }
        ],
        "repositories": [
            {
                "repository_id": "00000000-0000-4000-8000-000000000002",
                "repository_url": "https://example.com/org/repo",
                "tally": _tally(),
                "hardening_categories": {"authz": 2, "uncategorized": 1},
            }
        ],
        "top": [
            {
                "finding_id": "00000000-0000-4000-8000-000000000003",
                "repository_url": "https://example.com/org/repo",
                "title": "Unbounded input allocation",
                "severity": "critical",
                "cvss_score": "9.8",
                "execution_proven": True,
                "sla_due": "2026-11-15T00:00:00+02:00",
            }
        ],
        "categories": [
            {
                "key": "injection",
                "findings": 5,
                "open": 3,
                "hardening": 1,
                "accepted": 0,
                "resolved": 1,
                "false_positives": 0,
                "open_by_severity": {**{s: 0 for s in SEVERITIES}, "high": 2, "unrated": 1},
            },
            {
                "key": None,
                "findings": 1,
                "open": 0,
                "hardening": 0,
                "accepted": 0,
                "resolved": 1,
                "false_positives": 0,
                "open_by_severity": dict.fromkeys(SEVERITIES, 0),
            },
        ],
        "attack_scenarios": [
            {
                "assessment_id": "00000000-0000-4000-8000-000000000004",
                "repository_id": "00000000-0000-4000-8000-000000000002",
                "label": "T3",
                "threat": None,
                "steps": ["The attacker sends a crafted request.", "The service allocates."],
            }
        ],
    }


def _objects(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "view": document,
        "total": document["total"],
        "severity_counts": document["total"]["open"],
        "product": document["products"][0],
        "repository": document["repositories"][0],
        "top_finding": document["top"][0],
        "category": document["categories"][0],
        "open_by_severity": document["categories"][0]["open_by_severity"],
        "attack_scenario": document["attack_scenarios"][0],
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_unscoped_empty_portfolio_is_valid(validator: Draft202012Validator) -> None:
    zero = {
        "open": _counts(),
        "hardening": 0,
        "resolved": 0,
        "risk_accepted": 0,
        "false_positive": 0,
        "execution_proven": 0,
        "unverified": 0,
        "decided": 0,
        "remediated": _counts(),
        "tracked": 0,
    }
    empty = {
        "as_of": None,
        "total": zero,
        "products": [],
        "repositories": [],
        "top": [],
        "categories": [],
        "attack_scenarios": [],
    }
    validator.validate(empty)


OBJECTS = (
    "view",
    "total",
    "severity_counts",
    "product",
    "repository",
    "top_finding",
    "category",
    "open_by_severity",
    "attack_scenario",
)


@pytest.mark.parametrize("scope", OBJECTS)
def test_every_serialized_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    fields = list(_objects(document)[scope])
    optional = {"open_by_severity": {"unrated"}}.get(scope, set())
    for field in fields:
        if field in optional:
            continue
        broken = copy.deepcopy(document)
        del _objects(broken)[scope][field]
        with pytest.raises(ValidationError):
            validator.validate(broken)


@pytest.mark.parametrize("scope", OBJECTS)
def test_unknown_fields_are_rejected_at_every_object_boundary(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    _objects(document)[scope]["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("total", "hardening"),
        ("total", "open", "critical"),
        ("total", "remediated", "unrated"),
        ("total", "tracked"),
        ("products", 0, "repositories"),
        ("categories", 0, "findings"),
        ("categories", 0, "open_by_severity", "high"),
    ],
)
@pytest.mark.parametrize("invalid", [-1, 1.5, "1", None, True])
def test_counts_are_nonnegative_integers(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("severity", ["medium", "low", "informational", "unrated", None, ""])
def test_top_lists_only_open_critical_and_high(
    validator: Draft202012Validator, document: dict[str, Any], severity: str | None
) -> None:
    document["top"][0]["severity"] = severity
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("score", ["9.8", "10", "10.0", "0", "0.0", "7.50", "7.5000000000", None])
def test_cvss_score_is_an_exact_decimal_string_from_0_to_10(
    validator: Draft202012Validator, document: dict[str, Any], score: str | None
) -> None:
    document["top"][0]["cvss_score"] = score
    validator.validate(document)


@pytest.mark.parametrize(
    "score", ["11", "10.1", "-1", "9.8.1", "1E+1", "", " 9.8", ".5", "9.", 9.8, 10]
)
def test_out_of_range_or_non_string_cvss_scores_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], score: Any
) -> None:
    document["top"][0]["cvss_score"] = score
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_category_unrated_is_present_only_when_counted(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    by_severity = document["categories"][0]["open_by_severity"]
    del by_severity["unrated"]
    validator.validate(document)
    by_severity["unrated"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_hardening_categories_list_only_counted_categories(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["repositories"][0]["hardening_categories"] = {}
    validator.validate(document)
    document["repositories"][0]["hardening_categories"] = {"authz": 0}
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("as_of",), None),
        (("top", 0, "cvss_score"), None),
        (("top", 0, "sla_due"), None),
        (("categories", 0, "key"), None),
        (("attack_scenarios", 0, "threat"), "Request smuggling"),
    ],
)
def test_nullable_fields_accept_their_documented_values(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], value: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("products", 0, "product_id"),
        ("repositories", 0, "repository_id"),
        ("top", 0, "finding_id"),
        ("attack_scenarios", 0, "assessment_id"),
        ("attack_scenarios", 0, "repository_id"),
    ],
)
@pytest.mark.parametrize("invalid", ["not-a-uuid", "00000000000040008000000000000001", "", None])
def test_invalid_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("path", [("as_of",), ("top", 0, "sla_due")])
@pytest.mark.parametrize("invalid", ["yesterday", "2026-02-30T00:00:00Z", "2026-11-01T00:00:00"])
def test_invalid_or_timezone_naive_timestamps_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: str
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize(
    "path",
    [
        ("top", 0, "title"),
        ("top", 0, "repository_url"),
        ("repositories", 0, "repository_url"),
        ("products", 0, "name"),
        ("categories", 0, "key"),
        ("attack_scenarios", 0, "steps", 0),
        ("attack_scenarios", 0, "threat"),
    ],
)
@pytest.mark.parametrize("raw", ["", UNTRUSTED])
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], raw: str
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = raw
    validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("products", None),
        ("products", {}),
        ("repositories", [None]),
        ("top", "none"),
        ("categories", None),
        ("attack_scenarios", {}),
        ("total", []),
    ],
)
def test_collections_keep_their_structured_types(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_severity_keys_match_the_scanner_severity_registry() -> None:
    registry = json.loads((ROOT / "enums/v1/scanner-severity.json").read_text())["values"]
    schema = json.loads(SCHEMA.read_text())["$defs"]
    assert list(schema["severity_counts"]["properties"]) == registry
    assert list(schema["category"]["properties"]["open_by_severity"]["properties"]) == registry
