from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).parents[1] / "views_schema/v1/benchmark-scorecards.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def recall(detected: int, expected: int) -> dict[str, Any]:
    return {
        "detected": detected,
        "expected": expected,
        "recall": detected / expected if expected else None,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "scorecards": [
            {
                "overall": recall(3, 4),
                "near_misses": 1,
                "by_cwe": {"CWE-79": recall(1, 1), "CWE-89": recall(2, 3)},
                "by_severity": {"high": recall(3, 4)},
                "by_provenance": {"cve_replay": recall(3, 4)},
                "by_language": {"go": recall(3, 4)},
                "by_split": {"dev": recall(3, 4)},
                "injection": {"total": 2, "passed": 1, "reported": 1, "pass_rate": 0.5},
                "mean_stability": 0.8,
                "targets_scored": 4,
                "targets_skipped": 1,
                "auditor_versions": ["1.2.0"],
            }
        ]
    }


def test_a_scorecard_per_auditor_version_validates(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    assert validator.is_valid(document)


def test_no_recorded_benchmark_audit_is_an_empty_list(validator: Draft202012Validator) -> None:
    assert validator.is_valid({"scorecards": []})


def test_nothing_expected_is_a_null_recall_and_unmeasured_values_are_null(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    card = document["scorecards"][0]
    card["by_severity"]["low"] = recall(0, 0)
    card["mean_stability"] = None
    card["injection"]["pass_rate"] = None
    assert validator.is_valid(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("overall", "recall"), 1.5),
        (("overall", "recall"), -0.1),
        (("overall", "detected"), -1),
        (("mean_stability", None), 1.2),
        (("injection", "pass_rate"), 2),
        (("targets_skipped", None), -1),
    ],
)
def test_rates_stay_in_range_and_counts_stay_non_negative(
    validator: Draft202012Validator,
    document: dict[str, Any],
    path: tuple[str, str | None],
    value: Any,
) -> None:
    card = document["scorecards"][0]
    if path[1] is None:
        card[path[0]] = value
    else:
        card[path[0]][path[1]] = value
    assert not validator.is_valid(document)


@pytest.mark.parametrize(
    "field",
    [
        "overall",
        "near_misses",
        "by_cwe",
        "by_severity",
        "by_provenance",
        "by_language",
        "by_split",
        "injection",
        "mean_stability",
        "targets_scored",
        "targets_skipped",
        "auditor_versions",
    ],
)
def test_every_scorecard_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["scorecards"][0][field]
    assert not validator.is_valid(document)


def test_unknown_fields_are_refused(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["scorecards"][0]["held_out"] = True  # release scoring never reaches this view
    assert not validator.is_valid(document)
    document["scorecards"][0].pop("held_out")
    document["window"] = {"start": "2026-10-01T00:00:00Z"}
    assert not validator.is_valid(document)
