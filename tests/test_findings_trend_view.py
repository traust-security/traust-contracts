from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/findings-trend.schema.json"
RATED = ("critical", "high", "medium", "low", "informational")
METRICS = (
    "open",
    "risk_index",
    "new",
    "velocity",
    "mttr",
    "fp_rate",
    "regressions",
    "accepted",
    "accepted_risk_index",
    "hardening",
    "coverage",
)


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _point(**overrides: Any) -> dict[str, Any]:
    point = {
        "bucket": "2026-10-05T00:00:00Z",
        "open_by_severity": {**dict.fromkeys(RATED, 0), "high": 2, "unrated": 1},
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
    return {**point, **overrides}


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-10-20T00:00:00Z",
        "repositories": 3,
        "points": [_point(), _point(bucket="2026-10-12T00:00:00Z", mttr_days=None)],
        "directions": [
            {
                "metric": "open",
                "last": 3.0,
                "baseline": 3.0,
                "change_pct": 0.0,
                "rising": None,
                "worsening": False,
            },
            {
                "metric": "velocity",
                "last": 1.0,
                "baseline": 0.0,
                "change_pct": None,
                "rising": True,
                "worsening": False,
            },
            {
                "metric": "coverage",
                "last": 50.0,
                "baseline": None,
                "change_pct": None,
                "rising": None,
                "worsening": False,
            },
        ],
        "accepted": [
            {
                "finding_id": "00000000-0000-4000-8000-000000000001",
                "repository_url": "https://example.com/org/repo",
                "title": "Debug endpoint behind network policy",
                "severity": "critical",
                "cvss_score": "9.5",
                "accepted_at": "2026-10-07T12:00:00+02:00",
                "accepted_by": "human:analyst@example.com",
                "rationale": "compensating network policy",
            }
        ],
    }


def _at(document: dict[str, Any], path: tuple[Any, ...]) -> tuple[Any, Any]:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    return target, path[-1]


def _set(document: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    target, key = _at(document, path)
    target[key] = value


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "point": ("points", 0),
    "open_by_severity": ("points", 0, "open_by_severity"),
    "direction": ("directions", 0),
    "accepted_risk": ("accepted", 0),
}
OPTIONAL = {"open_by_severity": {"unrated"}}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_scope_with_nothing_reported_is_valid(validator: Draft202012Validator) -> None:
    empty = {
        "as_of": "2026-10-20T00:00:00Z",
        "repositories": 0,
        "points": [],
        "directions": [],
        "accepted": [],
    }
    validator.validate(empty)


@pytest.mark.parametrize("scope", OBJECTS)
def test_every_serialized_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    for field in list(_object(document, scope)):
        if field in OPTIONAL.get(scope, set()):
            continue
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
    "path",
    [
        ("repositories",),
        *(("points", 0, f) for f in ("new", "resolved", "accepted", "hardening")),
        *(("points", 0, f) for f in ("false_positives", "regressions", "decisions")),
        ("points", 0, "reported"),
        ("points", 0, "dispositioned"),
        ("points", 0, "open_by_severity", "critical"),
    ],
)
@pytest.mark.parametrize("invalid", [-1, 1.5, "1", None, True])
def test_counts_are_nonnegative_integers(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["risk_index", "accepted_risk_index", "mttr_days"])
def test_indexes_and_mttr_are_unknown_as_null_never_negative(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    _set(document, ("points", 0, field), None)
    validator.validate(document)
    for invalid in (-0.1, "1.0"):
        _set(document, ("points", 0, field), invalid)
        with pytest.raises(ValidationError):
            validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"), [("coverage", 100.1), ("coverage", -1), ("fp_rate", -1)]
)
def test_percentages_stay_in_range(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: float
) -> None:
    _set(document, ("points", 0, field), invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["fp_rate", "coverage"])
def test_percentages_are_never_null(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    _set(document, ("points", 0, field), None)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_open_unrated_is_present_only_when_counted(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    by_severity = document["points"][0]["open_by_severity"]
    del by_severity["unrated"]
    validator.validate(document)
    by_severity["unrated"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("metric", METRICS)
def test_every_core_metric_is_a_known_direction(
    validator: Draft202012Validator, document: dict[str, Any], metric: str
) -> None:
    document["directions"][0]["metric"] = metric
    validator.validate(document)


@pytest.mark.parametrize("metric", ["Open", "risk", "", None])
def test_unknown_metrics_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], metric: str | None
) -> None:
    document["directions"][0]["metric"] = metric
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "fields", [{"change_pct": 5.0}, {"rising": True}, {"rising": False, "worsening": True}]
)
def test_no_baseline_means_no_change_and_no_direction(
    validator: Draft202012Validator, document: dict[str, Any], fields: dict[str, Any]
) -> None:
    document["directions"][2].update(fields)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_flat_metric_is_never_worsening(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["directions"][0]["worsening"] = True
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_zero_baseline_has_no_change_but_still_a_direction(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["directions"][1].update(rising=True, worsening=True)
    validator.validate(document)


@pytest.mark.parametrize("severity", ["critical", "informational", None])
def test_accepted_severity_is_rated_or_null_for_unrated(
    validator: Draft202012Validator, document: dict[str, Any], severity: str | None
) -> None:
    document["accepted"][0]["severity"] = severity
    validator.validate(document)


@pytest.mark.parametrize("severity", ["unrated", "Critical", ""])
def test_accepted_severity_outside_the_vocabulary_is_rejected(
    validator: Draft202012Validator, document: dict[str, Any], severity: str
) -> None:
    document["accepted"][0]["severity"] = severity
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("score", ["9.8", "10", "0", "0.0", "7.5000000000", None])
def test_cvss_score_is_an_exact_decimal_string_or_null(
    validator: Draft202012Validator, document: dict[str, Any], score: str | None
) -> None:
    document["accepted"][0]["cvss_score"] = score
    validator.validate(document)


@pytest.mark.parametrize("score", ["11", "-1", "1E+1", "", "9.8\n", " 9.8", 9.8])
def test_malformed_cvss_scores_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], score: Any
) -> None:
    document["accepted"][0]["cvss_score"] = score
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["accepted_at", "accepted_by", "rationale"])
def test_an_acceptance_not_found_is_null(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    document["accepted"][0][field] = None
    validator.validate(document)


def test_rationale_is_truncated_to_160_characters(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["accepted"][0]["rationale"] = "x" * 160
    validator.validate(document)
    document["accepted"][0]["rationale"] = "x" * 161
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [("as_of",), ("points", 0, "bucket"), ("accepted", 0, "accepted_at")],
)
@pytest.mark.parametrize("invalid", ["yesterday", "2026-02-30T00:00:00Z", "2026-10-20T00:00:00"])
def test_invalid_or_timezone_naive_timestamps_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: str
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_as_of_is_never_null(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    document["as_of"] = None
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("invalid", ["not-a-uuid", "00000000000040008000000000000001", "", None])
def test_invalid_finding_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], invalid: Any
) -> None:
    document["accepted"][0]["finding_id"] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize("field", ["title", "repository_url", "accepted_by", "rationale"])
@pytest.mark.parametrize("raw", ["", UNTRUSTED])
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], field: str, raw: str
) -> None:
    document["accepted"][0][field] = raw
    validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("points", None), ("points", {}), ("directions", [None]), ("accepted", "none")],
)
def test_collections_keep_their_structured_types(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_severity_keys_match_the_scanner_severity_registry() -> None:
    registry = json.loads((ROOT / "enums/v1/scanner-severity.json").read_text())["values"]
    point = json.loads(SCHEMA.read_text())["$defs"]["point"]
    assert list(point["properties"]["open_by_severity"]["properties"]) == registry


def test_accepted_severities_match_the_severity_registry() -> None:
    registry = json.loads((ROOT / "enums/v1/severity.json").read_text())["values"]
    accepted = json.loads(SCHEMA.read_text())["$defs"]["accepted_risk"]
    assert accepted["properties"]["severity"]["enum"] == [*registry, None]
