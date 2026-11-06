from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = Path(__file__).parents[1] / "views_schema/v1/critical-misses.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "window": {"start": "2026-10-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"},
        "misses": [
            {
                "finding_id": "00000000-0000-4000-8000-000000000001",
                "repository_id": "00000000-0000-4000-8000-000000000002",
                "title": "Unbounded input allocation",
                "found_by": "00000000-0000-4000-8000-000000000003",
                "found_at": "2026-10-15T09:30:00+02:00",
                "missed_by": "00000000-0000-4000-8000-000000000004",
                "reason": "missed",
                "validity": None,
            }
        ],
    }


def test_empty_misses_need_no_coverage_or_rate_fields(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["misses"] = []
    assert validator.is_valid(document)


def test_nonempty_view_accepts_actual_misses_and_area_reports(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    area_report = {**document["misses"][0], "reason": "area_reported", "validity": "unknown"}
    document["misses"].append(area_report)
    assert validator.is_valid(document)


@pytest.mark.parametrize("validity", [None, "confirmed", "unknown", "legacy-verdict", ""])
def test_nullable_validity_preserves_arbitrary_historical_strings(
    validator: Draft202012Validator, document: dict[str, Any], validity: str | None
) -> None:
    document["misses"][0]["validity"] = validity
    assert validator.is_valid(document)


@pytest.mark.parametrize(
    "title",
    [
        "",
        '<script>alert("finding")</script>\n| fake | row |\n'
        "[click](javascript:alert(1)) & <b>raw</b> \u202ecritical",
    ],
)
def test_raw_untrusted_title_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], title: str
) -> None:
    document["misses"][0]["title"] = title
    assert validator.is_valid(document)


@pytest.mark.parametrize("field", ["window", "misses"])
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["start", "end"])
def test_both_window_endpoints_are_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["window"][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field",
    [
        "finding_id",
        "repository_id",
        "title",
        "found_by",
        "found_at",
        "missed_by",
        "reason",
        "validity",
    ],
)
def test_every_serialized_miss_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["misses"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("scope", ["view", "window", "miss"])
def test_unknown_fields_are_rejected_at_every_object_boundary(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    objects = {"view": document, "window": document["window"], "miss": document["misses"][0]}
    objects[scope]["unexpected"] = "not part of the contract"
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["finding_id", "repository_id", "found_by", "missed_by"])
@pytest.mark.parametrize("invalid", ["not-a-uuid", "00000000000040008000000000000001", "", None])
def test_invalid_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document["misses"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["start", "end", "found_at"])
@pytest.mark.parametrize(
    "invalid", ["yesterday", "2026-02-30T00:00:00Z", "2026-10-15T09:30:00", None]
)
def test_invalid_or_timezone_naive_timestamps_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    target = document["misses"][0] if field == "found_at" else document["window"]
    target[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("reason", "not-a-reason"), ("reason", None), ("validity", False), ("title", 1)],
)
def test_unknown_reason_and_nonstring_row_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document["misses"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("window", None), ("window", []), ("misses", None), ("misses", {}), ("misses", [None])],
)
def test_window_and_misses_keep_their_structured_types(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)
