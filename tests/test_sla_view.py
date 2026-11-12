from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/sla.schema.json"
COUNTS = (
    "open_in_sla",
    "open_overdue",
    "open_no_sla",
    "unclocked",
    "accepted",
    "resolved_met",
    "resolved_breached",
    "resolved_unclocked",
    "out_of_profile_scope",
)


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "policy_name": "example-policy",
        "source": {
            "name": "Example security standard",
            "url": "https://example.com/standard",
            "retrieved": "2026-10-01",
            "note": None,
        },
        "clock_start": "first_routed_or_filed",
        "as_of": "2026-11-01T00:00:00Z",
        "profiles": [
            {
                "profile": "default",
                "description": None,
                "counts": {**dict.fromkeys(COUNTS, 0), "open_overdue": 1, "resolved_met": 3},
                "resolved_compliance_pct": 75.0,
                "median_days_to_resolve": {"high": 12, "unrated": -2},
                "overdue_by_severity": {"critical": 1},
                "teams": [{"team": "(unassigned)", "overdue": 1, "critical": 1, "worst_days": 4}],
                "escalations": [
                    {
                        "finding_id": "00000000-0000-4000-8000-000000000001",
                        "repository_url": "https://example.com/org/repo",
                        "severity": "critical",
                        "title": "Unbounded input allocation",
                        "teams": ["(unassigned)"],
                        "due": "2026-10-28T00:00:00+02:00",
                        "days_overdue": 4,
                        "clock_basis": "filed",
                    }
                ],
            }
        ],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "source": ("source",),
    "profile": ("profiles", 0),
    "counts": ("profiles", 0, "counts"),
    "team": ("profiles", 0, "teams", 0),
    "escalation": ("profiles", 0, "escalations", 0),
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


def test_a_profile_with_nothing_to_report_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    profile = document["profiles"][0]
    profile.update(
        counts=dict.fromkeys(COUNTS, 0),
        resolved_compliance_pct=None,
        median_days_to_resolve={},
        overdue_by_severity={},
        teams=[],
        escalations=[],
    )
    validator.validate(document)


def test_a_policy_has_at_least_one_profile(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["profiles"] = []
    with pytest.raises(ValidationError):
        validator.validate(document)


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
    "path",
    [
        *(("profiles", 0, "counts", c) for c in COUNTS),
        ("profiles", 0, "teams", 0, "critical"),
        ("profiles", 0, "teams", 0, "worst_days"),
        ("profiles", 0, "escalations", 0, "days_overdue"),
    ],
)
@pytest.mark.parametrize("invalid", [-1, 1.5, "1", None, True])
def test_counts_are_nonnegative_integers(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_median_resolve_time_can_be_negative(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["profiles"][0]["median_days_to_resolve"] = {"critical": -5}
    validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("median_days_to_resolve", {"severe": 1}),
        ("median_days_to_resolve", {"high": 1.5}),
        ("overdue_by_severity", {"critical": 0}),
        ("overdue_by_severity", {"urgent": 1}),
    ],
)
def test_severity_maps_carry_known_keys_and_counted_values(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document["profiles"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("pct", [-0.1, 100.1, "75"])
def test_compliance_is_a_percentage_or_null(
    validator: Draft202012Validator, document: dict[str, Any], pct: Any
) -> None:
    document["profiles"][0]["resolved_compliance_pct"] = pct
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_team_row_has_at_least_one_overdue_finding(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["profiles"][0]["teams"][0]["overdue"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_the_digest_holds_at_most_100_escalations(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    escalation = document["profiles"][0]["escalations"][0]
    document["profiles"][0]["escalations"] = [escalation] * 100
    validator.validate(document)
    document["profiles"][0]["escalations"].append(escalation)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("severity", "unrated"),
        ("severity", ""),
        ("clock_basis", "unclocked"),
        ("clock_basis", "audit"),
        ("teams", []),
        ("title", "x" * 121),
    ],
)
def test_an_escalation_is_well_formed(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document["profiles"][0]["escalations"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_an_unrated_escalation_is_null_severity(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["profiles"][0]["escalations"][0]["severity"] = None
    validator.validate(document)


@pytest.mark.parametrize("clock_start", ["first_routed_or_filed", "first_event", "audit_date"])
def test_every_registered_clock_start_is_accepted(
    validator: Draft202012Validator, document: dict[str, Any], clock_start: str
) -> None:
    document["clock_start"] = clock_start
    validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("as_of",), "2026-11-01T00:00:00"),
        (("as_of",), None),
        (("source", "retrieved"), "2026-02-30"),
        (("source", "retrieved"), "yesterday"),
        (("profiles", 0, "escalations", 0, "due"), "2026-10-28"),
        (("profiles", 0, "escalations", 0, "finding_id"), "not-a-uuid"),
    ],
)
def test_invalid_times_and_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize(
    "path",
    [
        ("policy_name",),
        ("source", "name"),
        ("source", "note"),
        ("profiles", 0, "profile"),
        ("profiles", 0, "description"),
        ("profiles", 0, "teams", 0, "team"),
        ("profiles", 0, "escalations", 0, "title"),
        ("profiles", 0, "escalations", 0, "repository_url"),
    ],
)
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...]
) -> None:
    _set(document, path, UNTRUSTED)
    validator.validate(document)


def test_vocabularies_match_their_registries() -> None:
    schema = json.loads(SCHEMA.read_text())
    clock = json.loads((ROOT / "enums/v1/sla-clock-start.json").read_text())["values"]
    severity = json.loads((ROOT / "enums/v1/severity.json").read_text())["values"]
    scanner = json.loads((ROOT / "enums/v1/scanner-severity.json").read_text())["values"]
    assert schema["properties"]["clock_start"]["enum"] == clock
    escalation = schema["$defs"]["escalation"]["properties"]
    assert escalation["severity"]["enum"] == [*severity, None]
    assert schema["$defs"]["severity_key"]["enum"] == scanner
