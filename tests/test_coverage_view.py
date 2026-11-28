from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/coverage.schema.json"
REPO = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _assessment(**overrides: Any) -> dict[str, Any]:
    assessment = {
        "id": "00000000-0000-4000-8000-000000000010",
        "created_at": "2026-10-01T10:00:00Z",
        "repository_ref_id": "00000000-0000-4000-8000-000000000011",
        "image_id": None,
        "baseline_assessment_id": None,
        "run_order_id": "00000000-0000-4000-8000-000000000012",
        "kind": "secure_code",
        "status": "completed",
        "assessor": "skill:secure-code-audit",
        "assessor_version": "1.4.0",
        "occurred_at": "2026-10-01T09:00:00+02:00",
    }
    return {**assessment, **overrides}


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "repositories": 2,
        "population": {
            "as_of": "2026-11-01T00:00:00Z",
            "rows": [
                {
                    "repository_id": REPO,
                    "kind": "secure_code",
                    "latest": _assessment(),
                    "default_line": 2,
                    "branches": 1,
                },
                {
                    "repository_id": REPO,
                    "kind": "threat_model",
                    "latest": None,
                    "default_line": 0,
                    "branches": 1,
                },
            ],
            "never_assessed_repository_ids": [OTHER],
        },
        "gaps": {
            "examined": 1,
            "total": 1,
            "gaps": [
                {
                    "tool": "opengrep",
                    "system": "kotlin",
                    "repositories": 1,
                    "items": None,
                    "signals": {"structured": 1},
                    "example_repository_ids": [REPO],
                }
            ],
        },
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "population": ("population",),
    "row": ("population", "rows", 0),
    "assessment": ("population", "rows", 0, "latest"),
    "coverage": ("gaps",),
    "gap": ("gaps", "gaps", 0),
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


def test_an_empty_scope_is_valid(validator: Draft202012Validator) -> None:
    validator.validate(
        {
            "repositories": 0,
            "population": {
                "as_of": "2026-11-01T00:00:00Z",
                "rows": [],
                "never_assessed_repository_ids": [],
            },
            "gaps": {"examined": 0, "total": 0, "gaps": []},
        }
    )


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
        ("repositories",),
        ("population", "rows", 0, "default_line"),
        ("population", "rows", 0, "branches"),
        ("gaps", "examined"),
        ("gaps", "total"),
    ],
)
@pytest.mark.parametrize("invalid", [-1, 1.5, "1", None, True])
def test_counts_are_nonnegative_integers(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["image_id", "baseline_assessment_id", "run_order_id"])
def test_optional_assessment_links_are_uuids_or_null(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    latest = document["population"]["rows"][0]["latest"]
    latest[field] = "00000000-0000-4000-8000-000000000099"
    validator.validate(document)
    latest[field] = None
    validator.validate(document)
    latest[field] = "not-a-uuid"
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["id", "created_at", "repository_ref_id", "occurred_at"])
def test_a_recorded_assessment_always_carries_its_identity_and_times(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    document["population"]["rows"][0]["latest"][field] = None
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("kind", ["secure_code", "container", "legacy-kind-preserved"])
def test_any_recorded_kind_is_preserved(
    validator: Draft202012Validator, document: dict[str, Any], kind: str
) -> None:
    document["population"]["rows"][0]["kind"] = kind
    document["population"]["rows"][0]["latest"]["kind"] = kind
    validator.validate(document)


@pytest.mark.parametrize("field", ["kind", "status", "assessor"])
def test_classifying_assessment_strings_are_never_empty(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    document["population"]["rows"][0]["latest"][field] = ""
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_an_empty_assessor_version_is_preserved(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["population"]["rows"][0]["latest"]["assessor_version"] = ""
    validator.validate(document)


def test_never_assessed_repositories_are_listed_once(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["population"]["never_assessed_repository_ids"] = [OTHER, OTHER]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("repositories", 0),
        ("items", -1),
        ("signals", {}),
        ("signals", {"structured": 0}),
        ("signals", {"guess": 1}),
        ("example_repository_ids", []),
        ("example_repository_ids", [REPO, REPO]),
        ("example_repository_ids", [f"00000000-0000-4000-8000-00000000010{i}" for i in range(9)]),
    ],
)
def test_a_gap_family_is_counted_signalled_and_exemplified(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    document["gaps"]["gaps"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("signals", [{"structured": 2, "steps": 1, "text": 3}, {"text": 1}])
def test_every_recording_signal_is_known(
    validator: Draft202012Validator, document: dict[str, Any], signals: dict[str, int]
) -> None:
    document["gaps"]["gaps"][0]["signals"] = signals
    document["gaps"]["gaps"][0]["items"] = 4
    validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("population", "as_of"),
        ("population", "rows", 0, "latest", "created_at"),
        ("population", "rows", 0, "latest", "occurred_at"),
    ],
)
@pytest.mark.parametrize("invalid", ["yesterday", "2026-02-30T00:00:00Z", "2026-11-01T00:00:00"])
def test_invalid_or_timezone_naive_timestamps_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: str
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("population", "rows", 0, "repository_id"),
        ("population", "never_assessed_repository_ids", 0),
        ("gaps", "gaps", 0, "example_repository_ids", 0),
    ],
)
@pytest.mark.parametrize("invalid", ["not-a-uuid", "", None])
def test_invalid_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize(
    "path",
    [
        ("gaps", "gaps", 0, "tool"),
        ("gaps", "gaps", 0, "system"),
        ("population", "rows", 0, "latest", "assessor"),
        ("population", "rows", 0, "latest", "assessor_version"),
    ],
)
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...]
) -> None:
    _set(document, path, UNTRUSTED)
    validator.validate(document)


def test_the_kind_description_names_the_registry() -> None:
    registry = json.loads((ROOT / "enums/v1/assessment-kind.json").read_text())
    kind = json.loads(SCHEMA.read_text())["$defs"]["kind"]
    assert "assessment-kind registry" in kind["description"]
    assert "secure_code" in registry["values"]
