from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/loc.schema.json"
REPO, OTHER, REF = (f"00000000-0000-4000-8000-00000000000{n}" for n in (1, 2, 3))


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def _language(name: str, code: int) -> dict[str, Any]:
    return {"name": name, "files": 3, "code": code, "comments": None, "blanks": 10}


def _measured() -> dict[str, Any]:
    return {
        "repository_id": REPO,
        "repository_url": "https://forge.example/o/a",
        "repository_ref_id": REF,
        "code_delta": 40,
        "total_delta": -2,
        "code": 1200,
        "total": 1300,
        "primary": "Go",
        "languages": [_language("Go", 1200), _language("Markdown", 100)],
        "unmeasured": None,
    }


def _unmeasured() -> dict[str, Any]:
    return {
        "repository_id": OTHER,
        "repository_url": "https://forge.example/o/b",
        "repository_ref_id": None,
        "code_delta": None,
        "total_delta": None,
        "code": None,
        "total": None,
        "primary": None,
        "languages": [],
        "unmeasured": "no observed default-branch head",
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "code": 1200,
        "as_of": "2026-11-15T00:00:00Z",
        "comparison": {
            "as_of": "2026-10-15T00:00:00Z",
            "code": 1160,
            "total": 1302,
            "measured_repositories": 1,
            "comparable_repositories": 1,
            "code_delta": 40,
            "total_delta": -2,
        },
        "first_party_divisor": "1E+2",
        "first_party_estimate": "12",
        "total": 1300,
        "reported": 2,
        "dispositioned": 1,
        "languages": [
            {"name": "Go", "code": 1200, "repositories": 1, "documentation": False},
            {"name": "Markdown", "code": 100, "repositories": 1, "documentation": True},
        ],
        "repositories": [_measured(), _unmeasured()],
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_view_without_comparison_or_divisor_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document |= {"comparison": None, "first_party_divisor": None, "first_party_estimate": None}
    for row in document["repositories"]:
        row |= {"code_delta": None, "total_delta": None}
    validator.validate(document)


def test_an_empty_scope_is_valid(validator: Draft202012Validator) -> None:
    validator.validate(
        {
            "code": 0,
            "as_of": "2026-11-15T00:00:00Z",
            "comparison": None,
            "first_party_divisor": "3",
            "first_party_estimate": None,
            "total": 0,
            "reported": 0,
            "dispositioned": 0,
            "languages": [],
            "repositories": [],
        }
    )


@pytest.mark.parametrize(
    "value", ["3", "3.333333333333333333333333333", "0E+1", "5E+9", "1.5E-7", "0.07"]
)
def test_decimals_are_python_decimal_strings(
    validator: Draft202012Validator, document: dict[str, Any], value: str
) -> None:
    validator.validate(document | {"first_party_estimate": value})


@pytest.mark.parametrize("value", ["0", "0.000", "0E+2", "-1", "1e2", "1,5", "", 3])
def test_the_divisor_is_a_positive_decimal_string(
    validator: Draft202012Validator, document: dict[str, Any], value: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"first_party_divisor": value})


def test_a_measured_repository_with_no_languages_has_no_primary(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["repositories"][0] |= {"languages": [], "primary": None, "code": 0, "total": 0}
    validator.validate(document)


@pytest.mark.parametrize(
    "field",
    ["code", "as_of", "comparison", "first_party_divisor", "first_party_estimate", "total",
     "reported", "dispositioned", "languages", "repositories"],
)  # fmt: skip
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        *(("comparison", f) for f in ("as_of", "code", "total", "measured_repositories",
                                      "comparable_repositories", "code_delta", "total_delta")),
        *(("language", f) for f in ("name", "code", "repositories", "documentation")),
        *(("repository", f) for f in _measured()),
        *(("count", f) for f in _language("Go", 1)),
    ],
)  # fmt: skip
def test_every_serialized_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], target: str, field: str
) -> None:
    repository = document["repositories"][0]
    {
        "comparison": document["comparison"],
        "language": document["languages"][0],
        "repository": repository,
        "count": repository["languages"][0],
    }[target].pop(field)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "comparison", "language", "repository", "count"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    repository = document["repositories"][0]
    {
        "view": document,
        "comparison": document["comparison"],
        "language": document["languages"][0],
        "repository": repository,
        "count": repository["languages"][0],
    }[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("code",), -1),
        (("total",), -1),
        (("reported",), -1),
        (("dispositioned",), -1),
        (("as_of",), None),
        (("as_of",), "yesterday"),
        (("first_party_estimate",), "-3"),
        (("comparison", "as_of"), "2026-10-15"),
        (("comparison", "measured_repositories"), -1),
        (("comparison", "code_delta"), None),
        (("languages", 0, "name"), ""),
        (("languages", 0, "code"), -1),
        (("languages", 0, "repositories"), 0),
        (("languages", 0, "documentation"), None),
        (("repositories", 0, "repository_id"), "a"),
        (("repositories", 0, "repository_ref_id"), "a"),
        (("repositories", 0, "code"), -1),
        (("repositories", 0, "primary"), ""),
        (("repositories", 0, "languages", 0, "code"), -1),
        (("repositories", 0, "languages", 0, "files"), -1),
        (("repositories", 1, "unmeasured"), ""),
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


def test_an_estimate_needs_its_divisor(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"first_party_divisor": None})


@pytest.mark.parametrize(
    ("row", "change"),
    [
        (0, {"repository_ref_id": None}),
        (0, {"code": None}),
        (0, {"total": None}),
        (1, {"code": 0}),
        (1, {"total": 0}),
        (1, {"code_delta": 0, "total_delta": 0}),
        (1, {"primary": "Go", "languages": [_language("Go", 1)]}),
    ],
)
def test_counts_are_present_exactly_when_measured(
    validator: Draft202012Validator, document: dict[str, Any], row: int, change: dict[str, Any]
) -> None:
    document["repositories"][row] |= change
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "change",
    [{"primary": None}, {"languages": []}, {"code_delta": None}, {"total_delta": None}],
)
def test_primary_follows_languages_and_deltas_come_in_pairs(
    validator: Draft202012Validator, document: dict[str, Any], change: dict[str, Any]
) -> None:
    document["repositories"][0] |= change
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_language_counts_are_the_code_facts_definition() -> None:
    repository = json.loads(SCHEMA.read_text())["$defs"]["repository"]
    ref = repository["properties"]["languages"]["items"]["$ref"]
    assert ref.endswith("artifacts_schema/v1/code-facts.schema.json#/$defs/language")
