from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/dependency-reach.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "repositories": 5,
        "unmeasured": 2,
        "ecosystems": [
            {"ecosystem": "go", "repositories": 3, "packages": 40},
            {"ecosystem": "npm", "repositories": 1, "packages": 12},
        ],
        "shared": [{"ecosystem": "go", "name": "golang.org/x/net", "repositories": 3}],
    }


OBJECTS = {"view": (), "ecosystem": ("ecosystems", 0), "package": ("shared", 0)}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_scope_with_no_manifests_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"repositories": 3, "unmeasured": 3, "ecosystems": [], "shared": []})


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
        ("view", "repositories", -1),
        ("view", "unmeasured", -1),
        ("view", "shared", [{"ecosystem": "go", "name": "x", "repositories": 1}] * 26),
        ("ecosystem", "ecosystem", ""),
        ("ecosystem", "repositories", 0),
        ("ecosystem", "packages", 0),
        ("package", "ecosystem", ""),
        ("package", "name", ""),
        ("package", "repositories", 0),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], scope: str, field: str, invalid: Any
) -> None:
    _object(document, scope)[field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_stored_ecosystem_outside_todays_registry_is_still_served(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    # the store requires only a non-empty ecosystem; the registry is checked at intake
    document["ecosystems"][0]["ecosystem"] = "conda"
    document["shared"][0]["ecosystem"] = "conda"
    validator.validate(document)


def test_the_full_top_25_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["shared"] = [
        {"ecosystem": "go", "name": f"m{i}", "repositories": 1} for i in range(25)
    ]
    validator.validate(document)
