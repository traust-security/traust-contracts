from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/census.schema.json"
SEVERITIES = ("critical", "high", "medium", "low", "informational", "unrated")
CUT_COUNTS = (
    "products",
    "repositories",
    "audited",
    "audits",
    "branch_audits",
    "occurrences",
    "hardening",
    "false_positives",
    "dispositioned",
    "branch_confirmed",
    "branch_only",
)


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _counts(**values: int) -> dict[str, int]:
    return {s: values.get(s, 0) for s in SEVERITIES}


def _cut(ownership: str | None, **values: int) -> dict[str, Any]:
    return {
        "ownership": ownership,
        **dict.fromkeys(CUT_COUNTS, 0),
        "distinct": _counts(),
        "open": _counts(),
        **values,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    owned = _cut("owned", products=1, repositories=1, audited=1, audits=2, occurrences=3)
    owned.update(distinct=_counts(critical=1, high=1, unrated=1), open=_counts(high=1, unrated=1))
    return {
        "as_of": "2026-11-01T00:00:00Z",
        "repositories": 3,
        "reported": 2,
        "dispositioned": 1,
        "never_assessed": 1,
        "cuts": [owned, _cut("upstream", products=1, repositories=1), _cut(None, repositories=1)],
        "products": [
            {
                "product_id": "00000000-0000-4000-8000-000000000001",
                "slug": "core",
                "name": "Core",
                "ownership": "owned",
                "business_unit": "core unit",
                "repositories": 1,
            },
            {
                "product_id": "00000000-0000-4000-8000-000000000002",
                "slug": "loose",
                "name": "Loose",
                "ownership": None,
                "business_unit": None,
                "repositories": 0,
            },
        ],
        "cloud_config": {"findings": _counts(unrated=2), "false_positives": 0},
        "container": {"findings": _counts(), "false_positives": 1},
        "unregistered": ["https://example.com/org/stray"],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "cut": ("cuts", 0),
    "severity_counts": ("cuts", 0, "distinct"),
    "product": ("products", 0),
    "layer": ("cloud_config",),
}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_empty_corpus_is_valid(validator: Draft202012Validator) -> None:
    empty_layer = {"findings": _counts(), "false_positives": 0}
    validator.validate(
        {
            "as_of": "2026-11-01T00:00:00Z",
            "repositories": 0,
            "reported": 0,
            "dispositioned": 0,
            "never_assessed": 0,
            "cuts": [],
            "products": [],
            "cloud_config": empty_layer,
            "container": empty_layer,
            "unregistered": [],
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
        ("reported",),
        ("dispositioned",),
        ("never_assessed",),
        *(("cuts", 0, c) for c in CUT_COUNTS),
        ("cuts", 0, "distinct", "unrated"),
        ("cloud_config", "false_positives"),
        ("container", "findings", "high"),
        ("products", 0, "repositories"),
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


@pytest.mark.parametrize("ownership", ["owned", "upstream", "external-bu", "harness-qa"])
def test_each_registered_class_holds_at_most_one_cut(
    validator: Draft202012Validator, document: dict[str, Any], ownership: str
) -> None:
    document["cuts"] = [_cut(ownership)]
    validator.validate(document)
    document["cuts"].append(_cut(ownership))
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_there_is_at_most_one_unregistered_cut(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["cuts"].append(_cut(None))
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("ownership", ["Owned", "partner", ""])
def test_unknown_ownership_classes_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], ownership: str
) -> None:
    document["products"][0]["ownership"] = ownership
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_every_severity_key_is_always_present(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    del document["cloud_config"]["findings"]["unrated"]
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_unregistered_repositories_are_listed_once(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["unregistered"] *= 2
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("as_of",), "2026-11-01T00:00:00"),
        (("as_of",), None),
        (("products", 0, "product_id"), "not-a-uuid"),
    ],
)
def test_invalid_times_and_identifiers_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize("field", ["name", "business_unit", "slug"])
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    document["products"][0][field] = UNTRUSTED
    document["unregistered"] = [UNTRUSTED]
    validator.validate(document)


def test_vocabularies_match_their_registries() -> None:
    schema = json.loads(SCHEMA.read_text())
    ownership = json.loads((ROOT / "enums/v1/ownership.json").read_text())["values"]
    scanner = json.loads((ROOT / "enums/v1/scanner-severity.json").read_text())["values"]
    assert schema["$defs"]["ownership"]["enum"] == ownership
    assert list(schema["$defs"]["severity_counts"]["properties"]) == scanner
