from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/pqc-vendors.schema.json"
ARTIFACT = ROOT / "artifacts_schema/v1/pqc-vendor-claims.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def _claim(**overrides: Any) -> dict[str, Any]:
    return {
        "id": "example-lib",
        "name": "Example TLS library",
        "class": "library",
        "packages": [
            {"name": "example-tls", "ecosystem": "go"},
            {"name": "tls", "ecosystem": None},
        ],
        "status": "partial",
        "claim": "Hybrid key exchange shipped; signatures announced.",
        "watch": None,
        "sources": [
            {"url": "https://vendor.example/pqc", "title": None, "retrieved": "2026-11-01"}
        ],
        "last_reviewed": "2026-11-01",
        "reviewer": "crypto-review",
    } | overrides


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "claims_artifact_id": "00000000-0000-4000-8000-000000000001",
        "version": 3,
        "updated": "2026-11-01",
        "vendors": [
            {"claim": _claim(), "repositories": 4},
            {
                "claim": _claim(**{"id": "example-toolchain", "class": "provider", "packages": []}),
                "repositories": None,
            },
        ],
        "repositories": 10,
        "unmeasured": 2,
        "blocked_external": ["https://forge.example/o/a", "https://forge.example/o/b"],
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_empty_roadmap_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    validator.validate(
        document | {"vendors": [], "repositories": 0, "unmeasured": 0, "blocked_external": []}
    )


def test_optional_claim_fields_may_be_present(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    claim = document["vendors"][0]["claim"]
    claim["watch"] = "Signature support in the next release."
    claim["sources"][0]["title"] = "PQC roadmap"
    validator.validate(document)


@pytest.mark.parametrize(
    "field",
    [
        "claims_artifact_id",
        "version",
        "updated",
        "vendors",
        "repositories",
        "unmeasured",
        "blocked_external",
    ],
)
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("row", "claim"),
        ("row", "repositories"),
        *(("claim", f) for f in _claim()),
        ("package", "ecosystem"),
        ("source", "title"),
    ],
)
def test_every_serialized_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], target: str, field: str
) -> None:
    row = document["vendors"][0]
    claim = row["claim"]
    {"row": row, "claim": claim, "package": claim["packages"][1], "source": claim["sources"][0]}[
        target
    ].pop(field)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "row", "claim", "package", "source"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    row = document["vendors"][0]
    claim = row["claim"]
    {
        "view": document,
        "row": row,
        "claim": claim,
        "package": claim["packages"][0],
        "source": claim["sources"][0],
    }[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("claims_artifact_id",), "not-a-uuid"),
        (("version",), 0),
        (("updated",), "2026-13-01"),
        (("repositories",), -1),
        (("unmeasured",), -1),
        (("blocked_external",), [None]),
        (("vendors", 0, "repositories"), -1),
        (("vendors", 0, "claim", "id"), "Example"),
        (("vendors", 0, "claim", "name"), ""),
        (("vendors", 0, "claim", "class"), "vendor"),
        (("vendors", 0, "claim", "status"), "unknown"),
        (("vendors", 0, "claim", "claim"), ""),
        (("vendors", 0, "claim", "watch"), ""),
        (("vendors", 0, "claim", "sources"), []),
        (("vendors", 0, "claim", "last_reviewed"), "yesterday"),
        (("vendors", 0, "claim", "reviewer"), ""),
        (("vendors", 0, "claim", "packages", 0, "name"), ""),
        (("vendors", 0, "claim", "packages", 0, "ecosystem"), "cobol"),
        (("vendors", 0, "claim", "sources", 0, "url"), "not a uri"),
        (("vendors", 0, "claim", "sources", 0, "title"), ""),
        (("vendors", 0, "claim", "sources", 0, "retrieved"), "2026-11-32"),
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


def test_a_claim_naming_packages_carries_a_count(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["vendors"][0]["repositories"] = None
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_claim_naming_no_package_has_no_count(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["vendors"][1]["repositories"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_zero_count_is_valid_for_a_claim_naming_packages(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["vendors"][0]["repositories"] = 0
    validator.validate(document)


def test_claim_vocabularies_are_the_artifacts() -> None:
    claim = json.loads(SCHEMA.read_text())["$defs"]["claim"]["properties"]
    base = ARTIFACT.name + "#/$defs/"
    assert claim["class"]["$ref"].endswith(base + "vendor_class")
    assert claim["status"]["$ref"].endswith(base + "status")
