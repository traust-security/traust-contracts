from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/pqc-portfolio.schema.json"
REF = "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _fact() -> dict[str, Any]:
    return {
        "fact_id": "F0001",
        "rule_id": "go-tls-curve-preferences",
        "file": "pkg/tls/config.go",
        "line": 12,
        "detail": "",
        "match": None,
        "provider": None,
        "pqc_capable": None,
        "fips_mode": None,
        "capability_hint": None,
        "finding_id": None,
        "severity": None,
        "risk": None,
        "confidence": None,
        "ir8547": {
            "qclass": "kex",
            "usage": "unknown",
            "clock": {"status_now": None, "deprecated_after": 2030, "disallowed_after": 2035},
            "matched_prefix": "",
            "qclass_resolved": None,
        },
        "provenance_hint": "native",
        "path_class": "first_party",
    }


def _readiness() -> dict[str, Any]:
    return {
        "assessment_id": "00000000-0000-4000-8000-000000000001",
        "repository_ref_id": REF,
        "assessed_at": "2026-10-01T00:00:00Z",
        "bucket": "not-ready",
        "overall": 42.5,
        "has_2030_clock_items": True,
        "hndl_priority": False,
        "runtime_verification_required": False,
        "dominant": "native-first-party",
        "who_sets_tls": None,
        "pqca": 30.0,
        "fips_interaction": None,
        "clock_items": [
            {
                "primitive": "ECDHE",
                "deprecated_after": 2030,
                "disallowed_after": 2035,
                "remediation_effort": "s",
                "blocked_external": None,
            }
        ],
        "remediations": [
            {
                "id": "SVC-abc1234-REM-001",
                "category": "fix-now",
                "action": "Prefer X25519MLKEM768.",
                "target": None,
                "details": None,
                "locations": ["pkg/tls/config.go:12"],
                "blocked_on": None,
                "remediation_effort": None,
                "blocked_external": None,
                "blast_radius": None,
                "deadline": None,
                "recipe": None,
            }
        ],
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "scopes": [
            {
                "product_id": None,
                "repositories": [
                    {"repository_url": "https://example.com/org/repo", "readiness": _readiness()}
                ],
                "sites": [
                    {
                        "repository_url": "https://example.com/org/repo",
                        "site": {"repository_ref_id": REF, "kind": "toolchain", "fact": _fact()},
                    }
                ],
                "packages": [{"package": "crypto/tls", "provider": None, "repositories": 1}],
                "without_sbom": 0,
            }
        ],
        "products": [
            {
                "product": "core",
                "repositories": 1,
                "not_ready": 1,
                "hndl_priority": 0,
                "clock_2030": 1,
                "worst_url": "https://example.com/org/repo",
                "worst_overall": 42.5,
            }
        ],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "scope": ("scopes", 0),
    "product": ("products", 0),
    "repository": ("scopes", 0, "repositories", 0),
    "readiness": ("scopes", 0, "repositories", 0, "readiness"),
    "clock_item": ("scopes", 0, "repositories", 0, "readiness", "clock_items", 0),
    "remediation": ("scopes", 0, "repositories", 0, "readiness", "remediations", 0),
    "site_row": ("scopes", 0, "sites", 0),
    "site": ("scopes", 0, "sites", 0, "site"),
    "fact": ("scopes", 0, "sites", 0, "site", "fact"),
    "ir8547": ("scopes", 0, "sites", 0, "site", "fact", "ir8547"),
    "clock": ("scopes", 0, "sites", 0, "site", "fact", "ir8547", "clock"),
    "package": ("scopes", 0, "packages", 0),
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


def test_a_product_scope_has_no_index(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["scopes"][0]["product_id"] = "00000000-0000-4000-8000-000000000009"
    document["products"] = []
    validator.validate(document)


def test_there_is_always_a_scope(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    document["scopes"] = []
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
    ("path", "invalid"),
    [
        (OBJECTS["readiness"] + ("overall",), 100.5),
        (OBJECTS["readiness"] + ("overall",), -1),
        (OBJECTS["readiness"] + ("pqca",), 101),
        (OBJECTS["product"] + ("worst_overall",), 101),
        (OBJECTS["product"] + ("repositories",), 0),
        (OBJECTS["package"] + ("repositories",), 0),
        (OBJECTS["scope"] + ("without_sbom",), -1),
    ],
)
def test_scores_and_counts_stay_in_range(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        OBJECTS["readiness"] + ("bucket",),
        OBJECTS["readiness"] + ("pqca",),
        OBJECTS["readiness"] + ("fips_interaction",),
        OBJECTS["product"] + ("worst_overall",),
        OBJECTS["clock_item"] + ("remediation_effort",),
        OBJECTS["remediation"] + ("blast_radius",),
        OBJECTS["ir8547"] + ("clock",),
    ],
)
def test_unknown_values_are_null(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...]
) -> None:
    _set(document, path, None)
    validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (OBJECTS["readiness"] + ("bucket",), "almost-ready"),
        (OBJECTS["readiness"] + ("dominant",), None),
        (OBJECTS["readiness"] + ("fips_interaction",), "fips"),
        (OBJECTS["remediation"] + ("category",), "later"),
        (OBJECTS["remediation"] + ("remediation_effort",), "huge"),
        (OBJECTS["site"] + ("kind",), "library"),
        (OBJECTS["fact"] + ("path_class",), "generated"),
        (OBJECTS["fact"] + ("fact_id",), "1"),
        (OBJECTS["readiness"] + ("assessed_at",), "2026-10-01"),
        (OBJECTS["readiness"] + ("repository_ref_id",), "not-a-uuid"),
    ],
)
def test_vocabularies_times_and_ids_are_checked(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("registry", "path"),
    [
        ("pqc-readiness-bucket", ("readiness", "bucket")),
        ("pqc-dominant-provenance", ("readiness", "dominant")),
        ("pqc-fips-interaction", ("readiness", "fips_interaction")),
        ("pqc-remediation-category", ("remediation", "category")),
        ("pqc-blast-radius", ("remediation", "blast_radius")),
        ("pqc-path-class", ("fact", "path_class")),
        ("remediation-effort", ("effort",)),
    ],
)
def test_vocabularies_match_their_registries(registry: str, path: tuple[str, ...]) -> None:
    values = json.loads((ROOT / f"enums/v1/{registry}.json").read_text())["values"]
    defs = json.loads(SCHEMA.read_text())["$defs"]
    node = defs[path[0]] if len(path) == 1 else defs[path[0]]["properties"][path[1]]
    assert [v for v in node["enum"] if v is not None] == values


def test_a_historical_bare_remediation_id_is_preserved(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    _set(document, OBJECTS["remediation"] + ("id",), "REM-001")
    validator.validate(document)


def test_an_unmatched_rule_prefix_is_empty_not_null(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    _set(document, OBJECTS["ir8547"] + ("matched_prefix",), "")
    validator.validate(document)
    _set(document, OBJECTS["ir8547"] + ("matched_prefix",), None)
    with pytest.raises(ValidationError):
        validator.validate(document)
