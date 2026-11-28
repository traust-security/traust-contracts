from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/threat-register.schema.json"
MODEL = "00000000-0000-4000-8000-000000000001"
REPO = "00000000-0000-4000-8000-000000000002"
ARTIFACT = "00000000-0000-4000-8000-000000000003"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _threat() -> dict[str, Any]:
    return {
        "assessment_id": MODEL,
        "repository_id": REPO,
        "label": "T1",
        "title": "Cross-tenant data theft via SQL injection",
        "status": "unmitigated",
        "actor": "remote_auth",
        "actors": ["remote_auth", "insider"],
        "severity": None,
        "likelihood": "likely",
        "impact": "critical",
        "surface": "tenant API",
        "asset": None,
        "controls": None,
        "evidence": ["pkg/api/query.go:42"],
        "techniques": [{"id": "T1190"}],
        "isolation_dimensions": ["connectivity"],
        "boundary_ids": ["IF-1"],
        "isolation_review_ref": None,
        "mitigations": [
            {
                "text": "Parameterize the tenant query",
                "closes_class": "yes",
                "effort": "s",
                "blocked_external": None,
            }
        ],
        "linddun": False,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-11-13T00:00:00Z",
        "repository_urls": {REPO: "https://forge.example/o/svc"},
        "models": 1,
        "threats": [{"threat": _threat(), "band": "critical", "crosswalked": True}],
        "quick_wins": [
            {
                "repository_id": REPO,
                "mitigation": "Parameterize the tenant query",
                "effort": "s",
                "covers": ["T1"],
                "band": "critical",
                "blocked_external": None,
            }
        ],
        "tenant_boundaries": [
            {
                "boundary": {
                    "assessment_id": MODEL,
                    "repository_id": REPO,
                    "boundary_id": "IF-1",
                    "interface": "tenant API",
                    "kind": "api",
                    "exposure": "tenant",
                    "complexity": "high",
                    "dimensions": {"connectivity": "no", "privilege": "partial"},
                    "threat_ids": ["T1"],
                    "isolation_review_ref": None,
                },
                "weakness": 3,
                "failed": ["connectivity"],
                "partial": ["privilege"],
                "open_threats": ["T1"],
            }
        ],
        "open_variances": [
            {
                "repository_id": REPO,
                "record": "DV-001",
                "kind": "overclaim",
                "disposition": "open",
                "product_slug": "example-product",
                "version": "1.0",
                "claim": "Tenants are isolated at the network layer.",
                "verified_at": "2026-11-01T00:00:00Z",
                "artifact": {"id": ARTIFACT, "name": "doc-variance-register", "digest": "a" * 64},
            }
        ],
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "ranked_threat": ("threats", 0),
    "threat": ("threats", 0, "threat"),
    "technique": ("threats", 0, "threat", "techniques", 0),
    "mitigation": ("threats", 0, "threat", "mitigations", 0),
    "quick_win": ("quick_wins", 0),
    "ranked_boundary": ("tenant_boundaries", 0),
    "boundary": ("tenant_boundaries", 0, "boundary"),
    "doc_variance": ("open_variances", 0),
    "artifact": ("open_variances", 0, "artifact"),
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


def test_an_empty_register_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    for key in ("threats", "quick_wins", "tenant_boundaries", "open_variances"):
        document[key] = []
    document["repository_urls"], document["models"] = {}, 0
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
        (("models",), -1),
        (("as_of",), "2026-11-13"),
        (("repository_urls",), {"not-a-uuid": "https://forge.example/o/svc"}),
        (OBJECTS["threat"] + ("repository_id",), None),
        (OBJECTS["threat"] + ("status",), "open"),
        (OBJECTS["threat"] + ("actor",), "anyone"),
        (OBJECTS["threat"] + ("actors",), ["anyone"]),
        (OBJECTS["threat"] + ("severity",), "severe"),
        (OBJECTS["threat"] + ("likelihood",), "sometimes"),
        (OBJECTS["threat"] + ("impact",), "huge"),
        (OBJECTS["threat"] + ("isolation_dimensions",), ["tenancy"]),
        (OBJECTS["threat"] + ("mitigations",), None),
        (OBJECTS["ranked_threat"] + ("band",), "severe"),
        (OBJECTS["quick_win"] + ("effort",), "m"),
        (OBJECTS["quick_win"] + ("band",), "medium"),
        (OBJECTS["quick_win"] + ("covers",), []),
        (OBJECTS["ranked_boundary"] + ("weakness",), -1),
        (OBJECTS["ranked_boundary"] + ("failed",), ["connectivity", "connectivity"]),
        (OBJECTS["boundary"] + ("complexity",), "extreme"),
        (OBJECTS["boundary"] + ("dimensions",), {"tenancy": "no"}),
        (OBJECTS["doc_variance"] + ("disposition",), "accepted"),
        (OBJECTS["doc_variance"] + ("kind",), "wrong"),
        (OBJECTS["doc_variance"] + ("verified_at",), "yesterday"),
        (OBJECTS["artifact"] + ("digest",), "A" * 64),
        (OBJECTS["artifact"] + ("digest",), "a" * 64 + "\n"),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (OBJECTS["ranked_threat"] + ("band",), None),
        (OBJECTS["threat"] + ("likelihood",), None),
        (OBJECTS["threat"] + ("impact",), None),
        (OBJECTS["threat"] + ("severity",), "high"),
        (OBJECTS["technique"] + ("id",), "T9999.99"),
        (OBJECTS["mitigation"] + ("effort",), "XS"),
        (OBJECTS["mitigation"] + ("effort",), None),
        (OBJECTS["mitigation"] + ("blocked_external",), True),
        (OBJECTS["quick_win"] + ("effort",), "XS"),
        (OBJECTS["boundary"] + ("complexity",), None),
        (OBJECTS["boundary"] + ("dimensions",), {"hygiene": "unclear"}),
        (OBJECTS["doc_variance"] + ("kind",), None),
    ],
)
def test_nulls_and_raw_values_core_serves_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], value: Any
) -> None:
    _set(document, path, value)
    validator.validate(document)


def _defs() -> dict[str, Any]:
    return json.loads(SCHEMA.read_text())["$defs"]


@pytest.mark.parametrize(
    ("registry", "node"),
    [
        ("risk-rating-band", lambda d: d["band"]),
        ("isolation-dimension", lambda d: d["dimension"]),
        ("threat-actor", lambda d: d["actor"]),
        ("threat-status", lambda d: d["threat"]["properties"]["status"]),
        ("threat-likelihood", lambda d: d["threat"]["properties"]["likelihood"]),
        ("threat-impact", lambda d: d["threat"]["properties"]["impact"]),
        ("interface-complexity", lambda d: d["boundary"]["properties"]["complexity"]),
        ("doc-variance-kind", lambda d: d["doc_variance"]["properties"]["kind"]),
        (
            "isolation-dimension",
            lambda d: d["boundary"]["properties"]["dimensions"]["propertyNames"],
        ),
    ],
)
def test_vocabularies_match_their_registries(registry: str, node: Any) -> None:
    values = json.loads((ROOT / f"enums/v1/{registry}.json").read_text())["values"]
    assert [v for v in node(_defs())["enum"] if v is not None] == values


def test_quick_win_sizes_are_the_registry_values_that_normalize_to_xs_or_s() -> None:
    registry = json.loads((ROOT / "enums/v1/mitigation-effort.json").read_text())
    small = {"xs", "s"}

    def canonical(value: str) -> set[str]:
        replaced = registry.get("deprecated", {}).get(value, {}).get("replaced_by")
        return {r["value"] for r in replaced} if replaced else {value}

    expected = [v for v in registry["values"] if canonical(v) & small]
    assert _defs()["quick_win"]["properties"]["effort"]["enum"] == expected


def test_quick_win_bands_are_the_top_two_risk_bands() -> None:
    bands = json.loads((ROOT / "enums/v1/risk-rating-band.json").read_text())["values"]
    assert _defs()["quick_win"]["properties"]["band"]["enum"] == bands[:2]


def test_the_variance_disposition_is_the_registry_open_value() -> None:
    values = json.loads((ROOT / "enums/v1/doc-variance-disposition.json").read_text())["values"]
    assert _defs()["doc_variance"]["properties"]["disposition"]["enum"] == [values[0]] == ["open"]
