from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
VIEWS = ROOT / "views_schema/v1"
SCHEMA = VIEWS / "executive-summary.schema.json"
ID = "00000000-0000-4000-8000-000000000001"
AS_OF = "2026-11-13T00:00:00Z"


def _registry() -> Registry:
    """Every view and artifact schema by its $id: the summary composes the component views."""
    resources = []
    for path in [
        *sorted(VIEWS.glob("*.schema.json")),
        *sorted((ROOT / "artifacts_schema/v1").glob("*.schema.json")),
    ]:
        doc = json.loads(path.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((VIEWS / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker())


@pytest.fixture
def validator() -> Draft202012Validator:
    return _validator("executive-summary")


def _counts(**counts: int) -> dict[str, int]:
    keys = ("critical", "high", "medium", "low", "informational", "unrated")
    return {k: counts.get(k, 0) for k in keys}


def _tally() -> dict[str, Any]:
    return {
        "open": _counts(high=1),
        "hardening": 0,
        "resolved": 0,
        "risk_accepted": 0,
        "false_positive": 0,
        "execution_proven": 0,
        "unverified": 1,
        "decided": 0,
        "remediated": _counts(),
        "tracked": 0,
    }


def _rollup() -> dict[str, Any]:
    return {
        "as_of": AS_OF,
        "total": _tally(),
        "products": [],
        "repositories": [],
        "top": [],
        "categories": [],
        "attack_scenarios": [],
    }


def _attack() -> dict[str, Any]:
    return {
        "as_of": AS_OF,
        "attack_version": "19.1",
        "mapping_version": "1.0.0",
        "attribution": "MITRE ATT&CK",
        "repositories": 0,
        "threat_models": 0,
        "threats_with_techniques": 0,
        "findings_mapped": 0,
        "techniques": [],
        "dropped": {},
        "navigator_layer": {
            "name": "coverage",
            "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": [],
        },
    }


def _pqc() -> dict[str, Any]:
    scope = {"product_id": None, "repositories": [], "sites": [], "packages": [], "without_sbom": 0}
    return {"scopes": [scope], "products": []}


def _register() -> dict[str, Any]:
    return {
        "as_of": AS_OF,
        "repository_urls": {},
        "models": 0,
        "threats": [],
        "quick_wins": [],
        "tenant_boundaries": [],
        "open_variances": [],
    }


def _leak() -> dict[str, Any]:
    return {
        "finding_id": ID,
        "repository_url": "https://forge.example/o/svc",
        "title": "AWS key in config",
        "severity": "medium",
        "cvss_score": None,
        "execution_proven": False,
        "sla_due": None,
    }


def _exposure_row() -> dict[str, Any]:
    return {
        "key": "GHSA-xxxx-xxxx-xxxx",
        "commits": 2,
        "exposed": 1,
        "affected": 1,
        "by_classification": {"affected": 1, "not_imported": 1},
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "rollup": _rollup(),
        "credential_leaks": [_leak()],
        "themes": {"injection": 2},
        "hardening_themes": {},
        "languages": [{"language": "go", "repositories": 1, "open": _counts(high=1)}],
        "privileges": {
            "profiles": 1,
            "privileged": 1,
            "scc_requesting": 0,
            "wildcard_repositories": 0,
            "wildcard_rules": 0,
            "flags": {"hostNetwork": 1},
        },
        "exposure": [_exposure_row()],
        "attack": _attack(),
        "pqc": _pqc(),
        "pqc_unavailable": None,
        "isolation": {
            "reviews": [
                {
                    "repository": "https://forge.example/o/svc",
                    "assessment_id": ID,
                    "service": "svc",
                    "posture": "weak",
                    "interfaces": 2,
                    "gaps": 1,
                    "dimensions": {"yes": 7, "partial": 2, "no": 1},
                }
            ],
            "threat_register": _register(),
        },
        "iac": {
            "repositories": 1,
            "assessments": 1,
            "findings": {"findings": _counts(low=1), "false_positives": 0},
            "targets": [
                {
                    "repository": "https://forge.example/o/infra",
                    "assessment_id": ID,
                    "target": "terraform/",
                    "unsuppressed": 1,
                    "suppressed": 0,
                    "needs_review": 0,
                    "ledgered": 0,
                    "severities": _counts(low=1),
                }
            ],
        },
    }


@pytest.mark.parametrize(
    ("name", "build"),
    [
        ("findings-rollup", _rollup),
        ("attack-coverage", _attack),
        ("pqc-portfolio", _pqc),
        ("threat-register", _register),
    ],
)
def test_the_embedded_panels_are_valid_component_views(name: str, build: Any) -> None:
    _validator(name).validate(build())


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_scoped_summary_without_panels_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    for panel in ("exposure", "attack", "pqc", "isolation", "iac"):
        document[panel] = None
    validator.validate(document)


def test_a_historical_pqc_panel_is_explained_not_built(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["pqc"] = None
    document["pqc_unavailable"] = "Historical PQC readiness is unavailable."
    validator.validate(document)
    document["pqc"] = _pqc()
    with pytest.raises(ValidationError):
        validator.validate(document)


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "credential_leak": ("credential_leaks", 0),
    "language": ("languages", 0),
    "privileges": ("privileges",),
    "isolation": ("isolation",),
    "isolation_review": ("isolation", "reviews", 0),
    "iac": ("iac",),
    "iac_target": ("iac", "targets", 0),
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
        (("rollup", "total"), None),
        (("attack", "navigator_layer", "domain"), "mobile-attack"),
        (("pqc", "scopes"), []),
        (("isolation", "threat_register", "models"), -1),
        (("exposure", 0, "commits"), 0),
        (("exposure", 0, "key"), None),
        (("exposure",), [_exposure_row()] * 11),
        (("iac", "findings", "false_positives"), -1),
        (OBJECTS["credential_leak"] + ("severity",), "severe"),
        (OBJECTS["credential_leak"] + ("cvss_score",), "11"),
        (OBJECTS["language"] + ("repositories",), 0),
        (OBJECTS["language"] + ("open",), {"high": 1}),
        (("themes",), {"injection": 0}),
        (OBJECTS["privileges"] + ("flags",), {"hostNetwork": 0}),
        (OBJECTS["isolation_review"] + ("posture",), "fine"),
        (OBJECTS["isolation_review"] + ("dimensions",), {"yes": 0}),
        (OBJECTS["iac_target"] + ("severities",), _counts() | {"unrated": -1}),
        (("pqc_unavailable",), ""),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("severity", [None, "critical", "low", "informational"])
def test_a_leak_can_be_any_severity_or_unrated(
    validator: Draft202012Validator, document: dict[str, Any], severity: str | None
) -> None:
    _set(document, OBJECTS["credential_leak"] + ("severity",), severity)
    validator.validate(document)


def _defs() -> dict[str, Any]:
    return json.loads(SCHEMA.read_text())["$defs"]


def test_leak_severities_match_the_severity_registry() -> None:
    values = json.loads((ROOT / "enums/v1/severity.json").read_text())["values"]
    node = _defs()["credential_leak"]["properties"]["severity"]
    assert [v for v in node["enum"] if v is not None] == values


def test_postures_match_the_isolation_posture_registry() -> None:
    values = json.loads((ROOT / "enums/v1/isolation-posture.json").read_text())["values"]
    assert _defs()["isolation_review"]["properties"]["posture"]["enum"] == values


def _refs(node: Any) -> list[str]:
    if isinstance(node, list):
        return [r for item in node for r in _refs(item)]
    if not isinstance(node, dict):
        return []
    own = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
    return own + [r for value in node.values() for r in _refs(value)]


def test_the_components_are_referenced_never_copied() -> None:
    views = {
        r.split("views_schema/v1/")[1].split(".schema.json")[0]
        for r in _refs(json.loads(SCHEMA.read_text()))
        if "views_schema/v1/" in r
    }
    assert views == {
        "findings-rollup",
        "attack-coverage",
        "pqc-portfolio",
        "threat-register",
        "exposure",
        "census",
    }


@pytest.mark.parametrize(
    "field", ["credential_leaks", "languages", ("isolation", "reviews"), ("iac", "targets")]
)
def test_only_exposure_of_the_lists_may_be_null(
    validator: Draft202012Validator, document: dict[str, Any], field: Any
) -> None:
    _set(document, field if isinstance(field, tuple) else (field,), None)
    with pytest.raises(ValidationError):
        validator.validate(document)
