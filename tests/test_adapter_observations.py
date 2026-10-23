"""Scanner observations retain report constraints without fabricating authored findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from traust_contracts.models import AdapterResult, Finding

SCHEMA_DIR = Path(__file__).parent.parent / "schemas" / "v1"
OPTIONAL_NONEMPTY_ARRAYS = (
    ("peach_references", "PEACH-P"),
    ("owasp_llm_references", "LLM01"),
    ("isolation_dimensions", "privilege"),
)


@pytest.fixture
def schemas() -> dict[str, Any]:
    return {
        name: json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
        for name in ("adapter-result", "report")
    }


def _validator(
    schemas: dict[str, Any], name: str = "adapter-result", definition: str | None = None
) -> Draft202012Validator:
    registry = Registry(
        resources={schema["$id"]: Resource.from_contents(schema) for schema in schemas.values()}
    )
    schema = schemas[name]
    if definition is not None:
        schema = {"$ref": f"{schema['$id']}#/$defs/{definition}"}
    return Draft202012Validator(schema, registry=registry)


@pytest.fixture
def sparse() -> dict[str, Any]:
    return {
        "id": "native:rule/observation#1",
        "title": "x",
        "severity": "high",
        "cwes": [],
        "locations": [{"path": "config/example.env", "lines": "12"}],
        "description": "",
        "remediation": "",
    }


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": "example/repository",
        "scanned_at": "2026-10-23T00:00:00Z",
        "metadata": {"tool": "native-scanner", "scanner_version": "1.0"},
        "findings": [finding],
        "summary": {"total": 1, "by_severity": {"high": 1}},
        "focus_areas": [],
    }


@pytest.fixture
def historical() -> dict[str, Any]:
    return {
        "id": "EXAMPLE-abc1234-001",
        "title": "Historical dependency finding",
        "severity": "high",
        "cwes": ["CWE-79"],
        "locations": [{"path": "package.json", "lines": "12", "description": "Dependency"}],
        "description": (
            "A historical finding with the complete authored description retained unchanged."
        ),
        "remediation": "Upgrade the affected dependency.",
        "asvs_references": ["V5.1.1"],
        "peach_references": ["PEACH-P"],
        "owasp_llm_references": ["LLM01"],
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "capec": ["CAPEC-63"],
        "evidence": [{"code": "dependency@1.0.0", "language": "text", "caption": "Version"}],
        "attack_pattern": "An attacker reaches the affected dependency.",
        "category": "historical-free-form-category",
        "validation_status": "not_verified",
        "source_findings": ["native:advisory"],
        "origin": "impact-analysis",
        "pqc_classification": "pqc-adoption",
        "remediation_effort": "moderate",
        "blocked_external": False,
        "isolation_dimensions": ["privilege"],
        "isolation_boundary": "tenant-api",
        "disposition": {
            "validity": "not_verified",
            "resolution": "open",
            "last_updated": "2026-10-23T00:00:00Z",
            "events": [],
        },
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v3",
        "effective_severity": "high",
        "passes": [1, 2],
        "dependency": {
            "advisory": "GHSA-example",
            "module": "example-package",
            "ecosystem": "npm",
            "purl": "pkg:npm/example-package@1.0.0",
            "vulnerable_range": "<2.0.0",
            "fixed_version": "2.0.0",
            "installed_version": "1.0.0",
            "evidence_level": "manifest",
            "classification": "likely_affected",
            "impact_artifact": "impact-analysis.json",
        },
    }


def test_sparse_observation_survives_nested_serialization(schemas, sparse):
    result = AdapterResult.from_dict(_result(sparse))
    for data in (result.to_dict(), json.loads(result.model_dump_json(exclude_none=True))):
        _validator(schemas).validate(data)
        _validator(schemas, definition="canonical_write").validate(data)
        finding = data["findings"][0]
        assert {key: finding[key] for key in sparse} == sparse
        for field, _ in OPTIONAL_NONEMPTY_ARRAYS:
            assert field not in finding
        for field in ("validation_status", "disposition", "fingerprint", "fingerprint_algo"):
            assert field not in finding
        assert finding["evidence"] == []


def test_adapter_finding_preserves_all_main_report_fields(schemas):
    adapter = schemas["adapter-result"]
    report_finding = schemas["report"]["$defs"]["finding"]
    observation = adapter["$defs"]["adapter_finding"]
    assert adapter["properties"]["findings"]["items"] == {"$ref": "#/$defs/adapter_finding"}
    assert "finding" not in adapter["$defs"]
    assert observation["required"] == report_finding["required"]
    assert observation["properties"].keys() == report_finding["properties"].keys()
    for name in report_finding["properties"].keys() - {
        "id",
        "title",
        "cwes",
        "description",
        "remediation",
    }:
        assert observation["properties"][name] == {
            "$ref": f"report.schema.json#/$defs/finding/properties/{name}"
        }


@pytest.mark.parametrize(
    "field", ["id", "title", "severity", "cwes", "locations", "description", "remediation"]
)
def test_sparse_observation_keeps_required_fields(schemas, sparse, field):
    del sparse[field]
    with pytest.raises(ValidationError):
        _validator(schemas).validate(_result(sparse))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", ""),
        ("title", ""),
        ("severity", "urgent"),
        ("cwes", ["79"]),
        ("cwes", [79]),
        ("description", None),
        ("remediation", None),
        ("locations", []),
        ("locations", [{"path": ""}]),
        ("locations", [{"path": "a", "lines": 12}]),
        ("locations", [{"path": "a", "unexpected": True}]),
        ("validation_status", "verified"),
        ("origin", "scanner"),
        ("pqc_classification", "unknown"),
        ("effective_severity", "urgent"),
        ("remediation_effort", "unknown"),
        ("blocked_external", "false"),
        ("fingerprint", "native-fingerprint"),
        ("fingerprint_algo", "3"),
        ("passes", [0]),
        ("cvss", {"score": 11, "vector": "native"}),
        ("capec", ["63"]),
        ("peach_references", ["PEACH-X"]),
        ("owasp_llm_references", ["LLM11"]),
        ("isolation_dimensions", ["unknown"]),
        ("dependency", {"advisory": "GHSA-example"}),
        ("dependency", {"advisory": "GHSA-example", "module": "example", "ecosystem": "other"}),
        (
            "dependency",
            {"advisory": "GHSA-example", "module": "example", "classification": "confirmed"},
        ),
        (
            "dependency",
            {"advisory": "GHSA-example", "module": "example", "evidence_level": "guess"},
        ),
        ("dependency", {"advisory": "GHSA-example", "module": "example", "unexpected": True}),
        ("disposition", {"validity": "confirmed"}),
        ("unexpected", True),
    ],
)
def test_observations_reject_malformed_supplied_fields(schemas, sparse, field, value):
    sparse[field] = value
    with pytest.raises(ValidationError):
        _validator(schemas).validate(_result(sparse))


@pytest.mark.parametrize(("field", "value"), OPTIONAL_NONEMPTY_ARRAYS)
def test_explicit_empty_optional_arrays_are_not_hidden(schemas, sparse, field, value):
    sparse[field] = []
    result = AdapterResult.from_dict(_result(sparse))
    assert result.to_dict()["findings"][0][field] == []
    with pytest.raises(ValidationError):
        _validator(schemas).validate(result.to_dict())


@pytest.mark.parametrize(("field", "value"), OPTIONAL_NONEMPTY_ARRAYS)
def test_in_place_appends_are_not_lost(schemas, sparse, field, value):
    result = AdapterResult.from_dict(_result(sparse))
    finding = result.findings[0]
    getattr(finding, field).append(value)
    assert field not in finding.model_fields_set
    assert result.to_dict()["findings"][0][field] == [value]
    _validator(schemas).validate(result.to_dict())


@pytest.mark.parametrize(("field", "value"), OPTIONAL_NONEMPTY_ARRAYS)
def test_explicit_empty_assignments_are_not_hidden(schemas, sparse, field, value):
    finding = Finding.from_dict(sparse)
    setattr(finding, field, [])
    assert finding.to_dict()[field] == []
    with pytest.raises(ValidationError):
        _validator(schemas).validate(_result(finding.to_dict()))


def test_complete_historical_adapter_data_round_trips(schemas, historical):
    assert historical.keys() == schemas["report"]["$defs"]["finding"]["properties"].keys()
    raw = _result(historical)
    _validator(schemas).validate(raw)
    assert AdapterResult.from_dict(raw).to_dict() == raw


@pytest.mark.parametrize("effort", ["trivial", "moderate", "significant", "blocked-external"])
def test_historical_effort_is_not_silently_mapped(schemas, sparse, effort):
    sparse["remediation_effort"] = effort
    raw = _result(sparse)
    _validator(schemas).validate(raw)
    assert AdapterResult.from_dict(raw).to_dict()["findings"][0]["remediation_effort"] == effort
    with pytest.raises(ValidationError):
        _validator(schemas, definition="canonical_write").validate(raw)


@pytest.mark.parametrize("effort", ["xs", "s", "m", "l", "xl"])
def test_canonical_effort_accepts_sparse_observations(schemas, sparse, effort):
    sparse["remediation_effort"] = effort
    sparse["blocked_external"] = True
    _validator(schemas, definition="canonical_write").validate(_result(sparse))


def test_full_authored_report_still_rejects_sparse_observations(schemas, historical, sparse):
    severities = ("critical", "high", "medium", "low", "informational")
    report = {
        "title": "Security Assessment",
        "metadata": {"date": "2026-10-23", "scope": "Example repository"},
        "executive_summary": {
            "prose": (
                "A complete historical security assessment "
                "used to guard authored report constraints."
            ),
            "severity_counts": {severity: int(severity == "high") for severity in severities},
        },
        "severity_criteria": [
            {"level": severity, "definition": "Historical severity criterion retained unchanged."}
            for severity in severities
        ],
        "findings": [historical],
        "findings_summary": [
            {
                "severity": severity,
                "count": int(severity == "high"),
                "finding_ids": [historical["id"]] if severity == "high" else [],
            }
            for severity in severities
        ],
        "remediation_roadmap": [
            {
                "priority": "high",
                "action": "Upgrade the affected dependency.",
                "addresses": [historical["id"]],
            }
        ],
    }
    validator = _validator(schemas, "report")
    validator.validate(report)
    report["findings"] = [sparse]
    errors = list(validator.iter_errors(report))
    rejected_fields = {tuple(error.path) for error in errors}
    assert {
        ("findings", 0, field) for field in ("id", "title", "cwes", "description", "remediation")
    } <= rejected_fields
