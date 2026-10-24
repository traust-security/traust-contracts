"""Finding DTOs preserve supplied evidence without inventing optional report fields."""

import json

import pytest
from pydantic import ValidationError
from test_classifier_compatibility import _definition_validator, _finding
from test_contracts import SCHEMA_DIR, _canonical_write_validator

from traust_contracts.v1.enums import Classification, Validity
from traust_contracts.v1.models.adapter import AdapterResult
from traust_contracts.v1.models.finding import Finding

FINDING_PROPERTIES = json.loads((SCHEMA_DIR / "report.schema.json").read_text())["$defs"][
    "finding"
]["properties"]
DEPENDENCY_PROPERTIES = FINDING_PROPERTIES["dependency"]["properties"]


def _adapter(finding: dict) -> dict:
    return {
        "target": "example-repository",
        "scanned_at": "2026-10-23T00:00:00Z",
        "metadata": {"tool": "example-scanner"},
        "findings": [finding],
    }


def test_minimal_finding_and_nested_adapter_stay_schema_valid() -> None:
    raw = _finding()
    finding_validator = _definition_validator("report", "/$defs/finding")
    finding_validator.validate(raw)
    model = Finding.from_dict(raw)
    restored = model.to_dict()
    assert "peach_references" not in restored
    assert "isolation_dimensions" not in restored
    assert "remediation_effort" not in restored
    assert "fingerprint_algo" not in restored
    finding_validator.validate(restored)

    document = _adapter(raw)
    validator = _canonical_write_validator("adapter-result", canonical=True)
    validator.validate(document)
    nested = AdapterResult.from_dict(document).to_dict()
    assert nested["findings"][0] == restored
    validator.validate(nested)


@pytest.mark.parametrize(
    ("field", "value"),
    [("peach_references", "PEACH-P"), ("isolation_dimensions", "privilege")],
)
def test_nonempty_optional_lists_survive_in_place_mutation(field: str, value: str) -> None:
    model = Finding.from_dict(_finding())
    getattr(model, field).append(value)
    restored = AdapterResult.from_dict(_adapter(model.to_dict())).to_dict()
    assert restored["findings"][0][field] == [value]
    _canonical_write_validator("adapter-result", canonical=True).validate(restored)


@pytest.mark.parametrize("field", ["peach_references", "isolation_dimensions"])
@pytest.mark.parametrize("assigned", [False, True])
def test_explicit_empty_optional_lists_reach_final_schema_validation(
    field: str, assigned: bool
) -> None:
    raw = _finding()
    if assigned:
        model = Finding.from_dict(raw)
        setattr(model, field, [])
    else:
        model = Finding.from_dict({**raw, field: []})
    restored = AdapterResult.from_dict(_adapter(model.to_dict())).to_dict()
    assert restored["findings"][0][field] == []
    assert not _canonical_write_validator("adapter-result", canonical=True).is_valid(restored)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("origin", "validation_status", "pqc_classification", "remediation_effort")
        for value in FINDING_PROPERTIES[field]["enum"]
    ],
)
def test_every_schema_valid_finding_classifier_round_trips_unchanged(
    field: str, value: str | None
) -> None:
    raw = {**_finding(), field: value, "fingerprint_algo": "v3"}
    validator = _definition_validator("report", "/$defs/finding")
    validator.validate(raw)
    model = Finding.from_dict(raw)
    if field == "validation_status":
        assert isinstance(model.validation_status, Validity)
    restored = AdapterResult.from_dict(_adapter(model.to_dict())).to_dict()["findings"][0]
    assert restored[field] == value
    assert restored["fingerprint_algo"] == "v3"
    validator.validate(restored)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("ecosystem", "evidence_level", "classification")
        for value in DEPENDENCY_PROPERTIES[field]["enum"]
    ],
)
def test_every_schema_valid_dependency_classifier_round_trips_unchanged(
    field: str, value: str
) -> None:
    dependency = {"advisory": "CVE-2026-1234", "module": "example-module", field: value}
    raw = {**_finding(), "dependency": dependency}
    validator = _definition_validator("report", "/$defs/finding")
    validator.validate(raw)
    model = Finding.from_dict(raw)
    if field == "classification":
        assert isinstance(model.dependency.classification, Classification)
    restored = AdapterResult.from_dict(_adapter(model.to_dict())).to_dict()["findings"][0]
    assert restored["dependency"] == dependency
    validator.validate(restored)


def test_all_optional_provenance_and_identity_fields_survive_together() -> None:
    dependency = {
        "advisory": "CVE-2026-1234",
        "module": "golang.org/x/crypto",
        "ecosystem": "go",
        "purl": "pkg:golang/golang.org/x/crypto@0.1.0",
        "vulnerable_range": "<0.2.0",
        "fixed_version": "0.2.0",
        "installed_version": "0.1.0",
        "evidence_level": "symbol-usage",
        "classification": "likely_affected",
        "impact_artifact": "impact-analysis.json",
    }
    optional = {
        "origin": "impact-analysis",
        "validation_status": "not_verified",
        "pqc_classification": "classically-broken",
        "remediation_effort": "s",
        "blocked_external": False,
        "peach_references": ["PEACH-P"],
        "isolation_dimensions": ["privilege"],
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v3",
        "dependency": dependency,
    }
    document = _adapter({**_finding(), **optional})
    validator = _canonical_write_validator("adapter-result", canonical=True)
    validator.validate(document)
    restored = AdapterResult.from_dict(document).to_dict()
    for field, value in optional.items():
        assert restored["findings"][0][field] == value
    validator.validate(restored)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("origin", "gitleaks"),
        ("fingerprint", ""),
        ("fingerprint_algo", "sha256"),
        ("pqc_classification", "unknown-classification"),
        ("remediation_effort", "unknown-effort"),
    ],
)
def test_noncanonical_optional_strings_are_not_laundered_into_absence(
    field: str, value: str
) -> None:
    document = _adapter({**_finding(), field: value})
    restored = AdapterResult.from_dict(document).to_dict()
    assert restored["findings"][0][field] == value
    assert not _canonical_write_validator("adapter-result", canonical=True).is_valid(restored)


@pytest.mark.parametrize(
    "field",
    [
        "kind",
        "cvss",
        "attack_pattern",
        "category",
        "validation_status",
        "origin",
        "pqc_classification",
        "blocked_external",
        "isolation_boundary",
        "disposition",
        "fingerprint",
        "fingerprint_algo",
        "effective_severity",
        "dependency",
    ],
)
def test_explicit_invalid_finding_nulls_reach_final_schema_validation(field: str) -> None:
    restored = AdapterResult.from_dict(_adapter({**_finding(), field: None})).to_dict()
    assert field in restored["findings"][0]
    assert restored["findings"][0][field] is None
    assert not _canonical_write_validator("adapter-result", canonical=True).is_valid(restored)


@pytest.mark.parametrize("field", sorted(DEPENDENCY_PROPERTIES.keys() - {"advisory", "module"}))
def test_explicit_invalid_dependency_nulls_reach_final_schema_validation(field: str) -> None:
    dependency = {"advisory": "CVE-2026-1234", "module": "example-module", field: None}
    restored = AdapterResult.from_dict(_adapter({**_finding(), "dependency": dependency})).to_dict()
    assert restored["findings"][0]["dependency"] == dependency
    assert not _canonical_write_validator("adapter-result", canonical=True).is_valid(restored)


def test_explicit_null_effort_is_distinct_from_absence_in_nested_serialization() -> None:
    model = AdapterResult.from_dict(_adapter(_finding()))
    assert "remediation_effort" not in model.to_dict()["findings"][0]
    model.findings[0].remediation_effort = None
    restored = model.to_dict()
    assert restored["findings"][0]["remediation_effort"] is None
    _canonical_write_validator("adapter-result", canonical=True).validate(restored)
    assert "remediation_effort" not in model.findings[0].model_dump(
        include={"id"}, exclude_none=True
    )
    assert "remediation_effort" not in model.findings[0].model_dump(
        exclude={"remediation_effort"}, exclude_none=True
    )


@pytest.mark.parametrize(
    "optional",
    [
        {"validation_status": "unknown-status"},
        {"dependency": {"advisory": "CVE-2026-1234", "module": "x", "classification": "unknown"}},
    ],
)
def test_unknown_values_in_existing_enum_domains_are_not_silently_dropped(optional: dict) -> None:
    with pytest.raises(ValidationError):
        Finding.from_dict({**_finding(), **optional})
