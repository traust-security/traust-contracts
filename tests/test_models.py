"""Round-trip tests for Pydantic contract models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from traust_contracts.enums import Severity
from traust_contracts.models import (
    AdapterResult,
    Finding,
    Report,
)
from traust_contracts.v1.models.adapter import AdapterMetadata, AdapterSummary
from traust_contracts.v1.models.finding import Location

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "artifacts_schema" / "v1"
FIXTURES = Path(__file__).parent / "fixtures"


def _registry() -> Registry:
    resources = {}
    for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        resources[doc.get("$id", sf.name)] = Resource.from_contents(doc)
    return Registry(resources=resources)


def _validate(schema_name: str, data: dict) -> None:
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, registry=_registry())
    errors = list(validator.iter_errors(data))
    assert not errors, errors[0].message if errors else ""


def test_finding_round_trip():
    raw = {
        "id": "REPO-abc1234-001",
        "title": "Test finding",
        "severity": "high",
        "cwes": ["CWE-79"],
        "locations": [{"path": "src/main.go", "lines": "10-20"}],
        "description": "desc",
        "remediation": "fix",
    }
    model = Finding.from_dict(raw)
    out = model.to_dict()
    assert out["id"] == raw["id"]
    assert out["severity"] == "high"


def test_adapter_result_round_trip():
    finding = Finding(
        id="REPO-abc1234-001",
        title="x",
        severity=Severity.HIGH,
        cwes=["CWE-79"],
        locations=[Location(path="a.go")],
        description="d",
        remediation="r",
    )
    model = AdapterResult(
        target="repo",
        scanned_at="2026-01-01T00:00:00Z",
        metadata=AdapterMetadata(tool="opengrep"),
        findings=[finding],
        summary=AdapterSummary(total=1, by_severity={"high": 1}),
    )
    restored = AdapterResult.from_dict(model.to_dict())
    assert restored.summary.total == 1


def test_report_optional_sections_round_trip():
    from traust_contracts.v1.models.report import (
        DispositionSummary,
        ExecutiveSummary,
        ReportMetadata,
        ResolutionCounts,
        SeverityCounts,
        ValidityCounts,
    )

    report = Report(
        title="Audit",
        metadata=ReportMetadata(date="2026-01-01", scope="test"),
        executive_summary=ExecutiveSummary(
            prose="ok",
            severity_counts=SeverityCounts(),
        ),
        disposition_summary=DispositionSummary(
            layer_ref="layer.json",
            generated_at="2026-01-01T00:00:00Z",
            by_resolution=ResolutionCounts(),
            by_validity=ValidityCounts(),
        ),
    )
    restored = Report.from_dict(report.to_dict())
    assert restored.disposition_summary is not None


@pytest.mark.skipif(not FIXTURES.exists(), reason="fixtures not present")
def test_fixture_round_trips():
    for path in FIXTURES.glob("*.json"):
        schema_hint = path.stem.replace("_", "-") + ".schema.json"
        if not (SCHEMA_DIR / schema_hint).is_file():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        _validate(schema_hint, raw)


def test_layer_external_refs_round_trip_and_validate():
    """CVE-provenance stamps must survive the model AND the schema.

    ContractModel ignores unknown keys, so a schema-only field round-trips
    to nothing (the failure 85cbdfe had to fix for auto_accept_tier). This
    asserts both halves, and that the map is metadata rather than an event:
    provenance is derived and must not perturb the Merkle-signed chain.
    """
    from traust_contracts.models import ExternalRef, LayerMetadata

    md = LayerMetadata(
        audit_report="r-security-audit.json",
        repository="https://github.com/o/r",
        created="2026-08-20T00:00:00Z",
        harness_version="0.4.0",
        external_refs={
            "FIND-002": [
                ExternalRef(
                    system="cve",
                    id="CVE-2026-66792",
                    url="https://nvd.nist.gov/vuln/detail/CVE-2026-66792",
                    confidence="confirmed",
                    matched_on="title-similarity:0.78",
                    stamped_at="2026-08-20T00:00:00Z",
                )
            ]
        },
    )
    raw = md.to_dict()
    assert raw["external_refs"]["FIND-002"][0]["id"] == "CVE-2026-66792"
    assert LayerMetadata.from_dict(raw).external_refs["FIND-002"][0].confidence == "confirmed"

    schema = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator({**schema, **schema["$defs"]["layer_metadata"]}).validate(raw)

    # the event chain is deliberately untouched
    assert "external_refs" not in schema["$defs"]["event"]["properties"]


def test_layer_external_refs_rejects_unknown_system():
    schema = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema, **schema["$defs"]["layer_metadata"]})
    bad = {
        "audit_report": "r-security-audit.json",
        "repository": "https://github.com/o/r",
        "created": "2026-08-20T00:00:00Z",
        "harness_version": "0.4.0",
        "external_refs": {"FIND-001": [{"system": "pastebin", "id": "x"}]},
    }
    assert list(validator.iter_errors(bad))


def test_layer_claim_hashes_and_event_evidence_round_trip() -> None:
    from traust_contracts.models import Layer

    raw = json.loads((FIXTURES / "sample-findings-layer.json").read_text())
    raw["baseline_claims"]["FIND-001"] = "c" * 64
    _validate("layer.schema.json", raw)
    model = Layer.from_dict(raw)
    for restored in (model.to_dict(), json.loads(model.model_dump_json(exclude_none=True))):
        assert restored["baseline_claims"] == raw["baseline_claims"]
        assert restored["metadata"]["claim_hashes"] == raw["metadata"]["claim_hashes"]
        assert restored["events"][1]["evidence_refs"] == raw["events"][1]["evidence_refs"]
        assert restored["needs_review"] == raw["needs_review"]
        _validate("layer.schema.json", restored)


@pytest.mark.parametrize("present", [False, True])
def test_layer_evidence_collections_preserve_absence_and_explicit_empty(present: bool) -> None:
    from traust_contracts.models import Layer

    raw = json.loads((FIXTURES / "sample-findings-layer.json").read_text())
    raw.pop("baseline_claims")
    for event in raw["events"]:
        event.pop("evidence_refs", None)
    if present:
        raw["baseline_claims"] = {}
        raw["events"][0]["evidence_refs"] = []
    restored = Layer.from_dict(raw).to_dict()
    assert ("baseline_claims" in restored) is present
    assert ("evidence_refs" in restored["events"][0]) is present
    if present:
        assert restored["baseline_claims"] == {}
        assert restored["events"][0]["evidence_refs"] == []
    _validate("layer.schema.json", restored)


@pytest.mark.parametrize("field", ["baseline_claims", "evidence_refs"])
def test_layer_evidence_collections_do_not_accept_explicit_null(field: str) -> None:
    from pydantic import ValidationError

    from traust_contracts.models import Layer

    raw = json.loads((FIXTURES / "sample-findings-layer.json").read_text())
    target = raw if field == "baseline_claims" else raw["events"][0]
    target[field] = None
    with pytest.raises(ValidationError):
        Layer.from_dict(raw)
