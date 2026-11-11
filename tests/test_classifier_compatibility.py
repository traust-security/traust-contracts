"""Behavioral coverage for additive classifier contracts and immutable legacy representations."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from storage_samples import sample
from test_contracts import _canonical_write_validator, build_registry
from test_refuted_register import register

from traust_contracts.v1.models.adapter import AdapterResult
from traust_contracts.v1.models.compliance import ComplianceAssessment
from traust_contracts.v1.models.finding import Finding
from traust_contracts.v1.models.layer import Layer
from traust_contracts.v1.models.refuted_register import RefutedRegister
from traust_contracts.v1.models.report import Report, RoadmapItem
from traust_contracts.v1.models.triage import TriageFinding, TriageReport

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "artifacts_schema/v1"


def _finding() -> dict:
    return {
        "id": "EXAMPLE-abcdef0-001",
        "title": "Missing defense in depth",
        "severity": "low",
        "cwes": ["CWE-693"],
        "locations": [{"path": "src/example.py"}],
        "description": (
            "A defense-in-depth control is missing from the documented security boundary."
        ),
        "remediation": "Apply the documented defense-in-depth control.",
    }


def _disposition(validity: str) -> dict:
    return {
        "validity": validity,
        "resolution": "open",
        "last_updated": "2026-10-22T00:00:00Z",
        "events": [],
    }


def _definition_validator(family: str, pointer: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{family}.schema.json").read_text())
    return Draft202012Validator({"$ref": f"{schema['$id']}#{pointer}"}, registry=build_registry())


@pytest.mark.parametrize(
    "validity",
    [
        "confirmed",
        "false_positive",
        "not_affected",
        "corrected",
        "not_verified",
        "hardening",
        "true_positive",
    ],
)
def test_report_validity_preserves_canonical_and_historical_values(validity: str) -> None:
    finding = _finding()
    finding["validation_status"] = validity
    finding["disposition"] = _disposition(validity)
    _definition_validator("report", "/$defs/finding").validate(finding)
    restored = Finding.from_dict(finding).to_dict()
    assert restored["validation_status"] == validity
    assert restored["disposition"]["validity"] == validity


@pytest.mark.parametrize("kind", ["vulnerability", "weakness"])
@pytest.mark.parametrize("validity", ["confirmed", "false_positive", "not_affected"])
def test_finding_kind_and_validity_are_independent(kind: str, validity: str) -> None:
    finding = _finding()
    finding.update(kind=kind, disposition=_disposition(validity))
    _definition_validator("report", "/$defs/finding").validate(finding)
    restored = Finding.from_dict(finding).to_dict()
    assert restored["kind"] == kind
    assert restored["disposition"]["validity"] == validity


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize("kind", ["vulnerability", "weakness"])
def test_triage_true_positive_kind_survives_nested_round_trip(kind: str, canonical: bool) -> None:
    document = json.loads(sample("triage")[0])
    finding = document["findings"][0]
    finding["kind"] = kind
    if kind == "weakness":
        finding.update(severity=None, exclusion_rule=13)
        document["summary"].update(
            true_positives=0,
            hardening=1,
            by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        )
    validator = _canonical_write_validator("triage", canonical=canonical)
    validator.validate(document)
    restored = TriageReport.from_dict(document).to_dict()
    assert restored["findings"][0]["kind"] == kind
    assert restored["findings"][0]["verdict"] == "true_positive"
    validator.validate(restored)


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize("kind", ["unknown", "", None, 1, {}])
def test_triage_kind_rejects_unknown_and_null_values(kind: object, canonical: bool) -> None:
    document = json.loads(sample("triage")[0])
    document["findings"][0]["kind"] = kind
    assert not _canonical_write_validator("triage", canonical=canonical).is_valid(document)


@pytest.mark.parametrize("canonical", [False, True])
def test_triage_omitted_kind_remains_unknown(canonical: bool) -> None:
    document = json.loads(sample("triage")[0])
    before = json.dumps(document, sort_keys=True)
    validator = _canonical_write_validator("triage", canonical=canonical)
    validator.validate(document)
    assert json.dumps(document, sort_keys=True) == before
    model = TriageReport.from_dict(document)
    assert model.findings[0].kind is None
    restored = model.to_dict()
    assert "kind" not in restored["findings"][0]
    validator.validate(restored)


@pytest.mark.parametrize("canonical", [False, True])
def test_explicit_null_triage_kind_reaches_final_schema_validation(canonical: bool) -> None:
    document = json.loads(sample("triage")[0])
    document["findings"][0]["kind"] = None
    restored = TriageReport.from_dict(document).to_dict()
    assert restored["findings"][0]["kind"] is None
    assert not _canonical_write_validator("triage", canonical=canonical).is_valid(restored)


def test_historical_triage_hardening_is_readable_but_not_a_canonical_write() -> None:
    document = json.loads(sample("triage")[0])
    document["findings"][0].update(verdict="hardening", severity=None, exclusion_rule=13)
    document["summary"].update(
        true_positives=0,
        hardening=1,
        by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
    )
    before = json.dumps(document, sort_keys=True)
    reader = _canonical_write_validator("triage")
    writer = _canonical_write_validator("triage", canonical=True)
    reader.validate(document)
    assert json.dumps(document, sort_keys=True) == before
    restored = TriageReport.from_dict(document).to_dict()
    assert restored["findings"][0]["verdict"] == "hardening"
    assert "kind" not in restored["findings"][0]
    reader.validate(restored)
    assert not writer.is_valid(document)
    assert not writer.is_valid(restored)
    document["findings"][0]["kind"] = "weakness"
    reader.validate(document)
    assert not writer.is_valid(document)


@pytest.mark.parametrize("rule", [13, "13"])
@pytest.mark.parametrize("severity", [{}, {"severity": None}])
def test_canonical_triage_weakness_accepts_null_or_absent_severity_and_rule_13(
    rule: int | str, severity: dict
) -> None:
    document = json.loads(sample("triage")[0])
    document["findings"] = [
        {
            "id": "f001",
            "title": "A verified defense-in-depth gap",
            "verdict": "true_positive",
            "kind": "weakness",
            "exclusion_rule": rule,
            **severity,
        }
    ]
    writer = _canonical_write_validator("triage", canonical=True)
    writer.validate(document)
    restored = TriageReport.from_dict(document).to_dict()
    assert restored["findings"][0]["exclusion_rule"] == rule
    assert restored["findings"][0]["kind"] == "weakness"
    writer.validate(restored)


@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "weakness", "severity": "high", "exclusion_rule": 13},
        {"kind": "weakness", "severity": "informational", "exclusion_rule": "13"},
        {"kind": "weakness", "severity": None},
        {"kind": "weakness", "severity": None, "exclusion_rule": None},
        {"kind": "weakness", "severity": None, "exclusion_rule": 12},
        {"kind": "weakness", "severity": None, "exclusion_rule": "12"},
        {"severity": None, "exclusion_rule": 13},
        {"severity": None, "exclusion_rule": "13"},
        {"kind": "vulnerability", "severity": None, "exclusion_rule": 13},
        {"kind": "vulnerability", "severity": None, "exclusion_rule": "13"},
    ],
)
def test_canonical_triage_rejects_inconsistent_weakness_fields_but_preserves_history(
    fields: dict,
) -> None:
    document = json.loads(sample("triage")[0])
    document["findings"] = [
        {"id": "f001", "title": "A reported security claim", "verdict": "true_positive", **fields}
    ]
    before = json.dumps(document, sort_keys=True)
    _canonical_write_validator("triage").validate(document)
    assert json.dumps(document, sort_keys=True) == before
    assert not _canonical_write_validator("triage", canonical=True).is_valid(document)


@pytest.mark.parametrize("verdict", ["undetermined", "false_positive", "duplicate"])
def test_triage_kind_does_not_replace_an_unconfirmed_verdict(verdict: str) -> None:
    finding = {"id": "f001", "title": "A reported weakness", "verdict": verdict, "kind": "weakness"}
    _definition_validator("triage", "/$defs/finding").validate(finding)
    document = json.loads(sample("triage")[0])
    document["findings"] = [finding]
    _canonical_write_validator("triage", canonical=True).validate(document)
    restored = TriageFinding.from_dict(finding).to_dict()
    assert restored["verdict"] == verdict
    assert restored["kind"] == "weakness"


@pytest.mark.parametrize("canonical", [False, True])
def test_triage_verdict_does_not_borrow_confirmed_from_validity(canonical: bool) -> None:
    document = json.loads(sample("triage")[0])
    document["findings"][0].update(verdict="confirmed", kind="weakness")
    assert not _canonical_write_validator("triage", canonical=canonical).is_valid(document)


@pytest.mark.parametrize("assurance", ["claimed", "human_reviewed", "machine_verified"])
def test_legacy_assurance_does_not_manufacture_an_evidence_grade(assurance: str) -> None:
    finding = _finding()
    finding["disposition"] = {**_disposition("confirmed"), "assurance": assurance}
    _definition_validator("report", "/$defs/finding").validate(finding)
    restored = Finding.from_dict(finding)
    assert restored.disposition.evidence_grade is None
    assert "evidence_grade" not in restored.to_dict()["disposition"]


@pytest.mark.parametrize("grade", ["E0", "E1", "E2", "E3", None])
def test_explicit_evidence_grade_round_trips_without_upgrade(grade: str | None) -> None:
    finding = _finding()
    finding["disposition"] = {
        **_disposition("confirmed"),
        "assurance": "human_reviewed",
        "evidence_grade": grade,
    }
    _definition_validator("report", "/$defs/finding").validate(finding)
    restored = Finding.from_dict(finding)
    assert restored.disposition.evidence_grade == grade
    assert restored.to_dict()["disposition"].get("evidence_grade") == grade


@pytest.mark.parametrize("invalid", ["true_positive", "not_verified", "unknown"])
def test_layer_validity_does_not_borrow_triage_or_audit_defaults(invalid: str) -> None:
    validator = _definition_validator("layer", "/$defs/validity")
    assert not validator.is_valid(invalid)


@pytest.mark.parametrize("validity", ["confirmed", "false_positive", "not_affected", "hardening"])
def test_whole_layer_retains_legacy_validity_without_rewriting_events(validity: str) -> None:
    document = json.loads(sample("layer")[0])
    document["events"][0]["disposition"]["validity"] = validity
    before = json.dumps(document, sort_keys=True)
    _canonical_write_validator("layer").validate(document)
    restored = Layer.from_dict(document).to_dict()
    assert restored["events"][0]["event_id"] == document["events"][0]["event_id"]
    assert restored["events"][0]["disposition"]["validity"] == validity
    assert json.dumps(document, sort_keys=True) == before


def _review_reasons() -> list[str]:
    registry = json.loads((ROOT / "enums/v1/review-reason.json").read_text())
    return registry["values"]


@pytest.mark.parametrize("reason", _review_reasons())
def test_merged_review_reasons_survive_whole_layer_schema_and_model(reason: str) -> None:
    document = json.loads((ROOT / "tests/fixtures/sample-findings-layer.json").read_text())
    document["needs_review"][0]["queue_reason"] = reason
    _canonical_write_validator("layer").validate(document)
    restored = Layer.from_dict(document).to_dict()
    _canonical_write_validator("layer").validate(restored)
    assert restored["needs_review"] == document["needs_review"]
    assert restored["needs_review"][0]["queue_reason"] == reason


@pytest.mark.parametrize("status", ["confirmed", "rejected"])
def test_historical_review_status_is_not_rewritten_by_shared_contract(status: str) -> None:
    document = json.loads((ROOT / "tests/fixtures/sample-findings-layer.json").read_text())
    item = document["needs_review"][0]
    item.update(status=status, resolution_note="bulk-closed without human review")
    _canonical_write_validator("layer").validate(document)
    assert Layer.from_dict(document).to_dict()["needs_review"][0]["status"] == status


@pytest.mark.parametrize("include_reason", [False, True])
def test_artifact_review_statement_fields_round_trip_without_core_row_aliases(
    include_reason: bool,
) -> None:
    document = json.loads((ROOT / "tests/fixtures/sample-findings-layer.json").read_text())
    item = document["needs_review"][0]
    item.update(
        submitted_by={"kind": "machine", "identity": "fixture-submitter"},
        suggested_finding_ref="FIND-001",
        suggested_disposition={"validity": "not_affected", "resolution": "open"},
        resolution_note="Original review statement retained.",
    )
    if not include_reason:
        item.pop("queue_reason")
    _canonical_write_validator("layer").validate(document)
    restored = Layer.from_dict(document).to_dict()
    _canonical_write_validator("layer").validate(restored)
    assert restored["needs_review"] == document["needs_review"]
    assert not {"finding_ref", "recorded_at", "source", "disposition"} & (
        restored["needs_review"][0].keys()
    )


@pytest.mark.parametrize(
    "family",
    [
        "report",
        "adapter-result",
        "validation",
        "pqc-blockers",
        "pqc-decision-tree",
        "pqc-readiness",
        "threat-model",
    ],
)
@pytest.mark.parametrize("blocked", [False, True])
def test_unknown_effort_passes_whole_canonical_family_without_inventing_size(
    family: str, blocked: bool
) -> None:
    document = json.loads(sample(family)[0])
    if family == "report":
        document["remediation_roadmap"][0].update(
            priority="p2", effort=None, blocked_external=blocked
        )
        document["findings"] = [{**_finding(), "remediation_effort": None}]
    elif family in {"adapter-result", "validation"}:
        key = "findings" if family == "adapter-result" else "novel_findings"
        document[key] = [{**_finding(), "remediation_effort": None, "blocked_external": blocked}]
    elif family == "pqc-blockers":
        document["remediation_roadmap"][0].update(
            priority="p2", effort=None, blocked_external=blocked
        )
    elif family == "pqc-decision-tree":
        document["remediation_effort"]["classes"] = ["xs", "s", "m", "l", "xl"]
        for rule in document["remediation_effort"]["rules"]:
            rule.update(effort=None, blocked_external=blocked)
    elif family == "pqc-readiness":
        document["clock_items"] = [
            {
                "fact_ids": [],
                "primitive": "RSA",
                "disallowed_after": 2035,
                "remediation_effort": None,
                "blocked_external": blocked,
            }
        ]
    else:
        document["mitigations"] = [
            {
                "mitigation": "Verify authorization",
                "threat_ids": ["T1"],
                "closes_class": "partial",
                "effort": None,
                "blocked_external": blocked,
            }
        ]
    before = json.dumps(document, sort_keys=True)
    _canonical_write_validator(family).validate(document)
    _canonical_write_validator(family, canonical=True).validate(document)
    assert json.dumps(document, sort_keys=True) == before


@pytest.mark.parametrize(
    ("family", "pointer"),
    [
        ("report", "/$defs/finding/properties/remediation_effort"),
        ("report", "/$defs/roadmap_item/properties/effort"),
        ("report", "/$defs/effort"),
        ("pqc-blockers", "/$defs/finding/properties/remediation_effort"),
        ("pqc-readiness", "/properties/clock_items/items/properties/remediation_effort"),
        ("pqc-readiness", "/properties/remediations/items/properties/remediation_effort"),
        ("pqc-decision-tree", "/definitions/effort"),
        ("threat-model", "/$defs/mitigation/properties/effort"),
    ],
)
def test_every_effort_shape_accepts_unknown_null(family: str, pointer: str) -> None:
    _definition_validator(family, pointer).validate(None)


@pytest.mark.parametrize("family", ["report", "adapter-result"])
@pytest.mark.parametrize("blocked", [False, True])
def test_explicit_null_effort_survives_nested_model_serialization(
    family: str, blocked: bool
) -> None:
    document = json.loads(sample(family)[0])
    document["findings"] = [
        {
            **_finding(),
            "peach_references": ["PEACH-P"],
            "isolation_dimensions": ["privilege"],
            "remediation_effort": None,
            "blocked_external": blocked,
        }
    ]
    if family == "report":
        document["remediation_roadmap"][0].update(
            priority="p2", effort=None, blocked_external=blocked
        )
        restored = Report.from_dict(document).to_dict()
        assert restored["remediation_roadmap"][0]["effort"] is None
        assert restored["remediation_roadmap"][0]["blocked_external"] is blocked
    else:
        restored = AdapterResult.from_dict(document).to_dict()
    assert restored["findings"][0]["remediation_effort"] is None
    assert restored["findings"][0]["blocked_external"] is blocked
    _canonical_write_validator(family, canonical=True).validate(restored)


def test_unset_optional_effort_stays_omitted_and_explicit_exclusions_are_respected() -> None:
    finding = Finding.from_dict(_finding())
    assert "remediation_effort" not in finding.to_dict()
    assert "kind" not in finding.to_dict()
    roadmap = RoadmapItem(priority="p2", action="Apply the control", addresses=["EXAMPLE-001"])
    assert "effort" not in roadmap.to_dict()
    finding.remediation_effort = None
    assert finding.to_dict()["remediation_effort"] is None
    assert "remediation_effort" not in finding.model_dump(
        exclude={"remediation_effort"}, exclude_none=True
    )
    assert "remediation_effort" not in finding.model_dump(
        exclude={"remediation_effort": True}, exclude_none=True
    )
    assert "remediation_effort" not in finding.model_dump(include={"id"}, exclude_none=True)


@pytest.mark.parametrize("family", ["triage", "refuted-register"])
def test_claimed_severity_profile_preserves_history_and_reuses_existing_domain(family: str) -> None:
    if family == "triage":
        document = json.loads(sample(family)[0])
        item = {"id": "f001", "title": "A reported claim", "verdict": "false_positive"}
        document["findings"] = [item]
    else:
        document = register()
        item = document["entries"][0]
    item["claimed_severity"] = "Medium"
    reader = _canonical_write_validator(family)
    writer = _canonical_write_validator(family, canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    if family == "triage":
        assert TriageFinding.from_dict(item).claimed_severity == "Medium"
    else:
        assert RefutedRegister.from_dict(document).entries[0].claimed_severity == "Medium"
    for severity in ("critical", "high", "medium", "low", "informational", None):
        item["claimed_severity"] = severity
        writer.validate(document)
    item["claimed_severity"] = "not_affected"
    assert not writer.is_valid(document)


def test_refuted_profile_resolves_authoritative_report_id_using_only_loaded_resources() -> None:
    report = json.loads((SCHEMAS / "report.schema.json").read_text())
    refuted = json.loads((SCHEMAS / "refuted-register.schema.json").read_text())
    retrievals = []

    def reject_retrieval(uri: str) -> Resource:
        retrievals.append(uri)
        raise AssertionError(f"schema was not loaded locally: {uri}")

    registry = Registry(retrieve=reject_retrieval).with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in (report, refuted)
    )
    writer = Draft202012Validator(
        {"$ref": f"{refuted['$id']}#/$defs/canonical_write"}, registry=registry
    )
    document = register()
    document["entries"][0]["claimed_severity"] = "medium"
    writer.validate(document)
    document["entries"][0]["claimed_severity"] = "Medium"
    Draft202012Validator(refuted, registry=registry).validate(document)
    assert not writer.is_valid(document)
    assert retrievals == []


@pytest.mark.parametrize("family", ["report", "cloud-config-findings-current"])
def test_original_override_severity_profile_keeps_historical_text_readable(family: str) -> None:
    document = json.loads(sample(family)[0])
    if family == "report":
        document["remediation_roadmap"][0].update(priority="p2", effort=None)
        document["disposition_summary"] = {
            "layer_ref": "example-layer.json",
            "generated_at": "2026-10-22T00:00:00Z",
            "by_resolution": {
                code: 0
                for code in (
                    "open",
                    "fix_in_progress",
                    "resolved",
                    "partially_resolved",
                    "risk_accepted",
                    "regression_introduced",
                )
            },
            "by_validity": {
                code: 0 for code in ("confirmed", "corrected", "false_positive", "not_verified")
            },
        }
    override = {
        "finding": "EXAMPLE-001",
        "from": "Historical severity explanation",
        "severity": "high",
        "by": "user:reviewer",
        "at": "2026-10-22T00:00:00Z",
    }
    document["disposition_summary"]["severity_overrides"] = [override]
    reader = _canonical_write_validator(family)
    writer = _canonical_write_validator(family, canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    if family == "report":
        restored = Report.from_dict(document).to_dict()
        assert restored["disposition_summary"]["severity_overrides"][0]["from"] == override["from"]
        reader.validate(restored)
    for severity in ("critical", "high", "medium", "low", "informational", None):
        override["from"] = severity
        writer.validate(document)


def test_compliance_profile_preserves_history_and_enforces_domains() -> None:
    document = json.loads(sample("compliance-assessment")[0])
    result = {
        "framework": "Historical framework description",
        "control_id": "control-001",
        "classification": "organizational",
        "verdict": "not_assessed",
        "verdict_source": "human_override",
        "reason": "Review has not assessed this control.",
        "override": {
            "by": "user:reviewer",
            "date": "2026-10-22",
            "rationale": "Recorded review state.",
            "overridden_check_verdict": "Historical verdict description",
        },
    }
    document["results"] = [result]
    reader = _canonical_write_validator("compliance-assessment")
    writer = _canonical_write_validator("compliance-assessment", canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    restored = ComplianceAssessment.from_dict(document).to_dict()
    assert restored["results"][0]["framework"] == result["framework"]
    assert (
        restored["results"][0]["override"]["overridden_check_verdict"]
        == (result["override"]["overridden_check_verdict"])
    )
    result["framework"] = "nist-800-53-rev5"
    assert not writer.is_valid(document)
    for verdict in ("satisfied", "not_satisfied", "not_applicable", "not_assessed"):
        result["override"]["overridden_check_verdict"] = verdict
        writer.validate(document)
    result["override"]["overridden_check_verdict"] = "false_positive"
    assert not writer.is_valid(document)
