#!/usr/bin/env python3
"""Schema-only fields must survive the typed round-trip.

``ContractModel`` ignores unknown keys, so a field declared in an artifact
schema but not on the model round-trips to nothing. The repo has fixed this
exact failure before — ``auto_accept_tier`` (85cbdfe), ``fingerprint``/
``fingerprint_algo``, ``alias``/``finding``, ``restatement`` — each time by
declaring the schema's fields on the model. These tests hold the same line
for the fields the ledger stamps on a layer and the optional report sections.

predicted (layer): Layer.from_dict(...).to_dict() drops
    metadata.{merkle_root_signature, merkle_signature_format,
    merkle_signing_method, merkle_algorithm, leaf_format,
    pre_merkle_checkpoint, artifact_digests} and events[0].risk_weight —
    none are declared on LayerMetadata/LayerEvent.
predicted (report): Report.from_dict(...).to_dict() drops
    asvs_coverage, dependency_audit, peach_isolation_review and
    review_surface_coverage — none are declared on Report.
"""

from __future__ import annotations

import json
import pathlib

import jsonschema

from traust_contracts.models import Layer, Report

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "artifacts_schema" / "v1"

LAYER = {
    "metadata": {
        "audit_report": "r-security-audit.json",
        "repository": "https://github.com/traust-security/widget",
        "created": "2026-08-20T00:00:00Z",
        "harness_version": "0.40.0",
        "merkle_root": "a" * 64,
        "merkle_epoch": 1,
        "merkle_size": 1,
        "merkle_root_signature": "base64-signature-over-root",
        "merkle_signature_format": 3,
        "merkle_signing_method": "keypair",
        "merkle_algorithm": "sha256",
        "leaf_format": 2,
        "pre_merkle_checkpoint": "b" * 64,
        "artifact_digests": {"r-security-audit.json": "c" * 64},
    },
    "events": [
        {
            "event_id": "d" * 64,
            "finding_ref": "WIDGET-abcdef0-001",
            "recorded_at": "2026-08-20T00:00:00Z",
            "source": {"type": "commit", "ref": "abc1234", "actor": {"kind": "machine"}},
            "disposition": {"validity": "confirmed"},
            "rationale": "Confirmed by live validation.",
            "risk_weight": {
                "lambda": 0.5,
                "weights_version": "2026-10-01",
                "tenancy_profile": "single_tenant",
                "profile_source": "override",
            },
        }
    ],
    "needs_review": [],
}

REPORT = {
    "title": "Widget security audit",
    "metadata": {"date": "2026-11-01", "scope": "the widget service and its dependencies"},
    "executive_summary": {
        "prose": "One medium finding in the authentication callback; nothing critical or high.",
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
            "informational": 0,
        },
    },
    "severity_criteria": [
        {"level": lvl, "definition": "A finding at this level is one that matters as described."}
        for lvl in ("critical", "high", "medium", "low")
    ],
    "findings": [
        {
            "id": "WIDGET-abcdef0-001",
            "title": "Unvalidated redirect in the callback handler",
            "severity": "medium",
            "cwes": ["CWE-601"],
            "locations": [{"path": "pkg/auth/callback.go", "lines": "88-94"}],
            "description": "The callback handler echoes the next parameter into the redirect.",
            "remediation": "Allow-list redirect targets.",
        }
    ],
    "findings_summary": [
        {
            "severity": s,
            "count": 1 if s == "medium" else 0,
            "finding_ids": ["WIDGET-abcdef0-001"] if s == "medium" else [],
        }
        for s in ("critical", "high", "medium", "low", "informational")
    ],
    "remediation_roadmap": [
        {
            "priority": "P1",
            "action": "Allow-list the redirect targets in the callback handler.",
            "addresses": ["WIDGET-abcdef0-001"],
        }
    ],
    "asvs_coverage": [
        {"chapter": "V2", "area": "Authentication", "requirements_assessed": 4, "violations": 1}
    ],
    "dependency_audit": {
        "prose": "No vulnerable dependencies were found in the lockfile.",
        "entries": [],
    },
    "peach_isolation_review": {"applicable": False, "rationale": "Single-tenant component."},
    "review_surface_coverage": {
        "credential-acceptance": {"status": "not_applicable", "note": "No credentials accepted."},
        "ownership-resolution": {"status": "not_assessed", "note": "Not yet examined."},
        "security-flags": {"status": "not_applicable", "note": "No security flags."},
        "outbound-fetch": {"status": "out_of_scope", "note": "Diff scan did not touch it."},
        "stored-content-integrity": {"status": "not_applicable", "note": "Nothing stored."},
        "scope-enforcement": {"status": "not_applicable", "note": "No multi-tenant scope."},
    },
}

_SIGNATURE_FIELDS = (
    "merkle_root_signature",
    "merkle_signature_format",
    "merkle_signing_method",
    "merkle_algorithm",
    "leaf_format",
    "pre_merkle_checkpoint",
    "artifact_digests",
)


def _valid(document: dict, schema_name: str) -> None:
    schema = json.loads((SCHEMA_DIR / schema_name).read_text())
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(document))
    assert not errors, [e.message for e in errors]


def test_layer_signature_metadata_round_trips() -> None:
    """The ledger's signature stamps and emission-time risk weights survive."""
    _valid(LAYER, "layer.schema.json")
    out = Layer.from_dict(LAYER).to_dict()
    for field in _SIGNATURE_FIELDS:
        assert out["metadata"][field] == LAYER["metadata"][field], f"metadata.{field} was dropped"
    assert out["events"][0]["risk_weight"] == LAYER["events"][0]["risk_weight"], (
        "events[0].risk_weight was dropped"
    )


def test_report_optional_sections_round_trip() -> None:
    """asvs_coverage, dependency_audit, peach_isolation_review and
    review_surface_coverage survive the typed round-trip."""
    _valid(REPORT, "report.schema.json")
    out = Report.from_dict(REPORT).to_dict()
    for field in (
        "asvs_coverage",
        "dependency_audit",
        "peach_isolation_review",
        "review_surface_coverage",
    ):
        assert out[field] == REPORT[field], f"{field} was dropped"
