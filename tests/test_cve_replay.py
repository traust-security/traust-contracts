from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads((ROOT / "artifacts_schema/v1/cve-replay.schema.json").read_text())
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    audit = {
        "repository_id": "00000000-0000-4000-8000-000000000001",
        "repository_ref_id": "00000000-0000-4000-8000-000000000002",
        "audit_id": "00000000-0000-4000-8000-000000000003",
        "report_artifact_id": "00000000-0000-4000-8000-000000000004",
        "repository": "https://example.test/project",
        "audited_commit": "a" * 40,
        "audited_at": "2026-10-01T00:00:00Z",
    }
    return {
        "audit": audit,
        "watermark": None,
        "revision": 1,
        "checks": [
            {
                **audit,
                "advisory_id": "CVE-2026-99901",
                "aliases": [],
                "published_at": None,
                "checked_at": "2026-11-01T00:00:00Z",
                "severity": "high",
                "summary": "Unsafe archive extraction",
                "present_at_audit": None,
                "reviewer": None,
                "presence_identity_source": None,
                "presence_evidence": None,
                "matched_advisory_ids": [],
                "audit_verdict": "unclear",
                "reason": "Presence requires human adjudication",
                "source": "fixture:osv",
                "requires_human_review": True,
            }
        ],
    }


@pytest.mark.parametrize("withdrawn", [None, False, True])
@pytest.mark.parametrize(
    ("verdict", "presence", "valid"),
    [
        ("detected", None, True),
        ("detected", True, True),
        ("detected", False, False),
        ("unclear", None, True),
        ("unclear", True, True),
        ("unclear", False, True),
        ("missed", None, False),
        ("missed", True, True),
        ("missed", False, False),
        ("not_applicable", None, False),
        ("not_applicable", True, False),
        ("not_applicable", False, True),
    ],
)
def test_replay_verdict_presence_combinations(
    validator: Draft202012Validator,
    document: dict[str, Any],
    verdict: str,
    presence: bool | None,
    valid: bool,
    withdrawn: bool | None,
) -> None:
    check = document["checks"][0]
    check.update(audit_verdict=verdict, present_at_audit=presence)
    if withdrawn is not None:
        check["withdrawn"] = withdrawn
    if verdict == "not_applicable" and withdrawn is True:
        valid = True
    if presence is not None:
        check.update(
            reviewer="human:reviewer",
            presence_identity_source="local-user",
            presence_evidence="Reviewed source at the exact audited commit",
        )
    if verdict == "detected":
        check["matched_advisory_ids"] = [check["advisory_id"]]
    assert validator.is_valid(document) is valid


@pytest.mark.parametrize("withdrawn", [False, True])
@pytest.mark.parametrize("presence", [True, False])
@pytest.mark.parametrize("field", ["reviewer", "presence_identity_source", "presence_evidence"])
def test_boolean_presence_still_requires_verified_human_provenance(
    validator: Draft202012Validator,
    document: dict[str, Any],
    presence: bool,
    field: str,
    withdrawn: bool,
) -> None:
    check = document["checks"][0]
    check["withdrawn"] = withdrawn
    check.update(
        audit_verdict="not_applicable" if presence is False else "unclear",
        present_at_audit=presence,
        reviewer="human:reviewer",
        presence_identity_source="local-user",
        presence_evidence="Reviewed source at the exact audited commit",
    )
    validator.validate(document)
    check[field] = None
    assert not validator.is_valid(document)


@pytest.mark.parametrize("withdrawn", [None, "true", 1])
def test_withdrawal_provenance_must_be_boolean(
    validator: Draft202012Validator, document: dict[str, Any], withdrawn: Any
) -> None:
    document["checks"][0]["withdrawn"] = withdrawn
    assert not validator.is_valid(document)
