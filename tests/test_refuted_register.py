from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError
from pydantic import ValidationError

from traust_contracts.v1.models import RefutedRegister

ROOT = Path(__file__).parent.parent


def register() -> dict[str, object]:
    return {
        "source": "repo-triage.json",
        "sources": ["repo-triage.json", "validations/repo-validation.json"],
        "generated_at": "2026-07-23T17:00:10+00:00",
        "entries": [
            {
                "finding_ref": "FIND-007",
                "triage_id": "f007",
                "title": "Refuted claim",
                "file": "controllers/subscriptions.go",
                "line": 316,
                "category": "ASVS V1",
                "claimed_severity": "Medium",
                "refute_reasons": ["intentional_behavior"],
                "exclusion_rule": 3,
                "tier": "countersign",
                "evidence_refs": ["controllers/subscriptions.go:316"],
                "asserted_at": "2026-07-23T17:00:10+00:00",
                "asserted_by": "triage/0.32.0",
                "note": "Execution evidence overrides.",
            }
        ],
    }


def test_schema_and_model_accept_emitted_register_shape() -> None:
    document = register()
    schema = json.loads((ROOT / "artifacts_schema/v1/refuted-register.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    modeled = RefutedRegister.model_validate(document)
    assert modeled.entries[0].exclusion_rule == 3
    assert modeled.source == document["source"]
    assert modeled.entries[0].evidence_refs == document["entries"][0]["evidence_refs"]


def test_schema_and_model_forbid_uncontracted_fields() -> None:
    document = register() | {"unexpected": True}
    schema = json.loads((ROOT / "artifacts_schema/v1/refuted-register.schema.json").read_text())
    with pytest.raises(JSONSchemaValidationError):
        Draft202012Validator(schema).validate(document)
    with pytest.raises(ValidationError):
        RefutedRegister.model_validate(document)
