from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_contracts import build_registry

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/validation-plan.schema.json"

PLAN: dict[str, Any] = {
    "target": "example-operator",
    "scope_binding_mode": "explicit",
    "engagement": "authorized-lab",
    "chains": [
        {
            "chain_id": "chain-1",
            "name": "Example chain",
            "entry_point": "demo endpoint",
            "terminal_asset": "demo data",
            "finding_ids": ["DEMO-001"],
            "mitre_attack_refs": ["T1098"],
            "narrative": "",
            "path": ["entry:demo endpoint", "finding:DEMO-001", "asset:demo data"],
        }
    ],
    "steps": [
        {
            "id": "step-001",
            "technique": "replay",
            "adapter": "k8s",
            "verb": "apply-manifest",
            "target": {"context": "authorized-lab", "namespace": None, "resource": "configmap"},
            "finding_ref": "DEMO-001",
            "payload": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n",
            "classification": "mutating",
            "expected": "test resource created",
            "rollback": "delete the test resource",
            "preconditions": [],
            "summary": "exercise the finding",
        },
        {
            "id": "step-002",
            "technique": "skip",
            "adapter": "k8s",
            "verb": "noop",
            "target": {},
            "finding_ref": "DEMO-002",
            "classification": "safe",
            "skip": "wrong-surface:build-time",
            "summary": "cannot test in a live cluster",
        },
    ],
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry())


def test_validate_findings_plan_shape(validator: Draft202012Validator) -> None:
    validator.validate(PLAN)
    validator.validate({**PLAN, "chains": [], "steps": [], "engagement": None})
    recon = {
        **PLAN["steps"][0],
        "adapter": "container",
        "verb": "inspect",
        "target": {"name": "example", "runtime": "podman", "pqc": True},
        "classification": "safe",
        "technique": "recon",
    }
    validator.validate({**PLAN, "steps": [recon]})


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("approval",), {"approved_by": "machine:claimed"}),
        (("metadata",), {"environment": "lab"}),
        (("steps", 0, "scope_check"), "pass"),
        (("steps", 0, "target", "off_limits"), False),
        (("steps", 0, "target", "port"), 0),
        (("steps", 0, "target", "context"), 3),
        (("steps", 0, "classification"), "harmless"),
        (("steps", 0, "adapter"), "browser"),
        (("steps", 0, "technique"), "invented"),
        (("steps", 0, "payload"), {"cmd": "not a string"}),
        (("steps", 0, "preconditions"), ["step-001", "step-001"]),
        (("chains", 0, "confidence"), 1),
    ],
)
def test_unknown_or_mistyped_fields_are_rejected(
    validator: Draft202012Validator, path: tuple[str | int, ...], value: object
) -> None:
    plan = deepcopy(PLAN)
    node = plan
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(ValidationError):
        validator.validate(plan)


@pytest.mark.parametrize("missing", ["target", "scope_binding_mode", "chains", "steps"])
def test_plan_requires_its_envelope(validator: Draft202012Validator, missing: str) -> None:
    plan = {key: value for key, value in PLAN.items() if key != missing}
    with pytest.raises(ValidationError):
        validator.validate(plan)


def test_step_requires_its_dispatch_fields(validator: Draft202012Validator) -> None:
    for field in ("id", "technique", "adapter", "verb", "target", "classification"):
        plan = deepcopy(PLAN)
        del plan["steps"][0][field]
        with pytest.raises(ValidationError):
            validator.validate(plan)
