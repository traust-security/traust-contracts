from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/validation-authorization.schema.json"
PLAN_ID = "00000000-0000-4000-8000-000000000001"

APPROVAL: dict[str, Any] = {
    "artifact": "validation-authorization",
    "plan_id": PLAN_ID,
    "plan_digest": "a" * 64,
    "approved_by": "human:reviewer@example.com",
    "approved_at": "2026-10-22T12:00:00Z",
    "mode": "interactive",
    "skip_step_ids": ["step-002"],
    "permit_destructive": False,
    "scope": {
        "engagement": "authorized-lab",
        "authorized_by": "Example Security Team",
        "environment": "lab",
        "expires": "2026-12-31",
        "modes": ["explicit", "inline"],
        "clusters": [
            {
                "context": "example-lab",
                "namespaces": ["example-*"],
                "explicit_namespaces": ["example-a"],
                "verbs_denied": ["delete"],
            }
        ],
        "off_limits": [{"namespace": "kube-system"}],
        "browser": [],
        "containers": [],
        "images": [],
        "wasm_artifact_ids": [],
        "credential_probe_classes": [],
        "inventory_aws_profiles": [],
        "inventory_cluster_contexts": [],
    },
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def test_authorization_pins_plan_and_complete_scope(validator: Draft202012Validator) -> None:
    validator.validate(APPROVAL)
    auto = deepcopy(APPROVAL)
    auto["mode"] = "auto"
    auto["approved_by"] = "machine:lab-runner"
    validator.validate(auto)
    inline = deepcopy(APPROVAL)
    inline["scope"]["modes"] = ["inline"]
    inline["scope"]["environment"] = None
    inline["scope"]["authorized_by"] = None
    validator.validate(inline)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("approval",), "yes"),
        (("plan_id",), "not-a-uuid"),
        (("plan_digest",), "short"),
        (("approved_by",), "anonymous"),
        (("approved_at",), "yesterday"),
        (("mode",), "dry-run"),
        (("skip_step_ids",), ["step-002", "step-002"]),
        (("permit_destructive",), "true"),
        (("scope", "modes"), []),
        (("scope", "modes"), ["inferred", "unknown"]),
        (("scope", "clusters", 0, "explicit_namespaces"), ["example-a", "example-a"]),
        (("scope", "clusters", 0, "unsafe"), True),
        (("scope", "off_limits", 0, "unsafe"), True),
        (("scope", "expires"), "tomorrow"),
        (("scope", "wasm_artifact_ids"), ["file:///var/example.wasm"]),
    ],
)
def test_authorization_rejects_unknown_or_malformed_fields(
    validator: Draft202012Validator, path: tuple[str | int, ...], value: object
) -> None:
    approval = deepcopy(APPROVAL)
    node = approval
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(ValidationError):
        validator.validate(approval)


@pytest.mark.parametrize(
    "missing",
    ["plan_id", "plan_digest", "approved_by", "approved_at", "mode", "scope", "permit_destructive"],
)
def test_authorization_requires_binding_and_approval_fields(
    validator: Draft202012Validator, missing: str
) -> None:
    with pytest.raises(ValidationError):
        validator.validate({key: value for key, value in APPROVAL.items() if key != missing})


@pytest.mark.parametrize(
    "missing", ["environment", "modes", "clusters", "off_limits", "explicit_namespaces"]
)
def test_authorization_requires_full_scope_snapshot(
    validator: Draft202012Validator, missing: str
) -> None:
    approval = deepcopy(APPROVAL)
    if missing == "explicit_namespaces":
        del approval["scope"]["clusters"][0][missing]
    else:
        del approval["scope"][missing]
    with pytest.raises(ValidationError):
        validator.validate(approval)


@pytest.mark.parametrize("mode,environment", [(["inline"], "lab"), (["explicit"], "production")])
def test_auto_approval_requires_an_explicit_lab_scope(
    validator: Draft202012Validator, mode: list[str], environment: str
) -> None:
    approval = deepcopy(APPROVAL)
    approval["mode"] = "auto"
    approval["scope"]["modes"] = mode
    approval["scope"]["environment"] = environment
    with pytest.raises(ValidationError):
        validator.validate(approval)
