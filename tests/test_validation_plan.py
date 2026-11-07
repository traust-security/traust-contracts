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


def http_plan() -> dict[str, Any]:
    plan = deepcopy(PLAN)
    step = plan["steps"][0]
    step.pop("payload")
    step.pop("rollback")
    step["verb"] = "port-forward+http"
    step["target"] = {
        "context": "authorized-lab",
        "namespace": "example-a",
        "resource": "routes",
        "method": "GET",
        "path": "/healthz",
        "http": {
            "mode": "route",
            "method": "GET",
            "path": "/healthz",
            "port": None,
            "scheme": "auto",
            "hint": "console",
            "namespaces": ["example-a"],
            "name": None,
            "url": None,
            "headers": {},
            "authenticate": False,
            "csrf": False,
            "service_account": None,
        },
    }
    return plan


def test_structured_http_probe_is_a_valid_plan(validator: Draft202012Validator) -> None:
    validator.validate(http_plan())


@pytest.mark.parametrize(
    ("probe", "resource"),
    [
        ({"namespaces": ["example-a"]}, "routes"),
        ({"mode": "route", "namespaces": ["example-a", "example-b"]}, "routes"),
        ({"mode": "service", "namespaces": ["example-a"]}, "services"),
        ({"mode": "node"}, "nodes"),
        ({"mode": "direct", "url": "https://example.invalid"}, "http_targets"),
    ],
)
def test_probe_snapshots_remain_readable_through_cli_validator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe: dict[str, Any], resource: str
) -> None:
    # This validates proposed snapshots, not permission to run them. Route
    # discovery without namespaces is rejected by the execution consumers.
    monkeypatch.syspath_prepend(str(SCHEMA.parents[2]))
    from validate import validate_artifact

    plan = http_plan()
    plan["steps"][0]["target"] = {
        "context": "authorized-lab",
        "resource": resource,
        "http": probe,
    }
    artifact = tmp_path / "plan.json"
    artifact.write_text(json.dumps(plan), encoding="utf-8")
    assert validate_artifact("validation-plan", artifact)


@pytest.mark.parametrize(
    "probe", [{"mode": "direct"}, {"mode": "direct", "url": None}, {"mode": "direct", "url": ""}]
)
def test_direct_probe_requires_url_through_cli_validator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe: dict[str, Any]
) -> None:
    monkeypatch.syspath_prepend(str(SCHEMA.parents[2]))
    from validate import validate_artifact

    plan = http_plan()
    plan["steps"][0]["target"] = {
        "context": "authorized-lab",
        "resource": "http_targets",
        "http": probe,
    }
    artifact = tmp_path / "plan.json"
    artifact.write_text(json.dumps(plan), encoding="utf-8")
    assert not validate_artifact("validation-plan", artifact)


def test_generated_direct_probe_without_explicit_port_is_valid(
    validator: Draft202012Validator,
) -> None:
    plan = http_plan()
    target = plan["steps"][0]["target"]
    target["resource"] = "http_targets"
    target["http"]["mode"] = "direct"
    target["http"]["url"] = "https://example.invalid"
    validator.validate(plan)


@pytest.mark.parametrize("mode", ["route", "service"])
@pytest.mark.parametrize("skipped", [False, True])
def test_generated_probe_without_discovery_candidates_remains_readable(
    validator: Draft202012Validator, mode: str, skipped: bool
) -> None:
    # The planner serializes empty candidates when no discovery grant is usable;
    # even an unskipped proposed plan is not executable without further checks.
    plan = http_plan()
    step = plan["steps"][0]
    step["target"]["namespace"] = None
    step["target"]["resource"] = "routes" if mode == "route" else "services"
    step["target"]["http"]["mode"] = mode
    step["target"]["http"]["namespaces"] = []
    if skipped:
        step["skip"] = "blocked_by_scope: no discovery candidates"
    validator.validate(plan)


@pytest.mark.parametrize("field", ["cmd", "rollback"])
def test_structured_http_probe_rejects_command_text(
    validator: Draft202012Validator, field: str
) -> None:
    plan = http_plan()
    plan["steps"][0][field] = "curl https://example.invalid"
    with pytest.raises(ValidationError):
        validator.validate(plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mode", "unknown"),
        ("method", "CONNECT"),
        ("port", 0),
        ("url", 12),
        ("namespaces", None),
        ("unexpected", True),
        ("headers", {"X": 1}),
    ],
)
def test_structured_http_probe_rejects_invalid_fields(
    validator: Draft202012Validator, field: str, value: object
) -> None:
    plan = http_plan()
    plan["steps"][0]["target"]["http"][field] = value
    with pytest.raises(ValidationError):
        validator.validate(plan)


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
