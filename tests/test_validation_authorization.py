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

HTTP_DISCOVERY: dict[str, Any] = {
    "routes": [
        {
            "namespace": "example-a",
            "names": ["console"],
            "domains": ["apps.example"],
            "credentials": True,
        }
    ],
    "nodes": {
        "names": ["worker-0"],
        "networks": ["10.0.0.0/24"],
        "address_types": ["InternalIP"],
        "credentials": False,
    },
    "port_forward_credentials": False,
    "kube_env": [],
    "ca_bundle": None,
    "insecure_tls": False,
    "session_check_path": None,
    "session_check_contains": None,
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
    "nodes",
    [
        None,
        {
            "names": ["worker-0"],
            "networks": ["10.0.0.0/24"],
            "address_types": ["InternalIP"],
            "credentials": False,
        },
    ],
)
def test_authorization_preserves_complete_http_grants_and_expiry(
    validator: Draft202012Validator, nodes: dict[str, Any] | None
) -> None:
    approval = deepcopy(APPROVAL)
    scope = approval["scope"]
    scope["expires_at"] = "2026-12-31T16:30:00Z"
    scope["http_targets"] = [
        {
            "host": "console.example",
            "context": "example-lab",
            "namespace": "example-a",
            "resource": "routes",
            "name": "console",
            "credentials": True,
        }
    ]
    cluster = scope["clusters"][0]
    cluster["api"] = "https://api.example:6443"
    cluster["http_discovery"] = deepcopy(HTTP_DISCOVERY)
    cluster["http_discovery"]["nodes"] = nodes
    validator.validate(approval)
    scope["expires_at"] = None
    cluster["http_discovery"] = None
    validator.validate(approval)


@pytest.mark.parametrize(
    ("path", "missing"),
    [
        ((), "routes"),
        ((), "nodes"),
        ((), "port_forward_credentials"),
        ((), "kube_env"),
        ((), "ca_bundle"),
        ((), "insecure_tls"),
        ((), "session_check_path"),
        ((), "session_check_contains"),
        (("routes", 0), "namespace"),
        (("routes", 0), "names"),
        (("routes", 0), "domains"),
        (("routes", 0), "credentials"),
        (("nodes",), "names"),
        (("nodes",), "networks"),
        (("nodes",), "address_types"),
        (("nodes",), "credentials"),
    ],
)
def test_present_http_policy_requires_every_snapshot_field(
    validator: Draft202012Validator, path: tuple[str | int, ...], missing: str
) -> None:
    approval = deepcopy(APPROVAL)
    discovery = approval["scope"]["clusters"][0]["http_discovery"] = deepcopy(HTTP_DISCOVERY)
    validator.validate(approval)
    obj = discovery
    for part in path:
        obj = obj[part]
    del obj[missing]
    with pytest.raises(ValidationError):
        validator.validate(approval)


@pytest.mark.parametrize("path", [(), ("routes", 0), ("nodes",)])
def test_authorization_rejects_empty_http_policy_objects(
    validator: Draft202012Validator, path: tuple[str | int, ...]
) -> None:
    approval = deepcopy(APPROVAL)
    cluster = approval["scope"]["clusters"][0]
    cluster["http_discovery"] = deepcopy(HTTP_DISCOVERY)
    if not path:
        cluster["http_discovery"] = {}
    else:
        obj = cluster["http_discovery"]
        for part in path[:-1]:
            obj = obj[part]
        obj[path[-1]] = {}
    with pytest.raises(ValidationError):
        validator.validate(approval)


def test_authorization_accepts_serialized_http_defaults(validator: Draft202012Validator) -> None:
    approval = deepcopy(APPROVAL)
    cluster = approval["scope"]["clusters"][0]
    cluster["http_discovery"] = {
        "routes": [{"namespace": "example-a", "names": [], "domains": [], "credentials": False}],
        "nodes": {
            "names": [],
            "networks": [],
            "address_types": ["InternalIP"],
            "credentials": False,
        },
        "port_forward_credentials": False,
        "kube_env": [],
        "ca_bundle": None,
        "insecure_tls": False,
        "session_check_path": None,
        "session_check_contains": None,
    }
    validator.validate(approval)
    cluster["http_discovery"]["routes"] = []
    cluster["http_discovery"]["nodes"] = None
    validator.validate(approval)


def test_authorization_accepts_pre_http_snapshots(validator: Draft202012Validator) -> None:
    # Older snapshots have none of the HTTP-related fields or the timestamp expiry.
    assert "http_targets" not in APPROVAL["scope"]
    assert "expires_at" not in APPROVAL["scope"]
    assert "http_discovery" not in APPROVAL["scope"]["clusters"][0]
    assert "api" not in APPROVAL["scope"]["clusters"][0]
    validator.validate(APPROVAL)


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
        (("scope", "expires_at"), "2026-12-31T16:30:00"),
        (("scope", "http_targets"), [{"context": "example-lab"}]),
        (
            ("scope", "clusters", 0, "http_discovery"),
            HTTP_DISCOVERY
            | {
                "nodes": {
                    "names": ["worker-0"],
                    "networks": ["10.0.0.0/24"],
                    "address_types": ["DNS"],
                    "credentials": False,
                }
            },
        ),
        (("scope", "clusters", 0, "api"), 1),
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
