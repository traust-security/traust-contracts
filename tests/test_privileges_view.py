from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/privileges.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _row() -> dict[str, Any]:
    return {
        "repository": "https://forge.example/o/operator",
        "assessment_id": "00000000-0000-4000-8000-000000000001",
        "workloads": 2,
        "privileged_workloads": 1,
        "rbac_rules": 14,
        "wildcard_rules": 2,
        "scc_requests": ["privileged", "privileged"],
        "no_scc_request_recorded": False,
        "flags": {"secrets_access": 3, "wildcard_verbs": 1},
        "containers": 3,
        "privileged_containers": 1,
        "run_as_non_root_containers": 2,
        "namespaces": ["openshift-operators"],
        "install_modes": ["OwnNamespace", "AllNamespaces"],
        "kubebuilder_markers": 9,
        "surplus": 4,
        "distinct_rule_triples": 40,
        "distinct_cluster_triples": 12,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {"as_of": "2026-11-15T00:00:00Z", "rows": [_row()]}


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_current_view_of_nothing_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"as_of": None, "rows": []})


@pytest.mark.parametrize("field", ["as_of", "rows"])
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", list(_row()))
def test_every_row_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["rows"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "row"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    (document if target == "view" else document["rows"][0])["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("assessment_id", "not-a-uuid"),
        ("workloads", -1),
        ("privileged_workloads", -1),
        ("rbac_rules", None),
        ("wildcard_rules", -1),
        ("flags", {"secrets_access": 0}),
        ("containers", -1),
        ("distinct_rule_triples", -1),
        ("distinct_cluster_triples", None),
        ("scc_requests", None),
        ("namespaces", [1]),
        ("no_scc_request_recorded", "yes"),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    broken["rows"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


def test_a_profile_without_workloads_has_no_container_posture(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    row = document["rows"][0]
    row["containers"] = row["privileged_containers"] = row["run_as_non_root_containers"] = None
    validator.validate(document)
    row["privileged_containers"] = 0
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_container_posture_is_listed_with_its_containers(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["rows"][0]["run_as_non_root_containers"] = None
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("privileged_workloads", None),
        ("wildcard_rules", None),
        ("kubebuilder_markers", None),
        ("surplus", None),
        ("surplus", -2),
        ("flags", {}),
        ("scc_requests", []),
        ("no_scc_request_recorded", None),
        ("no_scc_request_recorded", True),
    ],
)
def test_nulls_and_raw_values_core_serves_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], field: str, value: Any
) -> None:
    document["rows"][0][field] = value
    validator.validate(document)
