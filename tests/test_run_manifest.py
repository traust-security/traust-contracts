from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/run-manifest.schema.json"
DIGEST = "a" * 64

FULL = {
    "artifact": "run-manifest",
    "config": [
        {"name": "pack:security", "digest": DIGEST},
        {"name": "budget-policy", "digest": "b" * 64},
    ],
    "budget": {
        "lane": "diff-scan",
        "status": "over",
        "enforcement": "advisory",
        "spent_usd": "120.50",
        "estimate_usd": "2.00",
        "budget_usd": "100",
    },
    "approval": {"approver": "human:operator@example.com", "approved_at": "2026-10-23T12:00:00Z"},
    "progress": {"step": 2, "shards_done": ["a", "b"], "updated_at": "2026-10-23T12:05:00Z"},
    "degraded": {"unreachable": 2, "db-stale": 1},
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _with(**fields: Any) -> dict[str, Any]:
    return {**FULL, **fields}


def test_a_full_manifest_validates(validator: Draft202012Validator) -> None:
    validator.validate(FULL)


def test_a_planned_order_carries_only_its_config(validator: Draft202012Validator) -> None:
    config = [{"name": "pack:security", "digest": DIGEST}]
    validator.validate({"artifact": "run-manifest", "config": config})


def test_unknown_cost_and_no_budget_are_null_not_zero(validator: Draft202012Validator) -> None:
    budget = {
        "lane": "deps-lane",
        "status": "no_budget",
        "enforcement": None,
        "spent_usd": "0",
        "estimate_usd": None,
        "budget_usd": None,
    }
    validator.validate(_with(budget=budget))


@pytest.mark.parametrize(
    "fields",
    [
        {"config": [{"name": "pack:security", "digest": "sha256:" + DIGEST}]},
        {"config": [{"name": "Pack Security", "digest": DIGEST}]},
        {"budget": {**FULL["budget"], "status": "under"}},
        {"budget": {**FULL["budget"], "spent_usd": 120.5}},
        {"approval": {"approver": "operator@example.com", "approved_at": "2026-10-23T12:00:00Z"}},
        {"approval": {"approver": "human:operator@example.com", "approved_at": "yesterday"}},
        {"progress": {"step": -1, "updated_at": "2026-10-23T12:05:00Z"}},
        {"degraded": {"unreachable": 0}},
        {"degraded": {"Unreachable": 1}},
        {"run_order_id": "00000000-0000-4000-8000-000000000000"},
    ],
    ids=[
        "prefixed digest",
        "bad config name",
        "unknown budget status",
        "money as a float",
        "approver without a kind",
        "approval time not a timestamp",
        "negative step",
        "zero degraded count",
        "bad degraded key",
        "manifest names its order",
    ],
)
def test_an_invalid_manifest_is_rejected(
    validator: Draft202012Validator, fields: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(_with(**fields))
