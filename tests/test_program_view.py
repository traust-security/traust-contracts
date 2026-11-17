from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/program.schema.json"
SHARED = ROOT / "views_schema/v1/spend-records.schema.json"
FINISHED = ["succeeded", "degraded", "refused", "withheld", "failed"]


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(json.loads(SHARED.read_text()))
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (json.loads(p.read_text()) for p in sorted(SCHEMA.parent.glob("*.schema.json")))
    ]
    return Draft202012Validator(
        schema, registry=Registry().with_resources(resources), format_checker=FormatChecker()
    )


def _rollup(key: str | None, cost: str = "1.25") -> dict[str, Any]:
    return {"key": key, "events": 2, "tokens_in": 1000, "tokens_out": 200, "cost_usd": cost}


def _point(bucket: str, **counts: int) -> dict[str, Any]:
    return {"bucket": bucket, "finished": {s: counts.get(s, 0) for s in FINISHED}}


WINDOW = {"start": "2026-10-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"}


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "window": dict(WINDOW),
        "bucket": "month",
        "spend": {"window": dict(WINDOW), "attributed_usd": "2.50", "unattributed_usd": "0"},
        "by_month": [_rollup("2026-10", "2.50")],
        "by_model": [_rollup("model-a")],
        "by_lane": [_rollup("full-audit+validate"), _rollup(None)],
        "by_skill": [_rollup("vuln-scan"), _rollup("")],
        "throughput": {
            "repo_state": [_point("2026-10-01T00:00:00Z", succeeded=4, failed=1)],
            "vuln_scan": [_point("2026-10-01T00:00:00Z")],
        },
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_window_without_spend_or_assets_is_valid(validator: Draft202012Validator) -> None:
    validator.validate(
        {
            "window": dict(WINDOW),
            "bucket": "day",
            "spend": {"window": dict(WINDOW), "attributed_usd": "0", "unattributed_usd": "0"},
            "by_month": [],
            "by_model": [],
            "by_lane": [],
            "by_skill": [],
            "throughput": {},
        }
    )


@pytest.mark.parametrize("cost", ["0", "0.0300", "1E-9", "12345.678901", "3E+2"])
def test_amounts_are_non_negative_decimal_strings(
    validator: Draft202012Validator, document: dict[str, Any], cost: str
) -> None:
    document["by_model"][0]["cost_usd"] = cost
    document["spend"]["unattributed_usd"] = cost
    validator.validate(document)


@pytest.mark.parametrize("cost", ["-1", "1e-9", "1,5", "", ".5", 1.5, None])
def test_amounts_outside_the_decimal_form_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], cost: Any
) -> None:
    document["by_model"][0]["cost_usd"] = cost
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field",
    ["window", "bucket", "spend", "by_month", "by_model", "by_lane", "by_skill", "throughput"],
)
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        *(("window", f) for f in ("start", "end")),
        *(("spend", f) for f in ("window", "attributed_usd", "unattributed_usd")),
        *(("rollup", f) for f in _rollup("k")),
        *(("point", f) for f in ("bucket", "finished")),
        *(("finished", f) for f in FINISHED),
    ],
)
def test_every_serialized_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], target: str, field: str
) -> None:
    point = document["throughput"]["repo_state"][0]
    {
        "window": document["window"],
        "spend": document["spend"],
        "rollup": document["by_lane"][1],
        "point": point,
        "finished": point["finished"],
    }[target].pop(field)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "window", "spend", "rollup", "point", "finished"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    point = document["throughput"]["repo_state"][0]
    {
        "view": document,
        "window": document["window"],
        "spend": document["spend"],
        "rollup": document["by_model"][0],
        "point": point,
        "finished": point["finished"],
    }[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("window", "start"), "2026-10-01"),
        (("spend", "window", "end"), None),
        (("bucket",), "quarter"),
        (("by_month", 0, "key"), "2026-13"),
        (("by_month", 0, "key"), "October"),
        (("by_month", 0, "key"), None),
        (("by_model", 0, "key"), None),
        (("by_model", 0, "key"), ""),
        (("by_lane", 0, "key"), ""),
        (("by_model", 0, "events"), 0),
        (("by_model", 0, "tokens_in"), -1),
        (("by_model", 0, "tokens_out"), -1),
        (("throughput", "repo_state", 0, "bucket"), "October"),
        (("throughput", "repo_state", 0, "finished", "failed"), -1),
        (("throughput", "repo_state", 0, "finished", "queued"), 0),
        (("throughput", "repo_state"), None),
        (("throughput", ""), []),
        (("by_month", 0, "key"), "2026-10\n"),
        (("by_model", 0, "cost_usd"), "1\n"),
        (("spend", "attributed_usd"), " 1"),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    target = broken
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


def test_an_idle_asset_has_zero_filled_points(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    point = document["throughput"]["vuln_scan"][0]
    assert set(point["finished"].values()) == {0}
    validator.validate(document)


def test_a_series_is_empty_only_over_an_empty_window(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    """JSON Schema cannot compare the bounds, so an empty series stays valid: Core emits one only
    when the window holds no bucket (start not before end, which it does not refuse)."""
    empty = {"start": "2026-11-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"}
    document |= {"window": dict(empty), "throughput": {"repo_state": [], "vuln_scan": []}}
    validator.validate(document)


def test_skill_keys_stay_raw(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    document["by_skill"] = [_rollup(""), _rollup(None)]
    validator.validate(document)


def test_finished_outcomes_are_run_order_states() -> None:
    registry = json.loads((ROOT / "enums/v1/run-order-state.json").read_text())["values"]
    point = json.loads(SCHEMA.read_text())["$defs"]["point"]["properties"]["finished"]
    assert point["required"] == FINISHED
    assert set(FINISHED) <= set(registry)
    assert [s for s in registry if s in FINISHED] == FINISHED


def test_spend_records_is_definitions_only() -> None:
    shared = json.loads(SHARED.read_text())
    assert set(shared) == {"$schema", "$id", "title", "description", "$defs"}
