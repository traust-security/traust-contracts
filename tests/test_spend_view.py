from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/spend.schema.json"
WINDOW = {"start": "2026-10-15T00:00:00Z", "end": "2026-12-01T00:00:00Z"}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (
            json.loads(p.read_text())
            for d in ("views_schema", "artifacts_schema")
            for p in sorted((ROOT / d / "v1").glob("*.schema.json"))
        )
    ]
    return Draft202012Validator(
        schema, registry=Registry().with_resources(resources), format_checker=FormatChecker()
    )


def _rollup(key: str | None, cost: str = "1.50", events: int = 2) -> dict[str, Any]:
    return {"key": key, "events": events, "tokens_in": 100, "tokens_out": 20, "cost_usd": cost}


def _month(month: str = "2026-10") -> dict[str, Any]:
    return {
        "month": month,
        "total": _rollup(None, "3.00", 4),
        "by_skill": [_rollup("vuln-scan"), _rollup(None)],
        "by_lane": [_rollup("full-audit"), _rollup(None)],
        "by_model": [_rollup("model-a"), _rollup("model-b")],
        "by_business_unit": [_rollup("Platform"), _rollup(None)],
        "skill_usd": "1.50",
        "business_unit_coverage": "50.0",
    }


def _idle(month: str = "2026-11") -> dict[str, Any]:
    return {
        "month": month,
        "total": {"key": None, "events": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": "0"},
        "by_skill": [],
        "by_lane": [],
        "by_model": [],
        "by_business_unit": [],
        "skill_usd": "0",
        "business_unit_coverage": None,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "window": dict(WINDOW),
        "months": [_month(), _idle()],
        "unverified_models": ["model-b"],
        "unregistered_models": [],
        "unverified_usd": "1.50",
        "invoices": [
            {
                "period": "2026-10",
                "estimate_usd": "3.00",
                "invoiced_usd": "2.70",
                "note": "",
                "variance_usd": "-0.30",
                "variance_pct": "-10.0",
            }
        ],
        "unit_economics": {
            "month": "2026-10",
            "spend_usd": "1.50",
            "repositories": 10,
            "findings": 40,
            "critical_high": 6,
        },
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_window_without_spend_is_valid(validator: Draft202012Validator) -> None:
    validator.validate(
        {
            "window": dict(WINDOW),
            "months": [_idle("2026-10"), _idle()],
            "unverified_models": [],
            "unregistered_models": [],
            "unverified_usd": "0",
            "invoices": [],
            "unit_economics": None,
        }
    )


def test_an_invoice_against_a_zero_estimate_has_no_percentage(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["invoices"].append(
        {
            "period": "2026-11",
            "estimate_usd": "0",
            "invoiced_usd": "5",
            "note": "minimum charge",
            "variance_usd": "5",
            "variance_pct": None,
        }
    )
    validator.validate(document)


@pytest.mark.parametrize(
    "field",
    ["window", "months", "unverified_models", "unregistered_models", "unverified_usd", "invoices",
     "unit_economics"],
)  # fmt: skip
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        *(("month", f) for f in _month()),
        *(("total", f) for f in _rollup(None)),
        *(("invoice", f) for f in ("period", "estimate_usd", "invoiced_usd", "note",
                                   "variance_usd", "variance_pct")),
        *(("unit", f) for f in ("month", "spend_usd", "repositories", "findings",
                                "critical_high")),
    ],
)  # fmt: skip
def test_every_serialized_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], target: str, field: str
) -> None:
    month = document["months"][0]
    {
        "month": month,
        "total": month["total"],
        "invoice": document["invoices"][0],
        "unit": document["unit_economics"],
    }[target].pop(field)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "month", "total", "invoice", "unit", "window"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    month = document["months"][0]
    {
        "view": document,
        "month": month,
        "total": month["total"],
        "invoice": document["invoices"][0],
        "unit": document["unit_economics"],
        "window": document["window"],
    }[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("months", 0, "month"), "2026-10\n"),
        (("months", 0, "month"), "2026-13"),
        (("months", 0, "total", "key"), "all"),
        (("months", 0, "total", "events"), -1),
        (("months", 0, "skill_usd"), "-1"),
        (("months", 0, "business_unit_coverage"), "50%"),
        (("months", 0, "by_model", 0, "key"), None),
        (("months", 0, "by_model", 0, "key"), ""),
        (("months", 0, "by_lane", 0, "key"), ""),
        (("months", 0, "by_business_unit", 0, "key"), ""),
        (("months", 0, "by_skill", 0, "events"), 0),
        (("unverified_models",), ["model-b", "model-b"]),
        (("unregistered_models",), [""]),
        (("unverified_usd",), "-1"),
        (("invoices", 0, "period"), "October"),
        (("invoices", 0, "estimate_usd"), "-3"),
        (("invoices", 0, "variance_usd"), "- 0.30"),
        (("invoices", 0, "note"), None),
        (("unit_economics", "repositories"), -1),
        (("unit_economics", "spend_usd"), "1.5\n"),
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


def test_unit_economics_exactly_when_some_month_has_spend(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"unit_economics": None})
    idle = document | {"months": [_idle("2026-10"), _idle()], "unverified_models": []}
    idle |= {"unverified_usd": "0", "invoices": []}
    with pytest.raises(ValidationError):
        validator.validate(idle)


def test_nothing_unverified_costs_nothing(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"unverified_models": []})


@pytest.mark.parametrize(
    "change",
    [
        {"by_model": [_rollup("model-a")], "total": _rollup(None, "0", 0)},
        {"by_model": []},
        {"by_business_unit": []},
        {"by_skill": []},
        {"by_lane": []},
    ],
)
def test_a_months_rows_follow_its_events(
    validator: Draft202012Validator, document: dict[str, Any], change: dict[str, Any]
) -> None:
    document["months"][0] |= change
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(("cost", "coverage"), [("0", "0.0"), ("0E-10", "0.0"), ("3.00", None)])
def test_coverage_exactly_when_the_month_cost_something(
    validator: Draft202012Validator, document: dict[str, Any], cost: str, coverage: str | None
) -> None:
    month = document["months"][0]
    month["total"]["cost_usd"] = cost
    month["business_unit_coverage"] = coverage
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(("estimate", "pct"), [("0", "10.0"), ("3.00", None)])
def test_a_variance_percentage_exactly_when_there_is_an_estimate(
    validator: Draft202012Validator, document: dict[str, Any], estimate: str, pct: str | None
) -> None:
    document["invoices"][0] |= {"estimate_usd": estimate, "variance_pct": pct}
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [("cost_usd", "5"), ("tokens_in", 1), ("tokens_out", 1), ("skill_usd", "5")],
)
def test_an_idle_month_shows_no_spend(
    validator: Draft202012Validator, document: dict[str, Any], field: str, value: Any
) -> None:
    idle = document["months"][1]
    (idle if field == "skill_usd" else idle["total"])[field] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("coverage", ["0.0", "100.0", "100", "33.3"])
def test_coverage_is_a_share_of_the_month(
    validator: Draft202012Validator, document: dict[str, Any], coverage: str
) -> None:
    document["months"][0]["business_unit_coverage"] = coverage
    validator.validate(document)


@pytest.mark.parametrize("coverage", ["-1", "101", "100.1", "1E+3", "50.0\n"])
def test_coverage_outside_zero_to_a_hundred_is_rejected(
    validator: Draft202012Validator, document: dict[str, Any], coverage: str
) -> None:
    document["months"][0]["business_unit_coverage"] = coverage
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_rollups_are_the_shared_spend_records() -> None:
    month = json.loads(SCHEMA.read_text())["$defs"]["month"]["properties"]
    for split in ("by_skill", "by_lane", "by_model", "by_business_unit"):
        assert month[split]["items"]["$ref"].endswith("spend-records.schema.json#/$defs/rollup")
