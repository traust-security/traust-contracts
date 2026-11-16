from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/pqc.schema.json"
PRODUCT, OTHER = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _rollup(key: str) -> dict[str, Any]:
    return {
        "key": key,
        "repositories": 3,
        "mean_overall": 57.5,
        "clock_2030": 1,
        "hndl_priority": 2,
        "blocked": 1,
        "remediations": {"fix-now": 2, "waiting-on-upstream": 1},
    }


def _scope(product_id: str | None) -> dict[str, Any]:
    return {
        "product_id": product_id,
        "by_bucket": [_rollup("partial"), _rollup("unbucketed")],
        "by_provenance": [_rollup("delegated-dependency")],
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {"scopes": [_scope(None)]}


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_named_products_each_get_a_scope(validator: Draft202012Validator) -> None:
    validator.validate({"scopes": [_scope(PRODUCT), _scope(OTHER)]})


@pytest.mark.parametrize(
    "scopes",
    [[], [_scope(None), _scope(None)], [_scope(PRODUCT), _scope(None)]],
)
def test_scopes_are_every_commits_alone_or_each_named_products(
    validator: Draft202012Validator, scopes: list[dict[str, Any]]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate({"scopes": scopes})


def test_an_empty_scope_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"scopes": [{"product_id": None, "by_bucket": [], "by_provenance": []}]})


@pytest.mark.parametrize("field", ["product_id", "by_bucket", "by_provenance"])
def test_every_scope_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["scopes"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", list(_rollup("partial")))
def test_every_rollup_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["scopes"][0]["by_bucket"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "scope", "rollup"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    scope = document["scopes"][0]
    {"view": document, "scope": scope, "rollup": scope["by_bucket"][0]}[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("cut", "field", "invalid"),
    [
        ("by_bucket", "key", "almost"),
        ("by_bucket", "key", "delegated-dependency"),
        ("by_provenance", "key", "partial"),
        ("by_bucket", "repositories", 0),
        ("by_bucket", "mean_overall", 100.5),
        ("by_bucket", "mean_overall", -1),
        ("by_bucket", "blocked", -1),
        ("by_bucket", "remediations", {"later": 1}),
        ("by_bucket", "remediations", {"fix-now": 0}),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], cut: str, field: str, invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    broken["scopes"][0][cut][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


@pytest.mark.parametrize(
    ("registry", "path", "extra"),
    [
        ("pqc-readiness-bucket", "by_bucket", ["unbucketed"]),
        ("pqc-dominant-provenance", "by_provenance", []),
    ],
)
def test_cut_keys_match_their_registries(registry: str, path: str, extra: list[str]) -> None:
    values = json.loads((ROOT / f"enums/v1/{registry}.json").read_text())["values"]
    rule = json.loads(SCHEMA.read_text())["$defs"]["scope"]["allOf"][0]["then"]["properties"]
    assert rule[path]["items"]["properties"]["key"]["enum"] == [*values, *extra]


def test_remediation_categories_match_their_registry() -> None:
    values = json.loads((ROOT / "enums/v1/pqc-remediation-category.json").read_text())["values"]
    rollup = json.loads(SCHEMA.read_text())["$defs"]["rollup"]
    assert rollup["properties"]["remediations"]["propertyNames"]["enum"] == values
