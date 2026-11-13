from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/exposure.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _rollup(key: str | None) -> dict[str, Any]:
    return {
        "key": key,
        "commits": 3,
        "exposed": 2,
        "affected": 1,
        "by_classification": {"affected": 1, "inconclusive": 1, "not_imported": 1},
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "by_advisory": [_rollup("GHSA-xxxx-xxxx-xxxx")],
        "by_product": [_rollup("example-product"), _rollup(None)],
        "by_classification": [_rollup("affected")],
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_empty_view_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"by_advisory": [], "by_product": [], "by_classification": []})


@pytest.mark.parametrize("field", ["by_advisory", "by_product", "by_classification"])
def test_every_list_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", list(_rollup("k")))
def test_every_row_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["by_advisory"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "row"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    (document if target == "view" else document["by_product"][0])["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("commits", 0),
        ("exposed", -1),
        ("affected", -1),
        ("key", 7),
        ("by_classification", {"exploited": 1}),
        ("by_classification", {"affected": 0}),
        ("by_classification", None),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], field: str, invalid: Any
) -> None:
    broken = copy.deepcopy(document)
    broken["by_advisory"][0][field] = invalid
    with pytest.raises(ValidationError):
        validator.validate(broken)


def test_verdicts_match_the_impact_classification_registry() -> None:
    values = json.loads((ROOT / "enums/v1/impact-classification.json").read_text())["values"]
    row = json.loads(SCHEMA.read_text())["$defs"]["rollup"]
    assert row["properties"]["by_classification"]["propertyNames"]["enum"] == values
