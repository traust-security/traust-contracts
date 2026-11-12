from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "artifacts_schema/v1/insight-builds.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "folded_after": "2026-11-12T00:00:00Z",
        "views": {
            "findings-rollup": {"as_of": None, "total": {}},
            "coverage": {"population": {}},
        },
    }


def test_a_stored_build_validates(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    validator.validate(document)
    validator.validate(document | {"folded_after": None})


@pytest.mark.parametrize(
    "drift",
    [
        {"folded_after": "not-a-timestamp"},
        {"folded_after": 0},
        {"views": {}},
        {"views": {"findings rollup": {}}},
        {"views": {"findings-rollup": []}},
        {"extra": 1},
    ],
)
def test_a_drifted_build_is_refused(
    validator: Draft202012Validator, document: dict[str, Any], drift: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | drift)


@pytest.mark.parametrize("field", ["folded_after", "views"])
def test_both_fields_are_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    with pytest.raises(ValidationError):
        validator.validate({k: v for k, v in document.items() if k != field})
