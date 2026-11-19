from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Resource
from test_contracts import build_registry
from test_dependency_reach_view import SCHEMA

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def validators() -> tuple[Draft202012Validator, Draft202012Validator]:
    reach = json.loads(SCHEMA.read_text())
    path = FIXTURES / "dependency-reach-coverage-candidate.schema.json"
    candidate = json.loads(path.read_text())
    Draft202012Validator.check_schema(candidate)
    registry = build_registry().with_resource(reach["$id"], Resource.from_contents(reach))
    return Draft202012Validator(reach), Draft202012Validator(candidate, registry=registry)


def test_each_reach_response_and_coverage_envelope_have_separate_strict_readers(
    validators: tuple[Draft202012Validator, Draft202012Validator],
) -> None:
    v1, candidate = validators
    expected = json.loads((FIXTURES / "i8-reach-cases.json").read_text())
    path = os.environ.get("TRAUST_I8_CASES")
    cases = json.loads(Path(path).read_text()) if path is not None else expected
    assert cases.keys() == expected.keys()
    for case, pair in cases.items():
        reach = pair["reach"]
        v1.validate(reach)
        candidate.validate(pair)
        assert pair == expected[case], case
        assert not v1.is_valid(pair) and not candidate.is_valid(reach)
        expanded = {**reach, "coverage": pair["coverage"]}
        assert not v1.is_valid(expanded) and not candidate.is_valid(expanded)


@pytest.mark.parametrize(
    "coverage",
    [
        None,
        {},
        {"without_scan": 0},
        {"unresolved": {}},
        {"without_scan": -1, "unresolved": {}},
        {"without_scan": 0, "unresolved": None},
        {"without_scan": 0, "unresolved": {"npm": 0}},
        {"without_scan": 0, "unresolved": {"npm": "1"}},
        {"without_scan": 0, "unresolved": {"unknown-ecosystem": 1}},
        {"without_scan": 0, "unresolved": {}, "unexpected": True},
    ],
)
def test_invalid_or_incomplete_coverage_is_not_measured_empty(
    validators: tuple[Draft202012Validator, Draft202012Validator], coverage: Any
) -> None:
    _, candidate = validators
    reach = {"repositories": 1, "unmeasured": 0, "ecosystems": [], "shared": []}
    with pytest.raises(ValidationError):
        candidate.validate({"reach": reach, "coverage": coverage})


def test_envelope_does_not_relax_embedded_reach_or_allow_unknown_fields(
    validators: tuple[Draft202012Validator, Draft202012Validator],
) -> None:
    _, candidate = validators
    pair = json.loads((FIXTURES / "i8-reach-cases.json").read_text())["partial-positive"]
    assert not candidate.is_valid({**pair, "unexpected": 1})
    pair["reach"]["shared"][0]["repositories"] = 0
    assert not candidate.is_valid(pair)
