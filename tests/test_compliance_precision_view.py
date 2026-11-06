from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_contracts import build_registry

SCHEMA = Path(__file__).parents[1] / "views_schema/v1/compliance-precision.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "calibration": {
            "framework": "nist-800-53-rev5",
            "assessments": 2,
            "checks": [
                {
                    "check_id": "automatic-control",
                    "fired": 2,
                    "dismissed": 1,
                    "gate": 0.5,
                    "precision": 0.5,
                    "flagged": True,
                }
            ],
            "gate": 0.5,
        }
    }


def test_native_calibration_wrapper_resolves_framework_locally(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    validator.validate(document)
    document["calibration"]["framework"] = "invented-framework"
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_empty_population_is_not_a_score(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["calibration"].update(assessments=0, checks=[])
    validator.validate(document)


def test_no_firings_preserves_unmeasured_precision(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["calibration"]["checks"][0].update(fired=0, dismissed=0, precision=None, flagged=False)
    validator.validate(document)


@pytest.mark.parametrize("precision", [0, 1])
def test_measured_precision_and_gate_endpoints_are_valid(
    validator: Draft202012Validator, document: dict[str, Any], precision: int
) -> None:
    document["calibration"]["gate"] = precision
    document["calibration"]["checks"][0].update(
        gate=precision, precision=precision, dismissed=2 * (1 - precision)
    )
    validator.validate(document)


def test_hostile_check_identifier_remains_data(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["calibration"]["checks"][0]["check_id"] = (
        '../../[control](javascript:alert(1))\n<script>alert("check")</script>'
    )
    validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("calibration", "assessments"), -1),
        (("calibration", "assessments"), 0.5),
        (("calibration", "assessments"), True),
        (("calibration", "checks", 0, "fired"), -1),
        (("calibration", "checks", 0, "dismissed"), 0.5),
        (("calibration", "gate"), -0.1),
        (("calibration", "gate"), 1.1),
        (("calibration", "checks", 0, "gate"), -0.1),
        (("calibration", "checks", 0, "gate"), None),
        (("calibration", "checks", 0, "precision"), -0.1),
        (("calibration", "checks", 0, "precision"), 1.1),
        (("calibration", "checks", 0, "precision"), "0.5"),
        (("calibration", "checks", 0, "flagged"), 1),
        (("calibration", "checks", 0, "check_id"), None),
        (("calibration", "framework"), None),
        (("calibration", "checks"), {}),
        (("calibration",), []),
    ],
)
def test_invalid_values_are_rejected(
    validator: Draft202012Validator,
    document: dict[str, Any],
    path: tuple[str | int, ...],
    invalid: Any,
) -> None:
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("scope", ["view", "calibration", "check"])
@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_required_fields_and_unknown_fields_at_each_boundary(
    validator: Draft202012Validator, document: dict[str, Any], scope: str, mutation: str
) -> None:
    targets = {
        "view": (document, "calibration"),
        "calibration": (document["calibration"], "framework"),
        "check": (document["calibration"]["checks"][0], "precision"),
    }
    target, required = targets[scope]
    if mutation == "missing":
        del target[required]
    else:
        target["unexpected"] = "not part of the native model"
    with pytest.raises(ValidationError):
        validator.validate(document)
