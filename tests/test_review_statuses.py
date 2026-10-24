import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("status", "allowed"),
    [
        ("pending", True),
        ("confirmed", True),
        ("rejected", True),
        ("accepted", True),
        ("closed_unreviewed", True),
        ("resolved", False),
        ("", False),
    ],
)
def test_whole_layer_review_status_compatibility(status: str, allowed: bool) -> None:
    schema = json.loads((ROOT / "artifacts_schema/v1/layer.schema.json").read_text())
    layer = json.loads((ROOT / "tests/fixtures/sample-findings-layer.json").read_text())
    layer["needs_review"][0]["status"] = status
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    assert validator.is_valid(layer) is allowed
