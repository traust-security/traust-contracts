from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/code-facts.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize("symbols,languages", [([], None), (None, []), ([], [])])
def test_measured_empty_is_distinct_from_unmeasured(
    validator: Draft202012Validator, symbols: object, languages: object
) -> None:
    validator.validate({"artifact": "code-facts", "symbols": symbols, "languages": languages})


def test_a_document_must_report_at_least_one_measurement(
    validator: Draft202012Validator,
) -> None:
    with pytest.raises(ValidationError):
        validator.validate({"artifact": "code-facts", "symbols": None, "languages": None})


@pytest.mark.parametrize("missing", ["artifact", "symbols", "languages"])
def test_measurement_presence_is_explicit(validator: Draft202012Validator, missing: str) -> None:
    document = {"artifact": "code-facts", "symbols": [], "languages": []}
    del document[missing]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        "../escape.go",
        "/app.go",
        "a/../app.go",
        "./app.go",
        "C:/app.go",
        "a\\b.go",
        "pkg\n/../../app.go",
    ],
)
def test_symbol_paths_stay_relative_to_the_scanned_ref(
    validator: Draft202012Validator, path: str
) -> None:
    document = {
        "artifact": "code-facts",
        "symbols": [{"name": "Handle", "path": path, "line": 1, "kind": "func", "language": "Go"}],
        "languages": None,
    }
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("code", [-1, 1.5, None, True])
def test_loc_is_a_measured_nonnegative_integer(
    validator: Draft202012Validator, code: object
) -> None:
    document = {
        "artifact": "code-facts",
        "symbols": None,
        "languages": [
            {"name": "Go", "files": None, "code": code, "comments": None, "blanks": None}
        ],
    }
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_symbols_and_real_counter_shapes_are_accepted(
    validator: Draft202012Validator,
) -> None:
    validator.validate(
        {
            "artifact": "code-facts",
            "symbols": [
                {
                    "name": "Handle",
                    "path": "pkg/app.go",
                    "line": 3,
                    "kind": "func",
                    "language": "Go",
                }
            ],
            "languages": [{"name": "Go", "files": 1, "code": 5, "comments": 1, "blanks": 2}],
        }
    )
