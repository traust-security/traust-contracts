from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = Path(__file__).parents[1] / "views_schema/v1/inventory-export.schema.json"
STRING_COLUMNS = ("Repository", "URL", "Host", "Organization/Group", "Repo Name")
LIST_COLUMNS = ("Owner Team", "Products", "Accountable Contacts")


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "rows": [
            {
                "Repository": "group/project",
                "URL": "https://git.example/group/project",
                "Host": "git.example",
                "Organization/Group": "group",
                "Repo Name": "project",
                "Owner Team": ["security", "platform"],
                "Products": ["first-product", "second-product"],
                "Accountable Contacts": ["alice (owner; embargo_cleared=True)"],
            }
        ]
    }


def test_legacy_rows_in_native_wrapper_validate(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    validator.validate(document)


def test_empty_inventory_validates(validator: Draft202012Validator) -> None:
    validator.validate({"rows": []})


def test_empty_strings_and_lists_validate(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["rows"][0] = {
        **dict.fromkeys(STRING_COLUMNS, ""),
        **{column: [] for column in LIST_COLUMNS},
    }
    validator.validate(document)


@pytest.mark.parametrize("column", STRING_COLUMNS + LIST_COLUMNS)
def test_hostile_strings_are_preserved_as_data(
    validator: Draft202012Validator, document: dict[str, Any], column: str
) -> None:
    raw = '=SUM(1,2);\r\n<script>alert("inventory")</script>\x00[repo](javascript:alert(1))☃'
    document["rows"][0][column] = [raw, "", raw] if column in LIST_COLUMNS else raw
    decoded = json.loads(json.dumps(document))
    validator.validate(decoded)
    assert decoded["rows"][0][column] == document["rows"][0][column]


@pytest.mark.parametrize("url", ["not a URL", "../local repository", "ssh://host/group/repo"])
def test_url_is_unrestricted_raw_text(
    validator: Draft202012Validator, document: dict[str, Any], url: str
) -> None:
    document["rows"][0]["URL"] = url
    validator.validate(document)


@pytest.mark.parametrize("column", STRING_COLUMNS + LIST_COLUMNS)
def test_every_human_column_is_required(
    validator: Draft202012Validator, document: dict[str, Any], column: str
) -> None:
    del document["rows"][0][column]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("column", STRING_COLUMNS)
@pytest.mark.parametrize("invalid", [None, 0, True, [], {}])
def test_scalar_columns_require_strings(
    validator: Draft202012Validator, document: dict[str, Any], column: str, invalid: Any
) -> None:
    document["rows"][0][column] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("column", LIST_COLUMNS)
@pytest.mark.parametrize("invalid", [None, "team", 0, True, {}, [None], [1], [True], [[]], [{}]])
def test_list_columns_require_arrays_of_strings(
    validator: Draft202012Validator, document: dict[str, Any], column: str, invalid: Any
) -> None:
    document["rows"][0][column] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("invalid", [None, {}, "rows", 0, True, [None], [[]], ["row"], [1]])
def test_rows_requires_an_array_of_objects(validator: Draft202012Validator, invalid: Any) -> None:
    with pytest.raises(ValidationError):
        validator.validate({"rows": invalid})


@pytest.mark.parametrize("invalid", [None, [], "inventory", 0, True, {}])
def test_root_requires_an_object_with_rows(validator: Draft202012Validator, invalid: Any) -> None:
    with pytest.raises(ValidationError):
        validator.validate(invalid)


@pytest.mark.parametrize("scope", ["view", "row"])
@pytest.mark.parametrize("extra", ["unexpected", "artifact_type", "storage", "id", "repository"])
def test_unknown_fields_are_rejected_at_both_object_boundaries(
    validator: Draft202012Validator, document: dict[str, Any], scope: str, extra: str
) -> None:
    target = document if scope == "view" else document["rows"][0]
    target[extra] = "not part of the inventory view"
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_bare_legacy_array_is_not_the_native_wrapper(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document["rows"])
