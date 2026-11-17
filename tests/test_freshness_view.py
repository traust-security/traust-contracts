from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/freshness.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (json.loads(p.read_text()) for p in sorted(SCHEMA.parent.glob("*.schema.json")))
    ]
    return Draft202012Validator(
        schema, registry=Registry().with_resources(resources), format_checker=FormatChecker()
    )


def _item(item: str, status: str, refresh: str | None = None, detail: str = "") -> dict[str, Any]:
    return {"item": item, "status": status, "detail": detail, "refresh": refresh}


def _database(**changes: Any) -> dict[str, Any]:
    return {
        "tool": "grype",
        "exists": True,
        "built_at": "2026-08-24T00:00:00Z",
        "schema_version": "5",
        "max_age": "P5DT1H",
        "path": "/var/lib/grype",
    } | changes


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "items": [
            _item("feeds:osv", "stale", "fetch feed osv", "retrieved 2026-11-01"),
            _item("scanner:grype", "unavailable", detail="not installed"),
            _item("assessments:secure-code", "pending", "run /secure-code-audit"),
            _item("assessments:threat-model", "pending", detail="no threat models recorded yet"),
            _item("database:grype", "fresh", detail="built 2026-08-24"),
        ],
        "toolchain": {
            "core_version": "1.2.3",
            "tools": [
                {"tool": "grype", "version": "0.115.0", "database": _database()},
                {"tool": "syft", "version": None, "database": None},
            ],
        },
        "coverage": {"examined": 1, "total": 2, "gaps": []},
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_an_unreadable_toolchain_is_explained_by_its_item(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["toolchain"] = None
    document["items"].insert(1, _item("toolchain", "unavailable", detail="no tools registered"))
    validator.validate(document)


def test_the_two_cadences_alone_are_valid(validator: Draft202012Validator) -> None:
    validator.validate(
        {
            "items": [
                _item("assessments:secure-code", "fresh", detail="no repositories"),
                _item("assessments:threat-model", "pending"),
            ],
            "toolchain": {"core_version": "1.2.3", "tools": []},
            "coverage": {"examined": 0, "total": 0, "gaps": []},
        }
    )


@pytest.mark.parametrize("value", ["PT0S", "P30D", "P1DT12H", "PT1.5S", "P1Y35DT1M", "-P1D", None])
def test_max_age_is_an_iso_duration_or_null(
    validator: Draft202012Validator, document: dict[str, Any], value: str | None
) -> None:
    document["toolchain"]["tools"][0]["database"]["max_age"] = value
    validator.validate(document)


@pytest.mark.parametrize("value", ["P", "PT", "5 days", "P5D\n", "P1DT", "432000", 5])
def test_max_age_outside_the_duration_form_is_rejected(
    validator: Draft202012Validator, document: dict[str, Any], value: Any
) -> None:
    document["toolchain"]["tools"][0]["database"]["max_age"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        *(("view", f) for f in ("items", "toolchain", "coverage")),
        *(("item", f) for f in ("item", "status", "detail", "refresh")),
        *(("toolchain", f) for f in ("core_version", "tools")),
        *(("tool", f) for f in ("tool", "version", "database")),
        *(("database", f) for f in _database()),
    ],
)
def test_every_serialized_field_is_required_nullable_ones_included(
    validator: Draft202012Validator, document: dict[str, Any], target: str, field: str
) -> None:
    tool = document["toolchain"]["tools"][0]
    {
        "view": document,
        "item": document["items"][4],
        "toolchain": document["toolchain"],
        "tool": tool,
        "database": tool["database"],
    }[target].pop(field)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "item", "toolchain", "tool", "database"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    tool = document["toolchain"]["tools"][0]
    {
        "view": document,
        "item": document["items"][0],
        "toolchain": document["toolchain"],
        "tool": tool,
        "database": tool["database"],
    }[target]["x"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("items", 0, "item"), ""),
        (("items", 0, "status"), "old"),
        (("items", 0, "detail"), None),
        (("items", 0, "refresh"), ""),
        (("toolchain", "core_version"), ""),
        (("toolchain", "tools", 0, "database", "exists"), None),
        (("toolchain", "tools", 0, "database", "built_at"), "2026-08-24"),
        (("coverage", "examined"), -1),
        (("coverage", "x"), 1),
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


@pytest.mark.parametrize("cadence", ["assessments:secure-code", "assessments:threat-model"])
def test_each_cadence_appears_exactly_once(
    validator: Draft202012Validator, document: dict[str, Any], cadence: str
) -> None:
    missing = copy.deepcopy(document)
    missing["items"] = [i for i in missing["items"] if i["item"] != cadence]
    missing["items"].append(_item("feeds:nvd", "fresh"))
    with pytest.raises(ValidationError):
        validator.validate(missing)
    document["items"].append(_item(cadence, "fresh"))
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("status", "refresh"),
    [("stale", None), ("fresh", "fetch feed osv"), ("unavailable", "install it")],
)
def test_refresh_follows_the_status(
    validator: Draft202012Validator, document: dict[str, Any], status: str, refresh: str | None
) -> None:
    document["items"][0] |= {"status": status, "refresh": refresh}
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_pending_item_may_or_may_not_say_how_to_refresh(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    assert document["items"][2]["refresh"] and document["items"][3]["refresh"] is None
    validator.validate(document)


def test_no_toolchain_needs_its_unavailable_item(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(document | {"toolchain": None})


def test_a_read_toolchain_has_no_toolchain_item(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["items"].append(_item("toolchain", "unavailable"))
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_coverage_is_the_coverage_views_definition() -> None:
    coverage = json.loads(SCHEMA.read_text())["properties"]["coverage"]
    assert coverage["$ref"].endswith("views_schema/v1/coverage.schema.json#/$defs/coverage")
