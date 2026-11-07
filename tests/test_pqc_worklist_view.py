from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = Path(__file__).parents[1] / "views_schema/v1/pqc-worklist.schema.json"
REPOSITORY_ID = "00000000-0000-4000-8000-000000000001"
REF_ID = "00000000-0000-4000-8000-000000000002"
ASSESSMENT_ID = "00000000-0000-4000-8000-000000000003"
PRODUCT_ID = "00000000-0000-4000-8000-000000000004"
HOSTILE = '<script>alert("repo")</script>\n| fake | row |\n[jump](javascript:alert(1)) & \u202e'


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "product_id": None,
        "repository_ref_ids": None,
        "chokepoints": [],
        "entries": [
            {
                "repository_id": REPOSITORY_ID,
                "repository": "https://example.com/repo",
                "repository_ref_id": REF_ID,
                "sha": "legacy-sha",
                "priority_tier": "tail",
                "route": "source",
                "access": {
                    "repository_id": REPOSITORY_ID,
                    "url": "https://example.com/repo",
                    "observed_at": "2026-11-01T09:30:00+02:00",
                    "archived": False,
                    "pushed_at": "historical date",
                    "dormant": False,
                    "unobserved": None,
                    "reason": None,
                },
                "reason": None,
                "scan": {
                    "repository_ref_id": REF_ID,
                    "assessment_id": ASSESSMENT_ID,
                    "basis": "recorded-basis",
                    "current": True,
                },
                "cursor": "2|https://example.com/repo",
            }
        ],
    }


def target(document: dict[str, Any], path: tuple[str | int, ...]) -> Any:
    value = document
    for part in path:
        value = value[part]
    return value


OBJECT_PATHS = [(), ("entries", 0), ("entries", 0, "access"), ("entries", 0, "scan")]


@pytest.mark.parametrize("path", OBJECT_PATHS)
def test_each_serialized_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    obj = target(document, path)
    for field in tuple(obj):
        saved = obj.pop(field)
        with pytest.raises(ValidationError):
            validator.validate(document)
        obj[field] = saved


@pytest.mark.parametrize("path", OBJECT_PATHS)
def test_every_object_rejects_unknown_fields(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    target(document, path)["unexpected"] = "not part of the contract"
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("product_id", [None, PRODUCT_ID])
@pytest.mark.parametrize("refs", [None, [], [REF_ID]])
def test_global_product_and_explicit_empty_scope_remain_distinct(
    validator: Draft202012Validator, document: dict[str, Any], product_id: Any, refs: Any
) -> None:
    document.update(product_id=product_id, repository_ref_ids=refs, entries=[])
    validator.validate(document)
    assert json.loads(json.dumps(document))["repository_ref_ids"] == refs


@pytest.mark.parametrize("tier", ["chokepoint", "crypto-cwe", "tail"])
@pytest.mark.parametrize("route", ["source", "sbom-only", "access-request"])
def test_all_existing_routes_and_priority_tiers(
    validator: Draft202012Validator, document: dict[str, Any], tier: str, route: str
) -> None:
    document["entries"][0].update(priority_tier=tier, route=route)
    validator.validate(document)


def test_unregistered_repository_preserves_null_ref_sha_and_scan(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    entry = document["entries"][0]
    entry.update(
        repository_ref_id=None,
        sha=None,
        scan=None,
        route="access-request",
        reason="no-registered-commit",
    )
    entry["access"].update(
        observed_at=None,
        archived=None,
        pushed_at=None,
        dormant=None,
        unobserved=None,
        reason=None,
    )
    validator.validate(document)


@pytest.mark.parametrize("state", [None, False, True])
def test_unknown_and_measured_liveness_and_scan_states_are_distinct(
    validator: Draft202012Validator, document: dict[str, Any], state: bool | None
) -> None:
    entry = document["entries"][0]
    entry["access"].update(archived=state, dormant=state)
    entry["scan"].update(current=state, assessment_id=None, basis=None)
    validator.validate(document)
    restored = json.loads(json.dumps(document))["entries"][0]
    assert restored["scan"]["current"] is state
    assert restored["access"]["archived"] is state
    assert restored["access"]["dormant"] is state


@pytest.mark.parametrize("raw", ["", "legacy-value", HOSTILE])
def test_raw_scope_and_historical_strings_are_not_url_sha_or_markup_restricted(
    validator: Draft202012Validator, document: dict[str, Any], raw: str
) -> None:
    document["chokepoints"] = [raw]
    entry = document["entries"][0]
    entry.update(repository=raw, sha=raw, reason=raw, cursor="2|" + raw)
    entry["access"].update(url=raw, pushed_at=raw, unobserved=raw, reason=raw)
    entry["scan"]["basis"] = raw
    validator.validate(document)


ID_PATHS = [
    ("product_id",),
    ("repository_ref_ids", 0),
    ("entries", 0, "repository_id"),
    ("entries", 0, "repository_ref_id"),
    ("entries", 0, "access", "repository_id"),
    ("entries", 0, "scan", "repository_ref_id"),
    ("entries", 0, "scan", "assessment_id"),
]


@pytest.mark.parametrize("path", ID_PATHS)
@pytest.mark.parametrize("invalid", ["not-a-uuid", "00000000000040008000000000000001", "", 1])
def test_identifiers_require_uuid_strings(
    validator: Draft202012Validator,
    document: dict[str, Any],
    path: tuple[str | int, ...],
    invalid: Any,
) -> None:
    document["repository_ref_ids"] = [REF_ID]
    target(document, path[:-1])[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "invalid", ["yesterday", "2026-02-30T00:00:00Z", "2026-11-01T09:30:00", False]
)
def test_observation_time_requires_nullable_rfc3339(
    validator: Draft202012Validator, document: dict[str, Any], invalid: Any
) -> None:
    document["entries"][0]["access"]["observed_at"] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        ((), None),
        (("repository_ref_ids",), {}),
        (("repository_ref_ids",), [None]),
        (("chokepoints",), None),
        (("chokepoints",), [1]),
        (("entries",), None),
        (("entries",), {}),
        (("entries",), [None]),
        (("entries", 0, "repository_id"), None),
        (("entries", 0, "repository"), None),
        (("entries", 0, "sha"), False),
        (("entries", 0, "priority_tier"), "urgent"),
        (("entries", 0, "route"), "unknown"),
        (("entries", 0, "reason"), 1),
        (("entries", 0, "cursor"), None),
        (("entries", 0, "access"), None),
        (("entries", 0, "access", "repository_id"), None),
        (("entries", 0, "access", "url"), False),
        (("entries", 0, "access", "archived"), 0),
        (("entries", 0, "access", "dormant"), "false"),
        (("entries", 0, "access", "pushed_at"), 1),
        (("entries", 0, "access", "unobserved"), False),
        (("entries", 0, "access", "reason"), []),
        (("entries", 0, "scan"), []),
        (("entries", 0, "scan", "repository_ref_id"), None),
        (("entries", 0, "scan", "basis"), 1),
        (("entries", 0, "scan", "current"), 0),
    ],
)
def test_structured_types_and_closed_vocabularies_are_enforced(
    validator: Draft202012Validator,
    document: dict[str, Any],
    path: tuple[str | int, ...],
    invalid: Any,
) -> None:
    if path:
        target(document, path[:-1])[path[-1]] = invalid
    else:
        document = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)
