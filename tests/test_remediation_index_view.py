from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/remediation-index.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _row(**overrides: Any) -> dict[str, Any]:
    row = {
        "product": "example-product",
        "repository_url": "https://example.com/org/repo",
        "work_item_id": "00000000-0000-4000-8000-000000000001",
        "status": "pr_opened",
        "findings": 2,
        "fork_url": "https://example.com/mirror/repo",
        "fix_branch": "traust/fix-1",
        "tracker": "PROJ-123",
    }
    return {**row, **overrides}


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "rows": [
            _row(),
            _row(
                work_item_id="00000000-0000-4000-8000-000000000002",
                status="candidate",
                fork_url=None,
                fix_branch=None,
                tracker=None,
            ),
        ],
        "by_status": {"pr_opened": 1, "candidate": 1},
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_scope_with_no_work_items_is_valid(validator: Draft202012Validator) -> None:
    validator.validate({"rows": [], "by_status": {}})


def test_an_unnamed_product_group_is_null(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    for row in document["rows"]:
        row["product"] = None
    validator.validate(document)


@pytest.mark.parametrize("field", ["rows", "by_status"])
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", list(_row()))
def test_every_serialized_row_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    broken = copy.deepcopy(document)
    del broken["rows"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(broken)


@pytest.mark.parametrize("scope", ["view", "row"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    (document if scope == "view" else document["rows"][0])["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_statuses_match_the_remediation_status_registry() -> None:
    registry = json.loads((ROOT / "enums/v1/remediation-status.json").read_text())["values"]
    assert json.loads(SCHEMA.read_text())["$defs"]["status"]["enum"] == registry


@pytest.mark.parametrize("status", ["open", "Merged", "", None])
def test_unknown_statuses_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], status: Any
) -> None:
    document["rows"][0]["status"] = status
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "by_status", [{"unknown": 1}, {"merged": 0}, {"merged": -1}, {"merged": 1.5}, {"merged": "1"}]
)
def test_by_status_counts_only_known_statuses_seen(
    validator: Draft202012Validator, document: dict[str, Any], by_status: dict[str, Any]
) -> None:
    document["by_status"] = by_status
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("findings", [-1, 1.5, "2", None])
def test_findings_is_a_nonnegative_count(
    validator: Draft202012Validator, document: dict[str, Any], findings: Any
) -> None:
    document["rows"][0]["findings"] = findings
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "fork_url",
    ["https://github.com/a/b", "https://gitlab.example.com/group/sub/repo", "https://h/a/b.c_d-e"],
)
def test_a_fork_is_cores_canonical_https_repository_url(
    validator: Draft202012Validator, document: dict[str, Any], fork_url: str
) -> None:
    document["rows"][0]["fork_url"] = fork_url
    validator.validate(document)


@pytest.mark.parametrize(
    "fork_url",
    [
        "https://",
        "https://github.com",
        "https://github.com/",
        "https://github.com/a",
        "https://github.com/a/b/",
        "https://GitHub.com/a/b",
        "https://user@github.com/a/b",
        "https://github.com:8443/a/b",
        "https://github.com/a/b?x=1",
        "https://github.com/a/b#x",
        "https://github.com/a/../b",
        "https://github.com/./b",
        "https://github.com/-a/b",
        "https://gith..ub.com/a/b",
        "https://-github.com/a/b",
        "https://github.com/a/b\n",
        "http://example.com/org/repo",
        "git@example.com:org/repo",
        "",
    ],
)
def test_malformed_fork_urls_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], fork_url: str
) -> None:
    document["rows"][0]["fork_url"] = fork_url
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("invalid", ["not-a-uuid", "", None])
def test_invalid_work_item_ids_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], invalid: Any
) -> None:
    document["rows"][0]["work_item_id"] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


UNTRUSTED = "<script>alert(1)</script>\n| fake | row |\n[x](javascript:alert(1)) ‮"


@pytest.mark.parametrize("field", ["repository_url", "fix_branch", "tracker", "product"])
@pytest.mark.parametrize("raw", ["", UNTRUSTED])
def test_raw_untrusted_text_remains_data(
    validator: Draft202012Validator, document: dict[str, Any], field: str, raw: str
) -> None:
    document["rows"][0][field] = raw
    validator.validate(document)
