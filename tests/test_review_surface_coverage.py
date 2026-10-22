"""report.review_surface_coverage: a deterministic record of review-surface coverage.

One entry per review surface (enums/v1/review-surface.json), each with a
status from enums/v1/review-surface-status.json. The schema checks that every
surface is answered and each status carries what it needs; storage carries the
record in its own column. Also guards that no top-level report property is
silently dropped by the store.
"""

from __future__ import annotations

import json
import re
import sqlite3

import pytest
from conftest import report_with_findings
from jsonschema import Draft202012Validator

from traust_contracts.paths import enum_dir, schema_dir, storage_dir
from traust_contracts.v1.storage import Binding, Store
from traust_contracts.v1.storage.sql import view_names
from traust_contracts.v1.storage.store import ONE_ROW_PROJECTIONS

REPORT = json.loads((schema_dir() / "report.schema.json").read_text(encoding="utf-8"))
SURFACES = json.loads((enum_dir() / "review-surface.json").read_text(encoding="utf-8"))["values"]


def _coverage() -> dict:
    record = {s: {"status": "negative"} for s in SURFACES}
    record["credential-acceptance"] = {"status": "finding", "finding_ids": ["FIND-001"]}
    record["stored-content-integrity"] = {
        "status": "not_applicable",
        "note": "no content-addressed or deduplicated store",
    }
    record["outbound-fetch"] = {"status": "not_assessed", "note": "scoped audit"}
    return record


def _errors(record: dict) -> list[str]:
    validator = Draft202012Validator(
        {**REPORT["properties"]["review_surface_coverage"], "$defs": REPORT["$defs"]}
    )
    return [e.message for e in validator.iter_errors(record)]


def test_enum_and_schema_agree_on_the_surfaces():
    prop = REPORT["properties"]["review_surface_coverage"]
    assert prop["propertyNames"]["enum"] == SURFACES
    assert prop["required"] == SURFACES


def test_a_complete_record_validates():
    assert _errors(_coverage()) == []


@pytest.mark.parametrize(
    ("mutate", "why"),
    [
        (lambda r: r.pop("ownership-resolution"), "a surface is missing"),
        (lambda r: r.__setitem__("made-up-surface", {"status": "negative"}), "unknown surface"),
        (lambda r: r.__setitem__("security-flags", {"status": "skipped"}), "unknown status"),
        (lambda r: r.__setitem__("security-flags", {"status": "finding"}), "finding without ids"),
        (
            lambda r: r.__setitem__("security-flags", {"status": "finding", "finding_ids": []}),
            "finding with an empty id list",
        ),
        (lambda r: r.__setitem__("security-flags", {"status": "not_applicable"}), "no note"),
        (
            lambda r: r.__setitem__("security-flags", {"status": "not_assessed", "note": ""}),
            "empty note",
        ),
        (
            lambda r: r.__setitem__("security-flags", {"status": "negative", "extra": 1}),
            "undeclared key",
        ),
    ],
)
def test_malformed_records_fail(mutate, why):
    record = _coverage()
    mutate(record)
    assert _errors(record), why


def test_the_field_is_optional_for_existing_reports():
    assert "review_surface_coverage" not in REPORT.get("required", [])


def test_every_top_level_report_property_reaches_a_column():
    """The store writes reports through an explicit column list; a declared
    top-level property missing from it (or from the DDL) is silently dropped."""
    _, fields = ONE_ROW_PROJECTIONS["report"]
    projected = {name for name, _ in fields}
    declared = set(REPORT["properties"])
    assert declared == projected, sorted(declared ^ projected)
    for dialect in ("sqlite", "postgres"):
        ddl = (storage_dir() / dialect / "schema" / "report.sql").read_text(encoding="utf-8")
        missing = [p for p in declared if not re.search(rf"^\s+{p}\s", ddl, re.M)]
        assert missing == [], (dialect, missing)


def test_ingest_stores_the_record():
    conn = sqlite3.connect(":memory:")
    store = Store(conn)
    store.init()
    document = json.loads(report_with_findings())
    document["review_surface_coverage"] = _coverage()
    result = store.ingest(
        "report",
        json.dumps(document).encode(),
        Binding("local", "sci:inventory-item:42", "sci:scan-result:7", None, None),
    )
    (stored,) = conn.execute(
        "SELECT review_surface_coverage FROM report WHERE binding_id = ?", (result.binding_id,)
    ).fetchone()
    assert json.loads(stored) == _coverage()


def test_migrating_from_revision_two_adds_the_column():
    conn = sqlite3.connect(":memory:")
    store = Store(conn)
    store.init()
    conn.execute("ALTER TABLE report DROP COLUMN review_surface_coverage")
    conn.execute("ALTER TABLE verification DROP COLUMN review_surface_coverage")
    for name in reversed(view_names("sqlite")):  # migrate() recreates them
        conn.execute(f"DROP VIEW IF EXISTS {name}")
    conn.execute("ALTER TABLE threat DROP COLUMN review_surfaces")
    conn.execute("ALTER TABLE report_finding DROP COLUMN owasp_llm_references")  # revision 6
    conn.execute("UPDATE traust_storage_meta SET revision = 2")
    conn.commit()
    store.migrate()
    columns = {row[1] for row in conn.execute("PRAGMA table_info(report)")}
    assert "review_surface_coverage" in columns
