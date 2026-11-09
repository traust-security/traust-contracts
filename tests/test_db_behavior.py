"""What the database must enforce, on both engines.

Each test states a rule an application bug could break. Nothing here restates
the DDL (table, column or index lists): a test fails only if a rule stops
holding.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import bootstrap_namespaces_sqlite

from traust_contracts.v1.ledger import sql as ledger_sql
from traust_contracts.v1.ops import sql as ops_sql
from traust_contracts.v1.sql import bootstrap_statements
from traust_contracts.v1.storage import sql as storage_sql

MODULES = (storage_sql, ops_sql, ledger_sql)
SCHEMAS = ("traust_ledger", "traust_ops", "traust")
PREFIX = {"ops": ("ops_", "traust_ops."), "ledger": ("ledger_", "traust_ledger.")}


class Db:
    """One connection, one dialect: table names and placeholders mapped."""

    def __init__(self, engine: str, conn: Any, error: type[Exception]) -> None:
        self.engine, self.conn, self.Error = engine, conn, error

    def t(self, name: str) -> str:
        for ns, (sqlite_prefix, pg_schema) in PREFIX.items():
            if name.startswith(f"{ns}."):
                bare = name.split(".", 1)[1]
                return sqlite_prefix + bare if self.engine == "sqlite" else pg_schema + bare
        return name if self.engine == "sqlite" else f"traust.{name}"

    def run(self, sql: str, params: tuple = ()) -> list[tuple]:
        if self.engine == "postgres" and params:
            sql = sql.replace("?", "%s")
        cur = self.conn.execute(sql, params) if params else self.conn.execute(sql)
        return cur.fetchall() if cur.description else []

    def insert(self, table: str, **cols: Any) -> str:
        names = ", ".join(f'"{c}"' for c in cols)
        marks = ", ".join("?" for _ in cols)
        row = self.run(
            f"INSERT INTO {self.t(table)} ({names}) VALUES ({marks}) RETURNING id",
            tuple(cols.values()),
        )
        return str(row[0][0])

    def rejects(self, table: str, **cols: Any) -> None:
        with pytest.raises(self.Error):
            self.insert(table, **cols)


def _sqlite() -> Db:
    conn = bootstrap_namespaces_sqlite(*MODULES)
    conn.isolation_level = None
    return Db("sqlite", conn, sqlite3.Error)


def _postgres(dsn: str) -> Iterator[Db]:
    psycopg = pytest.importorskip("psycopg")
    conn = psycopg.connect(dsn, autocommit=True)
    for schema in SCHEMAS:
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    for module in MODULES:
        for path in module.bootstrap_files("postgres"):
            for statement in bootstrap_statements("postgres", path):
                conn.execute(statement)
    yield Db("postgres", conn, psycopg.Error)
    conn.close()


@pytest.fixture(params=["sqlite", "postgres"])
def db(request: pytest.FixtureRequest) -> Iterator[Db]:
    if request.param == "sqlite":
        yield _sqlite()
    else:
        yield from _postgres(request.getfixturevalue("postgres_dsn"))


NOW = "2026-10-20T12:00:00Z"
LATER = "2026-10-21T12:00:00Z"


def repo(db: Db, url: str = "https://example.com/r") -> str:
    return db.insert("repository", url=url, public=True)


def ref(db: Db, repository_id: str, name: str | None = "main", sha: str = "a" * 40) -> str:
    return db.insert(
        "repository_ref",
        repository_id=repository_id,
        name=name,
        kind="branch" if name else None,
        sha=sha,
    )


def assessment(db: Db, repository_ref_id: str) -> str:
    return db.insert(
        "assessment",
        repository_ref_id=repository_ref_id,
        kind="audit",
        status="completed",
        assessor="skill:vuln-scan",
        assessor_version="1",
        occurred_at=NOW,
    )


def finding(db: Db, repository_id: str, fingerprint: str = "f" * 64) -> str:
    return db.insert(
        "finding",
        repository_id=repository_id,
        fingerprint_algo="v3",
        fingerprint=fingerprint,
        title="t",
    )


def decision(db: Db, finding_id: str, **values: Any) -> str:
    return db.insert(
        "decision",
        **{
            "finding_id": finding_id,
            "actor": "human:a",
            "statement_key": str(uuid.uuid4()),
            "occurred_at": NOW,
            **values,
        },
    )


def test_database_owns_identity_and_time(db: Db) -> None:
    pid = db.insert("product", slug="acme", name="Acme")
    uuid.UUID(pid)
    created, updated = db.run(
        f"SELECT created_at, updated_at FROM {db.t('product')} WHERE id = ?", (pid,)
    )[0]
    assert created == updated
    time.sleep(0.02)
    db.run(f"UPDATE {db.t('product')} SET name = 'Acme 2' WHERE id = ?", (pid,))
    created2, updated2 = db.run(
        f"SELECT created_at, updated_at FROM {db.t('product')} WHERE id = ?", (pid,)
    )[0]
    assert created2 == created
    assert updated2 > updated


def test_rows_written_in_one_transaction_keep_their_order(db: Db) -> None:
    db.run("BEGIN")
    first = db.insert("team", name="first")
    time.sleep(0.002)  # SQLite stamps milliseconds
    second = db.insert("team", name="second")
    db.run("COMMIT")
    stamps = dict(db.run(f"SELECT id, created_at FROM {db.t('team')}"))
    assert (
        stamps[uuid.UUID(second) if db.engine == "postgres" else second]
        > stamps[uuid.UUID(first) if db.engine == "postgres" else first]
    )


def test_append_only_rows_are_never_changed(db: Db) -> None:
    sid = db.insert("sbom", digest="d" * 64)
    rid = repo(db)
    rref = ref(db, rid)
    fid = finding(db, rid)
    decided = db.insert(
        "decision",
        finding_id=fid,
        actor="human:a",
        repository_ref_id=rref,
        statement_key="k",
        occurred_at=NOW,
    )
    approver = db.insert("decision_approver", decision_id=decided, approver="human:b")
    spend = db.insert(
        "ops.spend_event",
        provider="p",
        model="m",
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.1,
        occurred_at=NOW,
    )
    for table, row in (("sbom", sid), ("ops.spend_event", spend), ("decision_approver", approver)):
        with pytest.raises(db.Error):
            db.run(f"UPDATE {db.t(table)} SET created_at = created_at WHERE id = ?", (row,))
        with pytest.raises(db.Error):
            db.run(f"DELETE FROM {db.t(table)} WHERE id = ?", (row,))


def test_referenced_rows_cannot_be_deleted(db: Db) -> None:
    rid = repo(db)
    ref(db, rid)
    with pytest.raises(db.Error):
        db.run(f"DELETE FROM {db.t('repository')} WHERE id = ?", (rid,))


def test_a_commit_is_recorded_once(db: Db) -> None:
    rid = repo(db)
    ref(db, rid, "main", "a" * 40)
    ref(db, rid, "release-4.22", "a" * 40)  # same sha on another line is fine
    db.rejects("repository_ref", repository_id=rid, name="main", kind="branch", sha="a" * 40)
    ref(db, rid, None, "b" * 40)
    db.rejects("repository_ref", repository_id=rid, sha="b" * 40)  # bare commit twice
    db.rejects("repository_ref", repository_id=rid, name="x", sha="c" * 40)  # name without kind
    db.rejects(
        "repository_ref", repository_id=rid, name="v1", kind="tag", is_default=True, sha="d" * 40
    )


def test_manifest_coverage_keeps_its_exact_scan_when_sbom_content_is_unchanged(db: Db) -> None:
    rref = ref(db, repo(db))
    table = db.t("repository_ref")
    query = f"SELECT manifest_sbom_id, manifest_sbom_assessment_id FROM {table} WHERE id = ?"
    assert db.run(query, (rref,)) == [(None, None)]
    sid = db.insert("sbom", digest="e" * 64)
    scans = []
    for _ in range(2):
        scan = db.insert(
            "assessment",
            repository_ref_id=rref,
            kind="manifest_sbom",
            status="completed",
            assessor="tool:syft",
            assessor_version="1.51.1",
            occurred_at=NOW,
            created_at=NOW,
        )
        scans.append(scan)
        db.run(
            f"UPDATE {table} SET manifest_sbom_id = ?, manifest_sbom_assessment_id = ? "
            "WHERE id = ?",
            (sid, scan, rref),
        )
        row = db.run(query, (rref,))[0]
        assert tuple(map(str, row)) == (sid, scan)
    assert scans[0] != scans[1]
    # Reinstalling the cyclic FK must preserve an already-bound scan.
    for path in storage_sql.bootstrap_files(db.engine):
        if path.stem in {"repository_ref", "assessment"}:
            for statement in bootstrap_statements(db.engine, path):
                db.run(statement)
    assert tuple(map(str, db.run(query, (rref,))[0])) == (sid, scans[1])
    db.run(f"UPDATE {table} SET manifest_sbom_assessment_id = NULL WHERE id = ?", (rref,))
    row = db.run(query, (rref,))[0]
    assert str(row[0]) == sid and row[1] is None


def test_a_manifest_scan_binding_must_reference_a_real_assessment(db: Db) -> None:
    rid = repo(db)
    rref = ref(db, rid)
    missing = str(uuid.uuid4())
    db.rejects(
        "repository_ref",
        repository_id=rid,
        sha="b" * 40,
        manifest_sbom_assessment_id=missing,
    )
    with pytest.raises(db.Error):
        db.run(
            f"UPDATE {db.t('repository_ref')} SET manifest_sbom_assessment_id = ? WHERE id = ?",
            (missing, rref),
        )
    assert db.run(
        f"SELECT manifest_sbom_assessment_id FROM {db.t('repository_ref')} WHERE id = ?", (rref,)
    ) == [(None,)]


def test_a_bound_manifest_assessment_cannot_be_deleted_through_its_ref(db: Db) -> None:
    rref = ref(db, repo(db))
    scan = assessment(db, rref)
    table = db.t("repository_ref")
    db.run(f"UPDATE {table} SET manifest_sbom_assessment_id = ? WHERE id = ?", (scan, rref))
    # Isolate the FK rule: the ordinary append-only guard would reject any delete.
    if db.engine == "sqlite":
        db.run("DROP TRIGGER assessment_reject_delete")
    else:
        db.run(f"DROP TRIGGER assessment_reject_mutation ON {db.t('assessment')}")
    with pytest.raises(db.Error):
        db.run(f"DELETE FROM {db.t('assessment')} WHERE id = ?", (scan,))
    assert (
        str(db.run(f"SELECT manifest_sbom_assessment_id FROM {table} WHERE id = ?", (rref,))[0][0])
        == scan
    )
    db.run(f"UPDATE {table} SET manifest_sbom_assessment_id = NULL WHERE id = ?", (rref,))
    db.run(f"DELETE FROM {db.t('assessment')} WHERE id = ?", (scan,))
    assert db.run(f"SELECT id FROM {table} WHERE id = ?", (rref,))


def test_manifest_scan_upgrade_preserves_existing_rows_without_inventing_coverage(db: Db) -> None:
    rref = ref(db, repo(db))
    scan = assessment(db, rref)
    sid = db.insert("sbom", digest="9" * 64)
    table = db.t("repository_ref")
    db.run(f"UPDATE {table} SET manifest_sbom_id = ? WHERE id = ?", (sid, rref))
    # Reproduce the prior table shape without recreating any populated table.
    db.run(f"DROP INDEX {db.t('idx_repository_ref_manifest_sbom_assessment')}")
    db.run(f"ALTER TABLE {table} DROP COLUMN manifest_sbom_assessment_id")
    query = f"SELECT * FROM {table} WHERE id = ?"
    before = db.run(query, (rref,))[0]
    assessment_before = db.run(f"SELECT * FROM {db.t('assessment')} WHERE id = ?", (scan,))
    sbom_before = db.run(f"SELECT * FROM {db.t('sbom')} WHERE id = ?", (sid,))
    for statement in storage_sql.manifest_sbom_binding_upgrade(db.engine):
        db.run(statement)
    row = db.run(query, (rref,))[0]
    assert row[:-1] == before and row[-1] is None
    assert db.run(f"SELECT * FROM {db.t('assessment')} WHERE id = ?", (scan,)) == assessment_before
    assert db.run(f"SELECT * FROM {db.t('sbom')} WHERE id = ?", (sid,)) == sbom_before
    with pytest.raises(db.Error):
        db.run(
            f"UPDATE {table} SET manifest_sbom_assessment_id = ? WHERE id = ?",
            (str(uuid.uuid4()), rref),
        )
    db.run(f"UPDATE {table} SET manifest_sbom_assessment_id = ? WHERE id = ?", (scan, rref))
    assert (
        str(db.run(f"SELECT manifest_sbom_assessment_id FROM {table} WHERE id = ?", (rref,))[0][0])
        == scan
    )
    # Normal bootstrap remains safe once the explicit upgrade has run.
    for path in storage_sql.bootstrap_files(db.engine):
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
    assert (
        str(db.run(f"SELECT manifest_sbom_assessment_id FROM {table} WHERE id = ?", (rref,))[0][0])
        == scan
    )


def test_default_named_at_upgrade_preserves_rows_without_inventing_times(db: Db) -> None:
    rid = repo(db)
    named = ref(db, rid)
    other = db.insert("repository_ref", repository_id=rid, name="main", kind="branch", sha="e" * 40)
    table = db.t("repository_ref")
    flagged = True if db.engine == "postgres" else 1
    db.run(f"UPDATE {table} SET is_default = ? WHERE id = ?", (flagged, named))
    assert db.run(f"SELECT is_default FROM {table} WHERE id = ?", (named,))[0][0] in (1, True)
    # Reproduce the prior table shape without recreating any populated table.
    db.run(f"DROP INDEX {db.t('idx_repository_ref_default')}")
    db.run(f"ALTER TABLE {table} DROP COLUMN default_named_at")
    for statement in storage_sql.default_named_at_upgrade(db.engine):
        db.run(statement)
    # The flagged row keeps an unknown naming time; the column is additive.
    listed = (
        f"PRAGMA table_info({table})"
        if db.engine == "sqlite"
        else (
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'repository_ref'"
        )
    )
    at = 1 if db.engine == "sqlite" else 0
    assert "default_named_at" in {d[at] for d in db.run(listed)}
    assert db.run(f"SELECT is_default FROM {table} WHERE id = ?", (named,))[0][0] in (1, True)
    assert db.run(f"SELECT default_named_at FROM {table} WHERE id = ?", (named,))[0][0] is None
    assert db.run(f"SELECT default_named_at FROM {table} WHERE id = ?", (other,))[0][0] is None
    # Stamping a naming time is a plain update once the column exists.
    db.run(f"UPDATE {table} SET default_named_at = ? WHERE id = ?", (NOW, named))
    named_at = db.run(f"SELECT default_named_at FROM {table} WHERE id = ?", (named,))[0][0]
    assert str(named_at).replace(" ", "T").startswith("2026-10-20T12:00:00")
    # Normal bootstrap remains safe once the explicit upgrade has run.
    for path in storage_sql.bootstrap_files(db.engine):
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
    again = db.run(f"SELECT default_named_at FROM {table} WHERE id = ?", (named,))[0][0]
    assert str(again).replace(" ", "T").startswith("2026-10-20T12:00:00")


def test_one_open_owner_row_per_team(db: Db) -> None:
    rid = repo(db)
    tid = db.insert("team", name="installer")
    db.insert("ownership", repository_id=rid, team_id=tid, valid_from=NOW)
    db.rejects("ownership", repository_id=rid, team_id=tid, valid_from=LATER)
    db.rejects("ownership", repository_id=rid, team_id=tid, valid_from=LATER, valid_to=NOW)


def test_artifact_is_one_row_per_producer_and_document(db: Db) -> None:
    rid = repo(db)
    first, second = assessment(db, ref(db, rid)), assessment(db, ref(db, rid, "dev"))
    doc = {"digest": "a" * 64, "kind": "report", "uri": "file:///artifacts/a.json"}
    db.insert("artifact", assessment_id=first, **doc)
    db.rejects("artifact", assessment_id=first, **doc)  # a retried publish is a no-op
    db.insert("artifact", assessment_id=second, **doc)  # same bytes, another producer
    db.insert("artifact", **{**doc, "digest": "b" * 64})  # imported
    db.rejects("artifact", **{**doc, "digest": "b" * 64})  # imported twice
    db.rejects("artifact", assessment_id=first, digest="c" * 64, kind="report", uri="")


def test_an_artifact_names_the_order_whose_run_recorded_it(db: Db) -> None:
    rid = repo(db)
    work, other = assessment(db, ref(db, rid)), assessment(db, ref(db, rid, "dev"))
    order = {"state": "queued", "priority": 1, "requested_by": "h", "repository_id": rid}
    fixing = db.insert("ops.run_order", asset="remediate_finding", work_item_id=work, **order)
    elsewhere = db.insert("ops.run_order", asset="remediate_finding", work_item_id=other, **order)
    scanning = db.insert("ops.run_order", asset="diff_scan", **order)
    produced = db.insert(
        "assessment",
        repository_ref_id=ref(db, rid, "scan"),
        run_order_id=scanning,
        kind="audit",
        status="completed",
        assessor="skill:vuln-scan",
        assessor_version="1",
        occurred_at=NOW,
    )
    doc = {"kind": "report", "uri": "file:///artifacts/a.json"}
    db.insert("artifact", assessment_id=work, run_order_id=fixing, digest="a" * 64, **doc)
    db.insert("artifact", assessment_id=produced, run_order_id=scanning, digest="d" * 64, **doc)
    db.insert("artifact", assessment_id=work, digest="b" * 64, **doc)  # recorded by hand
    for crossed in (elsewhere, scanning, str(uuid.uuid4())):  # another's item, none, no order
        db.rejects("artifact", assessment_id=work, run_order_id=crossed, digest="c" * 64, **doc)
    db.rejects("artifact", run_order_id=scanning, digest="e" * 64, **doc)  # imported: no order
    orders = db.t("ops.run_order")
    with pytest.raises(db.Error):  # a credited order keeps the work item it ran
        db.run(f"UPDATE {orders} SET work_item_id = ? WHERE id = ?", (other, fixing))
    db.run(f"UPDATE {orders} SET work_item_id = ? WHERE id = ?", (work, elsewhere))  # uncredited
    table = db.t("artifact")
    rows = db.run(f"SELECT digest FROM {table} WHERE run_order_id = ?", (fixing,))
    assert [r[0] for r in rows] == ["a" * 64]
    with pytest.raises(db.Error):  # append-only: the order a document names never changes
        db.run(f"UPDATE {table} SET run_order_id = NULL WHERE run_order_id = ?", (fixing,))


def _before_artifact_run_order(db: Db) -> Db:
    """The engine as it was before artifact.run_order_id: no column, index or guard. Postgres
    drops them; SQLite can't drop a column a foreign key uses, so it is rebuilt without."""
    if db.engine == "postgres":
        for statement in (
            "DROP TRIGGER artifact_order_owns_its_assessment ON traust.artifact",
            "DROP FUNCTION traust_ops.artifact_order_owns_its_assessment()",
            "DROP TRIGGER credited_order_keeps_its_work_item ON traust_ops.run_order",
            "DROP FUNCTION traust_ops.credited_order_keeps_its_work_item()",
            "DROP INDEX traust.idx_artifact_run_order",
            "ALTER TABLE traust.artifact DROP COLUMN run_order_id",
        ):
            db.run(statement)
        return db
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.create_function("uuid", 0, lambda: str(uuid.uuid4()))
    conn.isolation_level = None
    old = Db("sqlite", conn, sqlite3.Error)
    column = "    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,\n"
    for module in MODULES:
        for path in module.bootstrap_files("sqlite"):
            for statement in bootstrap_statements("sqlite", path):
                if any(
                    name in statement
                    for name in ("idx_artifact_run_order", "artifact_order_owns", "credited_order")
                ):
                    continue
                if "TABLE IF NOT EXISTS artifact (" in statement:
                    assert column in statement
                    statement = statement.replace(column, "")
                old.run(statement)
    return old


def test_artifact_run_order_upgrade_adds_the_link_without_inventing_one(db: Db) -> None:
    old = _before_artifact_run_order(db)
    rid = repo(old)
    work, other = assessment(old, ref(old, rid)), assessment(old, ref(old, rid, "dev"))
    doc = {"kind": "report", "uri": "file:///artifacts/a.json"}
    old.insert("artifact", assessment_id=work, digest="a" * 64, **doc)
    order = {"state": "queued", "priority": 1, "requested_by": "h", "repository_id": rid}
    fixing = old.insert("ops.run_order", asset="remediate_finding", work_item_id=work, **order)
    with pytest.raises(old.Error):  # no column yet
        old.insert("artifact", assessment_id=work, run_order_id=fixing, digest="b" * 64, **doc)
    for statement in storage_sql.artifact_run_order_upgrade(old.engine):
        old.run(statement)
    table = old.t("artifact")
    rows = old.run(f"SELECT digest, run_order_id FROM {table} WHERE assessment_id = ?", (work,))
    assert [(d, o) for d, o in rows] == [("a" * 64, None)]  # nothing inferred
    old.insert("artifact", assessment_id=work, run_order_id=fixing, digest="b" * 64, **doc)
    old.rejects("artifact", assessment_id=other, run_order_id=fixing, digest="c" * 64, **doc)
    for path in storage_sql.bootstrap_files(old.engine):  # bootstrap stays safe afterwards
        for statement in bootstrap_statements(old.engine, path):
            old.run(statement)
    assert len(old.run(f"SELECT id FROM {table} WHERE run_order_id = ?", (fixing,))) == 1


def _columns(db: Db, table: str) -> set[str]:
    if db.engine == "sqlite":
        return {c[1] for c in db.run(f"PRAGMA table_info({db.t(table)})")}
    query = "SELECT column_name FROM information_schema.columns WHERE table_name = ?"
    return {c[0] for c in db.run(query, (table,))}


def test_an_interrupted_sqlite_artifact_upgrade_rolls_back_whole() -> None:
    statements = storage_sql.artifact_run_order_upgrade("sqlite")
    assert statements[0].rstrip(";\n").endswith("BEGIN") and "COMMIT" in statements[-1]
    old = _before_artifact_run_order(_sqlite())
    work = assessment(old, ref(old, repo(old)))
    doc = {"kind": "report", "uri": "file:///artifacts/a.json"}
    upto = next(i for i, st in enumerate(statements) if "CREATE TRIGGER" in st)
    for statement in statements[: upto + 1]:  # stopped after the first guard
        old.run(statement)
    old.run("ROLLBACK")
    assert "run_order_id" not in _columns(old, "artifact")
    old.insert("artifact", assessment_id=work, digest="a" * 64, **doc)  # writes still work
    for statement in statements:  # and a retry completes
        old.run(statement)
    assert "run_order_id" in _columns(old, "artifact")
    old.insert("artifact", assessment_id=work, digest="b" * 64, **doc)


def test_the_artifact_upgrade_needs_contracts_117_and_changes_nothing_without_it(db: Db) -> None:
    old = _before_artifact_run_order(db)
    for statement in ROLLBACK[old.engine]:  # back to before contracts#117
        old.run(statement)
    with pytest.raises(old.Error):  # its prerequisite check fails first
        for statement in storage_sql.artifact_run_order_upgrade(old.engine):
            old.run(statement)
    if old.engine == "sqlite":
        old.run("ROLLBACK")
    assert "run_order_id" not in _columns(old, "artifact")


def test_run_order_fork_scheduled_upgrade_stamps_nothing_it_did_not_see(db: Db) -> None:
    rid = repo(db)
    work = assessment(db, ref(db, rid))
    table = db.t("ops.run_order")
    order = {"state": "queued", "priority": 1, "requested_by": "h", "repository_id": rid}
    fork = {
        "work_item_id": work,
        "fork_url": "https://github.com/mirror-org/r",
        "fork_branch": "fix/a",
    }
    stamped = db.insert(
        "ops.run_order", asset="remediate_finding", fork_scheduled_at=NOW, **fork, **order
    )
    assert db.run(f"SELECT fork_scheduled_at FROM {table} WHERE id = ?", (stamped,))[0][0]
    db.run(f"ALTER TABLE {table} DROP COLUMN fork_scheduled_at")  # the shape before
    legacy = db.insert("ops.run_order", asset="remediate_finding", **fork, **order)
    for statement in ops_sql.run_order_fork_scheduled_upgrade(db.engine):
        db.run(statement)
    assert db.run(f"SELECT fork_scheduled_at FROM {table} WHERE id = ?", (legacy,))[0][0] is None
    db.run(f"UPDATE {table} SET fork_scheduled_at = ? WHERE id = ?", (NOW, legacy))
    for path in ops_sql.bootstrap_files(db.engine):  # bootstrap stays safe afterwards
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
    assert db.run(f"SELECT fork_scheduled_at FROM {table} WHERE id = ?", (legacy,))[0][0]


def test_finding_identity_and_advisory_pairing(db: Db) -> None:
    rid = repo(db)
    finding(db, rid)
    db.rejects("finding", repository_id=rid, fingerprint_algo="v3", fingerprint="f" * 64, title="t")
    aid = db.insert("advisory", identifier="CVE-2026-0001")
    db.rejects(
        "finding",
        repository_id=rid,
        fingerprint_algo="v3",
        fingerprint="e" * 64,
        title="t",
        advisory_id=aid,  # without advisory_match
    )


def test_decision_has_one_who_one_commit_and_no_duplicates(db: Db) -> None:
    rid = repo(db)
    rref = ref(db, rid)
    aid, fid = assessment(db, rref), finding(db, rid)
    base = {"finding_id": fid, "occurred_at": NOW}
    db.insert("decision", assessment_id=aid, statement_key="k1", validity="confirmed", **base)
    db.rejects("decision", assessment_id=aid, statement_key="k1", **base)  # retry
    db.rejects("decision", statement_key="k2", **base)  # nobody decided
    db.rejects("decision", assessment_id=aid, actor="user:a", statement_key="k3", **base)
    db.rejects("decision", assessment_id=aid, repository_ref_id=rref, statement_key="k4", **base)
    db.insert("decision", actor="user:a", repository_ref_id=rref, statement_key="k5", **base)


def test_a_restatement_names_its_author_authority_reason_and_rationale(db: Db) -> None:
    rid = repo(db)
    rref = ref(db, rid)
    fid = finding(db, rid)
    base = {"finding_id": fid, "occurred_at": NOW, "repository_ref_id": rref}
    first = db.insert("decision", actor="human:a", statement_key="k1", validity="confirmed", **base)
    why = {"ticket": "T-1", "reason": "data_error", "rationale": "the audit misread the sink"}
    restated = {"restates_id": first, "actor": "human:b", "validity": "false_positive", **base}
    for missing in why:
        rest = {k: v for k, v in why.items() if k != missing}
        db.rejects("decision", statement_key=f"no-{missing}", **restated, **rest)
    second = db.insert("decision", statement_key="k2", **restated, **why)
    db.insert("decision_approver", decision_id=second, approver="human:c")
    db.rejects("decision_approver", decision_id=second, approver="human:c")
    db.rejects("decision_approver", decision_id=second, approver="")


def test_only_an_assessors_false_positive_is_auto_accepted(db: Db) -> None:
    rid = repo(db)
    rref = ref(db, rid)
    aid, fid = assessment(db, rref), finding(db, rid)
    base = {"finding_id": fid, "occurred_at": NOW, "auto_accept_tier": True}
    db.insert("decision", assessment_id=aid, statement_key="k1", validity="false_positive", **base)
    db.rejects("decision", assessment_id=aid, statement_key="k2", validity="confirmed", **base)
    db.rejects(
        "decision",
        actor="human:a",
        repository_ref_id=rref,
        statement_key="k3",
        validity="false_positive",
        **base,
    )


def test_default_reference_requires_a_named_branch_not_a_bare_commit(db: Db) -> None:
    rid = repo(db)
    db.insert("repository_ref", repository_id=rid, sha="a" * 40, is_default=False)
    db.insert(
        "repository_ref",
        repository_id=rid,
        name="main",
        kind="branch",
        sha="b" * 40,
        is_default=True,
    )
    db.rejects("repository_ref", repository_id=rid, sha="c" * 40, is_default=True)


def test_auto_accept_requires_nonnull_false_positive_validity(db: Db) -> None:
    rid = repo(db)
    rref = ref(db, rid)
    aid, fid = assessment(db, rref), finding(db, rid)
    base = {"finding_id": fid, "assessment_id": aid, "occurred_at": NOW, "validity": None}
    db.insert("decision", statement_key="no-answer", auto_accept_tier=False, **base)
    db.rejects("decision", statement_key="auto-no-answer", auto_accept_tier=True, **base)


def test_occurrence_and_location_rules(db: Db) -> None:
    rid = repo(db)
    aid, fid = assessment(db, ref(db, rid)), finding(db, rid)
    db.rejects("occurrence", finding_id=fid, assessment_id=aid, severity="high", cvss_score=11)
    oid = db.insert("occurrence", finding_id=fid, assessment_id=aid, severity="high")
    db.rejects("occurrence", finding_id=fid, assessment_id=aid, severity="high")
    db.insert("location", occurrence_id=oid, path="a.go", line_start=3, line_end=5)
    db.insert("location", occurrence_id=oid, path="a.go")
    db.rejects("location", occurrence_id=oid, path="a.go")  # whole file twice
    db.rejects("location", occurrence_id=oid, path="b.go", line_start=5, line_end=3)
    db.rejects("location", occurrence_id=oid, path="b.go", line_start=5)


def test_run_order_routing_and_lease_rules(db: Db) -> None:
    order = {
        "asset": "diff_scan",
        "lane": "diff-scan",
        "priority": 1,
        "requested_by": "skill:router",
    }
    db.insert("ops.run_order", state="queued", rule="r1", **order)
    db.rejects("ops.run_order", state="queued", rule="r1", event_source="cve", **order)
    db.rejects("ops.run_order", state="leased", **order)  # leased without a holder
    db.insert(
        "ops.run_order",
        state="leased",
        lease_holder="w1",
        lease_expires_at=LATER,
        **order,
    )
    db.rejects("ops.run_order", state="succeeded", started_at=LATER, finished_at=NOW, **order)


def test_run_order_names_its_asset_and_lane_only_when_routed(db: Db) -> None:
    order = {"state": "queued", "priority": 1, "requested_by": "service:engine"}
    db.insert("ops.run_order", asset="feeds_cache", **order)  # not routed: no lane
    db.rejects("ops.run_order", lane="diff-scan", **order)  # every order names its asset
    db.rejects("ops.run_order", asset="", **order)
    db.rejects("ops.run_order", asset="diff_scan", lane="", **order)


def test_a_run_order_names_a_real_work_item_or_none(db: Db) -> None:
    rid, elsewhere = repo(db), repo(db, "https://example.com/r2")
    at = ref(db, rid)
    item = assessment(db, at)
    order = {"asset": "remediate_finding", "state": "queued", "priority": 0, "requested_by": "h"}
    oid = db.insert(
        "ops.run_order",
        work_item_id=item,
        repository_id=rid,
        fork_url="https://example.com/mirrors/service",
        fork_branch="fix/xss-render",
        **order,
    )
    db.insert("ops.run_order", **order)  # an asset that runs no named item
    db.rejects("ops.run_order", work_item_id=str(uuid.uuid4()), repository_id=rid, **order)
    # the work item is one of the order's own repository
    db.rejects("ops.run_order", work_item_id=item, repository_id=elsewhere, **order)
    db.rejects("ops.run_order", work_item_id=item, **order)
    table = db.t("ops.run_order")
    row = db.run(f"SELECT work_item_id, fork_url, fork_branch FROM {table} WHERE id = ?", (oid,))[0]
    assert (str(row[0]), row[1], row[2]) == (
        item,
        "https://example.com/mirrors/service",
        "fix/xss-render",
    )
    with pytest.raises(db.Error):  # the work item an order runs can't be deleted from under it
        db.run(f"DELETE FROM {db.t('assessment')} WHERE id = ?", (item,))
    refs = db.t("repository_ref")
    with pytest.raises(db.Error):  # nor its commit move to another repository
        db.run(f"UPDATE {refs} SET repository_id = ? WHERE id = ?", (elsewhere, at))
    unordered = ref(db, rid, name="other")
    db.run(f"UPDATE {refs} SET repository_id = ? WHERE id = ?", (elsewhere, unordered))


def test_one_ledger_layer_per_repository_and_line(db: Db) -> None:
    r, other = repo(db), repo(db, "https://example.com/other")
    layer = {"merkle_signing_method": "keypair"}
    db.insert("ledger.layers", repository_id=r, **layer)
    db.rejects("ledger.layers", repository_id=r, **layer)  # a second repository layer
    db.insert("ledger.layers", repository_id=r, line="release-4.22", **layer)
    db.rejects("ledger.layers", repository_id=r, line="release-4.22", **layer)
    db.insert("ledger.layers", repository_id=r, line="release-4.23", **layer)
    db.insert("ledger.layers", repository_id=other, **layer)
    db.insert("ledger.layers", repository_id=other, line="release-4.22", **layer)


def test_spend_is_never_negative(db: Db) -> None:
    db.rejects(
        "ops.spend_event",
        provider="p",
        model="m",
        tokens_in=-1,
        tokens_out=0,
        cost_usd=0,
        occurred_at=NOW,
    )


def test_spend_carries_its_orders_lane(db: Db) -> None:
    order = {"state": "queued", "priority": 1, "requested_by": "service:engine"}
    routed = db.insert("ops.run_order", asset="diff_scan", lane="diff-scan", **order)
    unrouted = db.insert("ops.run_order", asset="feeds_cache", **order)
    spend = {"provider": "p", "model": "m", "tokens_in": 1, "tokens_out": 1, "cost_usd": 0.1}
    db.insert("ops.spend_event", run_order_id=routed, lane="diff-scan", occurred_at=NOW, **spend)
    db.insert("ops.spend_event", run_order_id=unrouted, occurred_at=NOW, **spend)
    db.insert("ops.spend_event", occurred_at=NOW, **spend)  # unattributed: no lane
    db.rejects("ops.spend_event", run_order_id=routed, occurred_at=NOW, **spend)
    db.rejects("ops.spend_event", run_order_id=routed, lane="full-audit", occurred_at=NOW, **spend)
    db.rejects("ops.spend_event", run_order_id=unrouted, lane="diff-scan", occurred_at=NOW, **spend)
    db.rejects("ops.spend_event", lane="diff-scan", occurred_at=NOW, **spend)
    db.rejects("ops.spend_event", run_order_id=routed, lane="", occurred_at=NOW, **spend)


def test_a_layer_frontier_is_absent_or_real(db: Db) -> None:
    rid = repo(db)
    base = {"repository_id": rid, "merkle_signing_method": "keypair"}
    db.insert("ledger.layers", merkle_frontier="ab" * 32 + "," + "cd" * 32, **base)
    db.insert("ledger.layers", line="dev", **base)
    db.rejects("ledger.layers", line="other", merkle_frontier="", **base)


def test_component_paging_survives_bootstrap_reapplication(db: Db) -> None:
    product = db.insert("product", slug="components", name="Components")
    release = db.insert("release", product_id=product, version="1")
    repository = repo(db)
    refs = [ref(db, repository, sha=digit * 40) for digit in "abc"]
    table = db.t("component")
    db.run(
        f"INSERT INTO {table} (release_id, repository_ref_id) VALUES (?, ?), (?, ?), (?, ?)",
        tuple(value for rid in refs for value in (release, rid)),
    )
    for path in storage_sql.bootstrap_files(db.engine):
        if path.stem == "component":
            for statement in bootstrap_statements(db.engine, path):
                db.run(statement)
    rows = db.run(f"SELECT created_at, id FROM {table} ORDER BY created_at DESC, id DESC")
    assert len(rows) == 3 and len({row[0] for row in rows}) == 1
    query = (
        f"SELECT created_at, id FROM {table} WHERE (created_at, id) < (?, ?) "
        "ORDER BY created_at DESC, id DESC LIMIT 2"
    )
    assert db.run(query, rows[0]) == rows[1:]
    if db.engine == "sqlite":
        plan = db.run("EXPLAIN QUERY PLAN " + query, rows[0])
        assert any("SEARCH" in row[-1] for row in plan), plan
        assert not any("TEMP B-TREE" in row[-1] for row in plan), plan


def hash_location(db: Db) -> str:
    rid = repo(db)
    oid = db.insert(
        "occurrence",
        finding_id=finding(db, rid),
        assessment_id=assessment(db, ref(db, rid)),
        severity="high",
    )
    return db.insert("location", occurrence_id=oid, path="handler.go", symbol="api.Handle")


def test_location_hash_is_one_claim_per_location_and_scheme(db: Db) -> None:
    location = hash_location(db)
    claim = {"location_id": location, "algorithm": "file-bytes-sha256/v1", "digest": "a" * 64}
    saved = db.insert("location_hash", **claim)
    uuid.UUID(saved)
    assert (
        db.run(f"SELECT created_at FROM {db.t('location_hash')} WHERE id = ?", (saved,))[0][0]
        is not None
    )
    db.rejects("location_hash", **claim)
    db.insert("location_hash", **{**claim, "algorithm": "function-bytes-sha256/v1"})
    db.rejects("location_hash", **{**claim, "location_id": str(uuid.uuid4())})


@pytest.mark.parametrize(
    "digest", ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\x00suffix", b"g" * 64]
)
def test_file_sha256_claim_requires_a_canonical_digest(db: Db, digest: str | bytes) -> None:
    db.rejects(
        "location_hash",
        location_id=hash_location(db),
        algorithm="file-bytes-sha256/v1",
        digest=digest,
    )


def test_location_hash_history_survives_reapplication_and_rejects_mutation(db: Db) -> None:
    location = hash_location(db)
    claim = db.insert(
        "location_hash", location_id=location, algorithm="file-bytes-sha256/v1", digest="a" * 64
    )
    before = db.run(f"SELECT * FROM {db.t('location_hash')}")
    for _ in range(2):
        for path in storage_sql.bootstrap_files(db.engine):
            if path.stem in {"location", "location_hash"}:
                for statement in bootstrap_statements(db.engine, path):
                    db.run(statement)
    assert db.run(f"SELECT * FROM {db.t('location_hash')}") == before
    for sql in (
        f"UPDATE {db.t('location_hash')} SET digest = digest WHERE id = ?",
        f"DELETE FROM {db.t('location_hash')} WHERE id = ?",
    ):
        with pytest.raises(db.Error):
            db.run(sql, (claim,))
    if db.engine == "postgres":
        with pytest.raises(db.Error):
            db.run(f"TRUNCATE {db.t('location_hash')}")


def test_existing_locations_gain_no_claims_when_hash_storage_is_installed(db: Db) -> None:
    location = hash_location(db)
    db.run(f"DROP TABLE {db.t('location_hash')}")
    for path in storage_sql.bootstrap_files(db.engine):
        if path.stem in {"location", "location_hash"}:
            for statement in bootstrap_statements(db.engine, path):
                db.run(statement)
    assert db.run(f"SELECT id FROM {db.t('location')} WHERE id = ?", (location,))
    assert db.run(f"SELECT * FROM {db.t('location_hash')}") == []


@pytest.mark.parametrize("collision", ["primary", "natural"])
def test_location_hash_cannot_be_replaced(db: Db, collision: str) -> None:
    location = hash_location(db)
    claim = db.insert(
        "location_hash", location_id=location, algorithm="file-bytes-sha256/v1", digest="a" * 64
    )
    before = db.run(f"SELECT * FROM {db.t('location_hash')}")
    algorithm = "function-bytes-sha256/v1" if collision == "primary" else "file-bytes-sha256/v1"
    identity = claim if collision == "primary" else str(uuid.uuid4())
    insert = "INSERT OR REPLACE" if db.engine == "sqlite" else "INSERT"
    sql = (
        f"{insert} INTO {db.t('location_hash')} "
        "(id, location_id, algorithm, digest) VALUES (?, ?, ?, ?)"
    )
    if db.engine == "postgres":
        key = "id" if collision == "primary" else "location_id, algorithm"
        sql += f" ON CONFLICT ({key}) DO UPDATE SET digest = EXCLUDED.digest"
    with pytest.raises(db.Error):
        db.run(sql, (identity, location, algorithm, "b" * 64))
    assert db.run(f"SELECT * FROM {db.t('location_hash')}") == before


RETIRED_VIEWS = (
    "decision_at",
    "current_decision",
    "current_resolution",
    "finding_status",
    "finding_clock",
)


def test_bootstrap_drops_the_retired_views_from_an_existing_database(db: Db) -> None:
    for name in RETIRED_VIEWS:
        db.run(f"CREATE VIEW {db.t(name)} AS SELECT id AS finding_id FROM {db.t('finding')}")
    (retired,) = [p for p in storage_sql.bootstrap_files(db.engine) if p.name == "retired.sql"]
    for _ in range(2):  # idempotent: a fresh database runs it too
        for statement in bootstrap_statements(db.engine, retired):
            db.run(statement)
    for name in RETIRED_VIEWS:
        with pytest.raises(db.Error):
            db.run(f"SELECT * FROM {db.t(name)}")
        if db.engine == "postgres":
            db.run("ROLLBACK")


def _interleave(
    dsn: str, first: str, first_params: tuple, second: str, second_params: tuple
) -> Any:
    """`first` in an open transaction, `second` on another connection while it is open, then
    `first` commits: the error `second` ends with, or None (Postgres; SQLite has one writer)."""
    import threading

    import psycopg

    holder = psycopg.connect(dsn)
    holder.execute(first, first_params)
    outcome: list[Any] = []

    def run() -> None:
        with psycopg.connect(dsn, autocommit=True) as other:
            other.execute("SET statement_timeout = '10s'")
            try:
                other.execute(second, second_params)
                outcome.append(None)
            except psycopg.Error as error:
                outcome.append(error)

    waiter = threading.Thread(target=run)
    waiter.start()
    time.sleep(0.3)
    blocked = waiter.is_alive()
    holder.commit()
    holder.close()
    waiter.join()
    assert blocked, "the second statement must wait for the first transaction"
    return outcome[0]


def test_a_concurrent_ref_move_and_order_never_both_commit(
    db: Db, request: pytest.FixtureRequest
) -> None:
    if db.engine != "postgres":
        pytest.skip("SQLite serializes writers")
    dsn = request.getfixturevalue("postgres_dsn")
    rid, elsewhere = repo(db), repo(db, "https://example.com/r2")
    move = "UPDATE traust.repository_ref SET repository_id = %s WHERE id = %s"
    order = (
        "INSERT INTO traust_ops.run_order (asset, state, priority, requested_by, repository_id, "
        "work_item_id) VALUES ('remediate_finding', 'queued', 0, 'h', %s, %s)"
    )
    at = ref(db, rid, name="ordered-first")
    error = _interleave(dsn, order, (rid, assessment(db, at)), move, (elsewhere, at))
    assert error is not None  # the move waited for the order, then saw it
    at = ref(db, rid, name="moved-first")
    item = assessment(db, at)
    error = _interleave(dsn, move, (elsewhere, at), order, (rid, item))
    assert error is not None  # the order waited for the move, then saw where it went
    rows = db.run(
        "SELECT count(*) FROM traust_ops.run_order o JOIN traust.assessment a "
        "ON a.id = o.work_item_id JOIN traust.repository_ref r ON r.id = a.repository_ref_id "
        "WHERE r.repository_id IS DISTINCT FROM o.repository_id"
    )
    assert rows == [(0,)]


ROLLBACK = {
    "postgres": (
        # contracts#128's guards read run_order.work_item_id: they go first
        "DROP TRIGGER IF EXISTS artifact_order_owns_its_assessment ON traust.artifact",
        "DROP FUNCTION IF EXISTS traust_ops.artifact_order_owns_its_assessment()",
        "DROP TRIGGER IF EXISTS credited_order_keeps_its_work_item ON traust_ops.run_order",
        "DROP FUNCTION IF EXISTS traust_ops.credited_order_keeps_its_work_item()",
        "DROP TRIGGER IF EXISTS ref_of_ordered_work_item_stays ON traust.repository_ref",
        "DROP FUNCTION IF EXISTS traust_ops.ref_of_ordered_work_item_stays()",
        "DROP TRIGGER IF EXISTS run_order_work_item_of_repository ON traust_ops.run_order",
        "DROP FUNCTION IF EXISTS traust_ops.run_order_work_item_of_repository()",
        "DROP INDEX IF EXISTS traust_ops.idx_ops_run_order_work_item",
        "ALTER TABLE traust_ops.run_order DROP COLUMN fork_branch",
        "ALTER TABLE traust_ops.run_order DROP COLUMN fork_url",
        "ALTER TABLE traust_ops.run_order DROP COLUMN work_item_id",
        "DROP INDEX IF EXISTS traust.idx_decision_assessment",
    ),
    "sqlite": (
        "DROP TRIGGER IF EXISTS ops_artifact_order_owns_its_assessment",
        "DROP TRIGGER IF EXISTS ops_credited_order_keeps_its_work_item",
        "DROP TRIGGER IF EXISTS ops_ref_of_ordered_work_item_stays",
        "DROP TRIGGER IF EXISTS ops_run_order_work_item_of_repository",
        "DROP TRIGGER IF EXISTS ops_run_order_work_item_of_repository_update",
        "DROP INDEX IF EXISTS idx_ops_run_order_work_item",
        "ALTER TABLE ops_run_order DROP COLUMN fork_branch",
        "ALTER TABLE ops_run_order DROP COLUMN fork_url",
        "ALTER TABLE ops_run_order DROP COLUMN work_item_id",
        "DROP INDEX IF EXISTS idx_decision_assessment",
    ),
}


def test_the_documented_rollback_leaves_findings_refs_and_orders_working(db: Db) -> None:
    for statement in ROLLBACK[db.engine]:  # the PR's manual rollback, verbatim
        db.run(statement)
    rid, elsewhere = repo(db), repo(db, "https://example.com/r2")
    fid, at = finding(db, rid), ref(db, rid)
    db.run(f"UPDATE {db.t('finding')} SET repository_id = ? WHERE id = ?", (elsewhere, fid))
    db.run(f"UPDATE {db.t('repository_ref')} SET repository_id = ? WHERE id = ?", (elsewhere, at))
    order = {"asset": "diff_scan", "state": "queued", "priority": 1, "requested_by": "h"}
    db.insert("ops.run_order", repository_id=elsewhere, **order)


def test_algorithm_free_fingerprint_upgrade_preserves_rows_and_recipe_ambiguity(db: Db) -> None:
    repository = repo(db)
    first = finding(db, repository, "opaque identity")
    second = db.insert(
        "finding",
        repository_id=repository,
        fingerprint_algo="other",
        fingerprint="opaque identity",
        title="Another recipe",
    )
    table = db.t("finding")
    query = f"SELECT * FROM {table} ORDER BY id"
    before = db.run(query)
    db.run(f"DROP INDEX {db.t('idx_finding_repository_fingerprint')}")
    for _ in range(2):
        for statement in storage_sql.finding_fingerprint_index_upgrade(db.engine):
            db.run(statement)
    assert db.run(query) == before
    matches = db.run(
        f"SELECT id FROM {table} WHERE repository_id = ? AND fingerprint = ? LIMIT 2",
        (repository, "opaque identity"),
    )
    assert {str(row[0]) for row in matches} == {first, second}
    assert (
        db.run(
            f"SELECT id FROM {table} WHERE repository_id = ? AND fingerprint = ? LIMIT 2",
            (repository, "missing"),
        )
        == []
    )


def test_external_reference_attempt_upgrade_leaves_historical_links_unattributed(db: Db) -> None:
    repository = repo(db)
    found = finding(db, repository)
    old = db.insert("finding_external_ref", finding_id=found, system="jira", ref="SEC-1")
    table = db.t("finding_external_ref")
    db.run(f"DROP INDEX {db.t('idx_finding_external_ref_assessment')}")
    db.run(f"ALTER TABLE {table} DROP COLUMN assessment_id")
    for statement in storage_sql.finding_external_ref_assessment_upgrade(db.engine):
        db.run(statement)
    assert db.run(f"SELECT assessment_id FROM {table} WHERE id = ?", (old,)) == [(None,)]
    first = assessment(db, ref(db, repository))
    second = assessment(db, ref(db, repository, sha="b" * 40))
    attached = db.insert(
        "finding_external_ref",
        finding_id=found,
        assessment_id=first,
        system="github",
        ref="https://github.com/example/service/pull/1",
    )
    assert [
        str(row[0]) for row in db.run(f"SELECT id FROM {table} WHERE assessment_id = ?", (first,))
    ] == [attached]
    assert db.run(f"SELECT id FROM {table} WHERE assessment_id = ?", (second,)) == []
    db.rejects(
        "finding_external_ref",
        finding_id=found,
        assessment_id=str(uuid.uuid4()),
        system="github",
        ref="https://github.com/example/service/pull/2",
    )


def _event(db: Db, **metadata: object) -> str:
    return db.insert(
        "ops.spend_event",
        provider="provider",
        model="model",
        tokens_in=11,
        tokens_out=7,
        cost_usd=0.125,
        occurred_at=NOW,
        **metadata,
    )


def _metadata(db: Db, event_id: str) -> tuple:
    rows = db.run(
        f"SELECT repository_id, repository_label, loc, batch, note "
        f"FROM {db.t('ops.spend_event')} WHERE id = ?",
        (event_id,),
    )
    canonical, label, loc, batch, note = rows[0]
    return (str(canonical) if canonical is not None else None, label, loc, batch, note)


def test_spend_metadata_roundtrips_with_canonical_repository(db: Db) -> None:
    canonical = repo(db)
    supplied = (canonical, "../adopter/raw-reference", 1234, "batch-42", "cost note\nverbatim")
    event = _event(
        db,
        **dict(
            zip(
                ("repository_id", "repository_label", "loc", "batch", "note"), supplied, strict=True
            )
        ),
    )
    assert _metadata(db, event) == supplied
    rows = db.run(
        f"SELECT tokens_in, tokens_out, cost_usd FROM {db.t('ops.spend_event')} WHERE id = ?",
        (event,),
    )
    assert rows[0] == (11, 7, 0.125)


def test_legacy_spend_keeps_new_metadata_null(db: Db) -> None:
    assert _metadata(db, _event(db)) == (None, None, None, None, None)


def test_ambiguous_spend_label_retains_cost_without_guessing_identity(db: Db) -> None:
    first = repo(db, "https://example.com/team-a/shared")
    second = repo(db, "https://example.com/team-b/shared")
    for canonical in (None, first, second):
        event = _event(
            db, repository_id=canonical, repository_label="shared", loc=0, batch="", note=""
        )
        assert _metadata(db, event) == (canonical, "shared", 0, "", "")
    rows = db.run(
        f"SELECT count(*), sum(cost_usd) FROM {db.t('ops.spend_event')} WHERE repository_label = ?",
        ("shared",),
    )
    assert rows[0] == (3, 0.375)


def test_spend_rejects_unknown_canonical_repository(db: Db) -> None:
    with pytest.raises(db.Error):
        _event(db, repository_id=str(uuid.uuid4()), repository_label="still-raw")


@pytest.mark.parametrize("loc", [-1, "not-an-integer", "1.5", b"invalid"])
def test_spend_rejects_invalid_loc(db: Db, loc: object) -> None:
    with pytest.raises(db.Error):
        _event(db, loc=loc)


def test_rich_spend_remains_append_only_and_retains_repository(db: Db) -> None:
    canonical = repo(db)
    event = _event(db, repository_id=canonical, repository_label="raw", loc=12)
    table = db.t("ops.spend_event")
    for statement in (
        f"UPDATE {table} SET note = 'changed' WHERE id = ?",
        f"DELETE FROM {table} WHERE id = ?",
    ):
        with pytest.raises(db.Error):
            db.run(statement, (event,))
    with pytest.raises(db.Error):
        db.run(f"DELETE FROM {db.t('repository')} WHERE id = ?", (canonical,))
    assert _metadata(db, event) == (canonical, "raw", 12, None, None)


def test_rich_spend_preserves_lane_order_guard(db: Db) -> None:
    canonical = repo(db)
    order = db.insert(
        "ops.run_order",
        asset="diff_scan",
        state="queued",
        priority=1,
        requested_by="human",
        repository_id=canonical,
        lane="interactive",
    )
    event = _event(
        db, run_order_id=order, lane="interactive", repository_id=canonical, note="retained"
    )
    assert _metadata(db, event)[-1] == "retained"
    with pytest.raises(db.Error):
        _event(db, run_order_id=order, lane="other", repository_id=canonical)
    with pytest.raises(db.Error):
        _event(db, lane="interactive", repository_label="unattributed")


def _before_spend_metadata(db: Db) -> None:
    prefix = "traust_ops." if db.engine == "postgres" else ""
    db.run(f"DROP INDEX {prefix}idx_ops_spend_event_repository_occurred")
    for column in ("repository_id", "repository_label", "loc", "batch", "note"):
        db.run(f"ALTER TABLE {db.t('ops.spend_event')} DROP COLUMN {column}")


def test_spend_metadata_upgrade_preserves_history_and_accepts_rich_events(db: Db) -> None:
    _before_spend_metadata(db)
    canonical = repo(db)
    old_event = _event(db)
    table = db.t("ops.spend_event")
    old_history = db.run(
        f"SELECT id, tokens_in, tokens_out, cost_usd, occurred_at, created_at FROM {table}"
    )
    if db.engine == "postgres":
        db.run("BEGIN")
    for statement in ops_sql.spend_event_metadata_upgrade(db.engine):
        db.run(statement)
    if db.engine == "postgres":
        db.run("COMMIT")
    assert (
        db.run(f"SELECT id, tokens_in, tokens_out, cost_usd, occurred_at, created_at FROM {table}")
        == old_history
    )
    assert _metadata(db, old_event) == (None, None, None, None, None)
    event = _event(
        db, repository_id=canonical, repository_label="raw", loc=42, batch="batch", note="note"
    )
    assert _metadata(db, event) == (canonical, "raw", 42, "batch", "note")
    assert _metadata(db, _event(db, repository_label="ambiguous")) == (
        None,
        "ambiguous",
        None,
        None,
        None,
    )
    with pytest.raises(db.Error):
        _event(db, repository_id=str(uuid.uuid4()))
    for loc in (-1, "bad", "1.5"):
        with pytest.raises(db.Error):
            _event(db, loc=loc)
    with pytest.raises(db.Error):
        db.run(f"UPDATE {table} SET note = 'changed' WHERE id = ?", (old_event,))
    with pytest.raises(db.Error):
        db.run(f"DELETE FROM {table} WHERE id = ?", (event,))
    with pytest.raises(db.Error):
        _event(db, lane="interactive")
    for path in ops_sql.bootstrap_files(db.engine):
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
    assert _metadata(db, old_event) == (None, None, None, None, None)


def _before_revision(db: Db) -> None:
    prefix = "traust." if db.engine == "postgres" else ""
    db.run(f"DROP INDEX {prefix}idx_artifact_imported_kind")
    db.run(f"ALTER TABLE {db.t('artifact')} DROP COLUMN publication_revision")
    db.run(
        f"CREATE INDEX idx_artifact_imported_kind ON {db.t('artifact')} "
        "(kind, created_at DESC, id DESC) WHERE assessment_id IS NULL"
    )


def _upgrade(db: Db) -> None:
    for statement in storage_sql.artifact_publication_revision_upgrade(db.engine):
        db.run(statement)


def test_imported_revisions_are_positive_unique_per_stream_and_not_assessment_metadata(
    db: Db,
) -> None:
    document = {"kind": "corpus-registry", "uri": "artifacts/example.json"}
    db.insert("artifact", digest="first", publication_revision=1, **document)
    db.rejects("artifact", digest="second", publication_revision=1, **document)
    for revision in (0, -1):
        db.rejects(
            "artifact", digest=f"invalid-{revision}", publication_revision=revision, **document
        )
    db.insert(
        "artifact", digest="other-stream", kind="policy", uri="policy.json", publication_revision=1
    )
    work = assessment(db, ref(db, repo(db)))
    db.rejects(
        "artifact", assessment_id=work, digest="produced", publication_revision=2, **document
    )
    db.insert("artifact", assessment_id=work, digest="produced", **document)
    db.insert("artifact", digest="raw-import", **document)


def test_revision_upgrade_preserves_every_original_row_and_orders_unambiguous_history(
    db: Db,
) -> None:
    _before_revision(db)
    work = assessment(db, ref(db, repo(db)))
    document = {"kind": "corpus-registry", "uri": "artifacts/example.json"}
    db.insert("artifact", digest="second", created_at=LATER, **document)
    db.insert("artifact", digest="first", created_at=NOW, **document)
    db.insert("artifact", digest="other-stream", kind="policy", uri="policy.json", created_at=NOW)
    db.insert("artifact", assessment_id=work, digest="produced", created_at=NOW, **document)
    table = db.t("artifact")
    original = db.run(
        f"SELECT id, assessment_id, digest, kind, uri, created_at FROM {table} ORDER BY digest"
    )
    _upgrade(db)
    assert (
        db.run(
            f"SELECT id, assessment_id, digest, kind, uri, created_at FROM {table} ORDER BY digest"
        )
        == original
    )
    assert db.run(f"SELECT digest, publication_revision FROM {table} ORDER BY digest") == [
        ("first", 1),
        ("other-stream", 1),
        ("produced", None),
        ("second", 2),
    ]
    db.insert("artifact", digest="third", publication_revision=3, **document)
    db.rejects("artifact", digest="duplicate-revision", publication_revision=3, **document)
    with pytest.raises(db.Error):
        db.run(f"UPDATE {table} SET publication_revision = 4 WHERE digest = 'third'")
    with pytest.raises(db.Error):
        db.run(f"DELETE FROM {table} WHERE digest = 'third'")
    for path in storage_sql.bootstrap_files(db.engine):
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
    assert len(db.run(f"SELECT id FROM {table}")) == 5


def test_revision_upgrade_refuses_ambiguous_real_database_timestamps_without_mutation(
    db: Db,
) -> None:
    _before_revision(db)
    table = db.t("artifact")
    db.run(
        f"INSERT INTO {table} (digest, kind, uri) VALUES "
        "('first', 'corpus-registry', 'first.json'), "
        "('second', 'corpus-registry', 'second.json')"
    )
    before = db.run(f"SELECT * FROM {table} ORDER BY digest")
    assert len({row[-1] for row in before}) == 1
    with pytest.raises(db.Error):
        _upgrade(db)
    if db.engine == "sqlite":
        db.run("ROLLBACK")
    assert "publication_revision" not in _columns(db, "artifact")
    assert db.run(f"SELECT * FROM {table} ORDER BY digest") == before
    with pytest.raises(db.Error):
        db.run(f"UPDATE {table} SET uri = 'changed.json'")


def test_interrupted_revision_upgrade_rolls_back_the_column_rows_and_append_only_guard(
    db: Db,
) -> None:
    _before_revision(db)
    db.insert("artifact", digest="first", kind="corpus-registry", uri="first.json")
    before = db.run(f"SELECT * FROM {db.t('artifact')}")
    statements = storage_sql.artifact_publication_revision_upgrade(db.engine)
    if db.engine == "sqlite":
        stop = next(
            index for index, statement in enumerate(statements) if "UPDATE artifact" in statement
        )
        for statement in statements[: stop + 1]:
            db.run(statement)
    else:
        db.run("BEGIN")
        _upgrade(db)
    db.run("ROLLBACK")
    assert "publication_revision" not in _columns(db, "artifact")
    assert db.run(f"SELECT * FROM {db.t('artifact')}") == before
    with pytest.raises(db.Error):
        db.run(f"UPDATE {db.t('artifact')} SET uri = 'changed.json'")
    _upgrade(db)
    assert db.run(f"SELECT publication_revision FROM {db.t('artifact')}") == [(1,)]


def test_revision_upgrade_accepts_historical_stores_without_the_old_read_index(db: Db) -> None:
    _before_revision(db)
    prefix = "traust." if db.engine == "postgres" else ""
    db.run(f"DROP INDEX {prefix}idx_artifact_imported_kind")
    original = db.insert("artifact", digest="old", kind="corpus-registry", uri="old.json")
    _upgrade(db)
    assert db.run(f"SELECT id, publication_revision FROM {db.t('artifact')}") == [
        (original if db.engine == "sqlite" else uuid.UUID(original), 1)
    ]
    with pytest.raises(db.Error):
        db.run(f"UPDATE {db.t('artifact')} SET uri = 'rewritten.json'")
