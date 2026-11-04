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
