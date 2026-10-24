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
        if self.engine == "postgres":
            sql = sql.replace("?", "%s")
        cur = self.conn.execute(sql, params)
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


def decision_status(db: Db, finding_id: str) -> tuple[str | None, bool]:
    validity, is_open = db.run(
        f"SELECT validity, is_open FROM {db.t('finding_status')} WHERE finding_id = ?",
        (finding_id,),
    )[0]
    return validity, bool(is_open)


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


@pytest.mark.parametrize("proof_validity", ["confirmed", "true_positive", "hardening"])
def test_execution_proof_needs_two_distinct_later_humans(db: Db, proof_validity: str) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, actor="service:executor", validity=proof_validity, evidence_grade="E0")
    assert decision_status(db, fid) == ("confirmed", True)
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)  # not an independent signature
    decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == ("false_positive", False)

    # A new execution proof resets the concurrence interval, not just its author.
    decision(db, fid, validity="confirmed", evidence_grade="E0", occurred_at="2026-10-22T12:00:00Z")
    assert decision_status(db, fid) == ("confirmed", True)
    for actor, expected in (
        ("human:a", ("confirmed", True)),
        ("human:b", ("false_positive", False)),
    ):
        decision(
            db,
            fid,
            actor=actor,
            validity="false_positive",
            evidence_grade="E0",
            occurred_at="2026-10-23T12:00:00Z",
        )
        assert decision_status(db, fid) == expected


@pytest.mark.parametrize(
    ("grade", "at"),
    [
        ("E0", "2026-10-19T12:00:00Z"),
        ("E0", NOW),  # strictly after, even when created later
        ("E1", LATER),
        ("E2", LATER),
        ("E3", LATER),
        (None, LATER),
        ("unknown", LATER),
    ],
)
def test_old_or_weaker_second_signature_cannot_close(db: Db, grade: str | None, at: str) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", evidence_grade="E0")
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade=grade, occurred_at=at
    )
    assert decision_status(db, fid) == ("confirmed", True)
    decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == ("false_positive", False)


@pytest.mark.parametrize(
    ("actor", "eligible"),
    [
        ("human:a", True),
        ("Human:a", False),
        ("HUMAN:a", False),
        ("user:a", False),
        ("service:human:a", False),
        ("humanish:a", False),
    ],
)
def test_fp_human_prefix_is_exact_and_case_sensitive(db: Db, actor: str, eligible: bool) -> None:
    fid = finding(db, repo(db))
    decision(
        db,
        fid,
        actor=actor,
        validity="false_positive",
        evidence_grade="E0",
        source_channel="human",
    )
    assert decision_status(db, fid) == (("false_positive", False) if eligible else (None, True))
    decision(db, fid, validity="confirmed", evidence_grade="E0", occurred_at=NOW)
    decision(
        db, fid, actor=actor, validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == (
        ("false_positive", False) if eligible else ("confirmed", True)
    )


@pytest.mark.parametrize("auto_accept", [False, True])
def test_machine_fp_eligibility_never_supplies_execution_signoff(db: Db, auto_accept: bool) -> None:
    rid = repo(db)
    fid, aid = finding(db, rid), assessment(db, ref(db, rid))
    decision(
        db,
        fid,
        actor=None,
        assessment_id=aid,
        validity="false_positive",
        evidence_grade="E0",
        auto_accept_tier=auto_accept,
        occurred_at=LATER,
    )
    assert decision_status(db, fid) == (("false_positive", False) if auto_accept else (None, True))
    decision(db, fid, validity="confirmed", evidence_grade="E0")
    assert decision_status(db, fid) == ("confirmed", True)
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)
    decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == ("false_positive", False)


@pytest.mark.parametrize(
    ("proof_grade", "fp_grade", "expected"),
    [
        ("E1", "E0", "false_positive"),
        ("E1", "E1", "false_positive"),
        ("E1", "E2", "confirmed"),
        ("E2", "E3", "confirmed"),
        ("E3", None, "confirmed"),
        ("E3", "E00", "confirmed"),
        (None, "E3", "false_positive"),
        ("unknown", None, "false_positive"),
    ],
)
def test_validity_uses_only_explicit_strength(
    db: Db, proof_grade: str | None, fp_grade: str | None, expected: str
) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, actor="service:executor", validity="confirmed", evidence_grade=proof_grade)
    decision(
        db,
        fid,
        actor="human:verified-admin",
        validity="false_positive",
        evidence_grade=fp_grade,
        source_channel="execution",
        occurred_at=LATER,
    )
    assert decision_status(db, fid) == (expected, expected != "false_positive")


def test_strongest_latest_non_fp_answer_controls_execution_guard(db: Db) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", evidence_grade="E0")
    decision(db, fid, validity="not_affected", evidence_grade="E1", occurred_at=LATER)
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)
    decision(
        db, fid, validity="not_affected", evidence_grade="E0", occurred_at="2026-10-22T12:00:00Z"
    )
    assert decision_status(db, fid) == ("not_affected", False)


@pytest.mark.parametrize("no_answer", [None, "not_verified", "corrected", "unknown"])
def test_absent_and_unrecognized_validity_do_not_replace_an_answer(
    db: Db, no_answer: str | None
) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", evidence_grade="E1")
    decision(db, fid, validity=no_answer, evidence_grade="E0", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)


def test_restated_execution_proof_is_not_active(db: Db) -> None:
    fid = finding(db, repo(db))
    proof = decision(db, fid, validity="true_positive", evidence_grade="E0")
    decision(db, fid, validity="false_positive", evidence_grade="E1", occurred_at=LATER)
    assert decision_status(db, fid) == ("confirmed", True)
    correction = decision(
        db,
        fid,
        restates_id=proof,
        validity="not_verified",
        reason="data_error",
        ticket="T-1",
        rationale="execution evidence was attached to the wrong finding",
        occurred_at=LATER,
    )
    assert decision_status(db, fid) == ("false_positive", False)
    decision(
        db,
        fid,
        restates_id=correction,
        validity="corrected",
        reason="data_error",
        ticket="T-2",
        rationale="correction wording clarified, original proof remains withdrawn",
        occurred_at=LATER,
    )
    assert decision_status(db, fid) == ("false_positive", False)


def test_restated_human_signature_no_longer_counts(db: Db) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", evidence_grade="E0")
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    second = decision(
        db, fid, actor="human:b", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == ("false_positive", False)
    decision(
        db,
        fid,
        actor="human:admin",
        restates_id=second,
        validity="not_verified",
        reason="data_error",
        ticket="T-1",
        rationale="second reviewer withdrew the mistaken signature",
        occurred_at=LATER,
    )
    assert decision_status(db, fid) == ("confirmed", True)
    decision(
        db, fid, actor="human:c", validity="false_positive", evidence_grade="E0", occurred_at=LATER
    )
    assert decision_status(db, fid) == ("false_positive", False)


def test_restatement_exclusion_is_scoped_to_its_finding(db: Db) -> None:
    rid = repo(db)
    fid, other = finding(db, rid), finding(db, rid, "e" * 64)
    proof = decision(db, fid, validity="confirmed", evidence_grade="E0", severity="high")
    # Historical malformed cross-finding references do not withdraw a proof.
    decision(
        db,
        other,
        restates_id=proof,
        validity="not_verified",
        reason="data_error",
        ticket="T-1",
        rationale="historical cross-finding reference is not this finding's correction",
    )
    assert db.run(
        f"SELECT validity, severity, evidence_grade FROM {db.t('current_decision')} "
        "WHERE finding_id = ?",
        (fid,),
    ) == [("confirmed", "high", "E0")]


def test_current_fields_are_active_recognized_and_strength_ranked(db: Db) -> None:
    fid = finding(db, repo(db))
    proof = decision(db, fid, validity="confirmed", evidence_grade="E1", severity="high")
    decision(db, fid, evidence_grade="E2", severity="low", occurred_at=LATER)
    invalid = decision(db, fid, evidence_grade="E0", severity="urgent", occurred_at=LATER)
    query = (
        f"SELECT validity, severity, evidence_grade FROM {db.t('current_decision')} "
        "WHERE finding_id = ?"
    )
    assert db.run(query, (fid,)) == [("confirmed", "high", "E0")]
    for target in (invalid, proof):
        decision(
            db,
            fid,
            restates_id=target,
            validity="not_verified",
            reason="data_error",
            ticket="T-1",
            rationale="the original statement's fields were erroneous",
            occurred_at=LATER,
        )
        expected = ("confirmed", "high", "E1") if target == invalid else (None, "low", "E2")
        assert db.run(query, (fid,)) == [expected]


def test_same_strength_answers_use_occurred_then_created_time(db: Db) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", severity="high", evidence_grade="E1", created_at=NOW)
    decision(
        db, fid, validity="not_affected", severity="low", evidence_grade="E1", created_at=LATER
    )
    query = f"SELECT validity, severity FROM {db.t('current_decision')} WHERE finding_id = ?"
    assert db.run(query, (fid,)) == [("not_affected", "low")]
    decision(
        db,
        fid,
        validity="confirmed",
        severity="informational",
        evidence_grade="E1",
        occurred_at=LATER,
        created_at=NOW,
    )
    assert db.run(query, (fid,)) == [("confirmed", "informational")]


def test_current_decision_preserves_population_and_null_shape(db: Db) -> None:
    fid = finding(db, repo(db))
    assert db.run(f"SELECT * FROM {db.t('current_decision')}") == []
    assert decision_status(db, fid) == (None, True)
    decision(db, fid, validity="unknown", severity="unknown", evidence_grade="unknown")
    rows = db.run(f"SELECT * FROM {db.t('current_decision')}")
    assert [(str(row[0]), *row[1:]) for row in rows] == [(fid, None, None, None)]
    assert decision_status(db, fid) == (None, True)


def test_explicit_view_refresh_is_transactional_and_preserves_statements(db: Db) -> None:
    fid = finding(db, repo(db))
    decision(db, fid, validity="confirmed", evidence_grade="E0")
    decision(db, fid, validity="false_positive", evidence_grade="E0", occurred_at=LATER)
    saved = db.run(f"SELECT * FROM {db.t('decision')} ORDER BY id")
    path = next(
        path
        for path in storage_sql.bootstrap_files(db.engine)
        if path.name == "current_decision.sql"
    )
    # Install the prior latest-nonnull projection to model an already-created DB.
    db.run("BEGIN")
    if db.engine == "sqlite":
        db.run(f"DROP VIEW {db.t('current_decision')}")
    create = "CREATE VIEW" if db.engine == "sqlite" else "CREATE OR REPLACE VIEW"
    db.run(
        f"{create} {db.t('current_decision')} AS "
        f"SELECT f.id AS finding_id, "
        f"(SELECT d.validity FROM {db.t('decision')} d "
        "WHERE d.finding_id = f.id AND d.validity IS NOT NULL "
        "ORDER BY d.occurred_at DESC, d.created_at DESC LIMIT 1) AS validity, "
        "CAST(NULL AS TEXT) AS severity, CAST(NULL AS TEXT) AS evidence_grade "
        f"FROM {db.t('finding')} f"
    )
    db.run("COMMIT")
    assert decision_status(db, fid) == ("false_positive", False)

    db.run("BEGIN")
    for statement in bootstrap_statements(db.engine, path):
        db.run(statement)
    assert decision_status(db, fid) == ("confirmed", True)
    db.run("ROLLBACK")
    assert decision_status(db, fid) == ("false_positive", False)

    # Explicitly reapplying the authored file is safe with dependent views and
    # is repeatable. No bootstrap-order or statement-loader change is needed.
    for _ in range(2):
        db.run("BEGIN")
        for statement in bootstrap_statements(db.engine, path):
            db.run(statement)
        db.run("COMMIT")
        assert decision_status(db, fid) == ("confirmed", True)
        assert db.run(f"SELECT * FROM {db.t('decision')} ORDER BY id") == saved


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


def test_status_and_clock_follow_the_default_line(db: Db) -> None:
    rid = repo(db)
    main1 = db.insert(
        "repository_ref", repository_id=rid, name="main", kind="branch", is_default=True, sha="m1"
    )
    main2 = db.insert(
        "repository_ref", repository_id=rid, name="main", kind="branch", is_default=True, sha="m2"
    )
    release = ref(db, rid, "release-4.22", "r1")
    a1, a2, a3 = (assessment(db, r) for r in (main1, main2, release))
    fixed, untouched, refuted = (finding(db, rid, n * 64) for n in "abc")
    for fid in (fixed, untouched, refuted):
        db.insert("occurrence", finding_id=fid, assessment_id=a1, severity="medium")
    db.insert(
        "decision",
        finding_id=fixed,
        assessment_id=a1,
        statement_key="1",
        validity="confirmed",
        severity="critical",
        occurred_at=NOW,
    )
    db.insert(
        "decision",
        finding_id=fixed,
        assessment_id=a2,
        statement_key="2",
        resolution="resolved",
        occurred_at=LATER,
    )
    db.insert(
        "decision",
        finding_id=fixed,
        assessment_id=a3,
        statement_key="3",
        resolution="open",
        occurred_at=LATER,
    )  # still open on the release line
    db.insert(
        "decision",
        finding_id=refuted,
        actor="human:a",
        statement_key="4",
        validity="false_positive",
        occurred_at=LATER,
    )

    status = {
        str(fid): (sev, bool(is_open))
        for fid, sev, is_open in db.run(
            f"SELECT finding_id, severity, is_open FROM {db.t('finding_status')}"
        )
    }
    assert status == {
        fixed: ("critical", False),  # fixed on main; the release line does not reopen it
        untouched: ("medium", True),
        refuted: ("medium", False),
    }
    clock = {
        str(fid): closed
        for fid, closed in db.run(f"SELECT finding_id, closed_at FROM {db.t('finding_clock')}")
    }
    assert clock[untouched] is None
    assert clock[fixed] is not None and clock[refuted] is not None
    resolution_on_release = db.run(
        f"SELECT resolution FROM {db.t('current_resolution')} WHERE finding_id = ? AND line = ?",
        (fixed, "release-4.22"),
    )
    assert resolution_on_release == [("open",)]


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
