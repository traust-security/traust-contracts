"""Real-server checks using the fixed reachable PostgreSQL test database."""

from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest
from conftest import (
    FINDINGS_SUMMARY_ROWS,
    FINDINGS_SUMMARY_SCOPE,
    report_with_external_blocking,
    report_with_findings,
    seed_findings_summary,
)
from storage_samples import (
    ALL_SECONDARY_PROJECTION_TABLES,
    FAMILIES,
    INVENTORY_TABLES,
    PROJECTION_TABLES,
    REGISTRY_TABLES,
    RUN_BOUND,
    encode,
    sample,
)

from traust_contracts.v1.storage import Binding, IngestError, Store
from traust_contracts.v1.storage.sql import REVISION

TABLES = {
    "portfolio_forge_facts",
    *REGISTRY_TABLES,
    *INVENTORY_TABLES,
    "artifact_binding",
    "artifact_evidence",
    "artifact_location",
    "traust_storage_meta",
    *PROJECTION_TABLES.values(),
    *ALL_SECONDARY_PROJECTION_TABLES,
}


@pytest.fixture(params=[False, True], ids=["transactional-driver", "autocommit-driver"])
def database(request: pytest.FixtureRequest, postgres_dsn: str) -> Iterator[tuple[Any, str]]:
    import psycopg
    from psycopg import sql

    conn = psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=2)
    schema = "storage_test_" + uuid4().hex
    conn.execute("DROP SCHEMA IF EXISTS traust_storage CASCADE")
    conn.execute(sql.SQL("CREATE SCHEMA {} ").format(sql.Identifier(schema)))
    conn.execute(sql.SQL("SET search_path TO {}, traust_storage").format(sql.Identifier(schema)))
    conn.autocommit = request.param
    try:
        yield conn, schema
    finally:
        conn.rollback()
        conn.autocommit = True
        conn.execute("DROP SCHEMA IF EXISTS traust_storage CASCADE")
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        conn.close()


def run_binding(
    *, scope: str = "local", layer: str | None = None, supersedes: str | None = None
) -> Binding:
    return Binding(scope, "sci:inventory-item:42", "sci:scan-result:7", layer, supersedes)


def binding_for(name: str) -> Binding:
    if name in RUN_BOUND:
        return run_binding()
    if name == "layer":
        return Binding(layer_id="ledger:layer:1")
    return Binding()


def test_postgres_shape_roundtrip_and_binding_noop(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    assert {
        row[0]
        for row in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'traust_storage'"
        ).fetchall()
    } == TABLES
    conn.commit()
    for name in FAMILIES:
        payload, _ = sample(name)
        result = store.ingest(name, payload, binding_for(name))
        # Evidence record keeps digest and byte_size, not payload.
        row = conn.execute(
            "SELECT byte_size FROM artifact_evidence WHERE digest = %s", (result.digest,)
        ).fetchone()
        assert row[0] == len(payload)
        conn.commit()
        retry = store.ingest(name, payload, binding_for(name))
        assert retry.already_bound and retry.binding_id == result.binding_id
    assert conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (len(FAMILIES),)
    fan_out = {"vuln-findings": 2, "corpus-registry": 2, "threat-model": 2, "layer": 3}
    for name, table in PROJECTION_TABLES.items():
        # Fan-out families project one row per item in their sample.
        expected = fan_out.get(name, 1)
        assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (expected,)
    assert conn.execute(
        "SELECT reloptions FROM pg_class WHERE oid='findings_summary'::regclass"
    ).fetchone() == (["security_barrier=true"],)
    conn.commit()
    conn.execute("UPDATE traust_storage_meta SET revision=%s", (REVISION + 1,))
    conn.commit()
    with pytest.raises(IngestError, match="explicit migration"):
        store.init()


def test_postgres_storage_does_not_collide_with_application_tables(
    database: tuple[Any, str],
) -> None:
    conn, _ = database
    conn.execute("CREATE TABLE report (marker TEXT NOT NULL)")
    conn.execute("INSERT INTO report VALUES ('application-owned')")
    conn.commit()
    store = Store(conn)
    store.init()
    store.ingest("report", sample("report")[0], binding_for("report"))
    assert conn.execute("SELECT marker FROM report").fetchall() == [("application-owned",)]
    assert conn.execute("SELECT count(*) FROM traust_storage.report").fetchone() == (1,)
    conn.commit()


@pytest.mark.parametrize("number", [1, 1.0, 1e3])
def test_postgres_integral_projection(database: tuple[Any, str], number: int | float) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    document = json.loads(sample("vuln-findings")[0])
    document["findings"][0]["line"] = number
    payload = json.dumps(document).encode()
    store.ingest("vuln-findings", payload, run_binding())
    assert conn.execute(
        "SELECT line FROM finding WHERE finding_id=%s",
        (document["findings"][0]["id"],),
    ).fetchone() == (int(number),)
    conn.commit()


def test_postgres_findings_summary_uses_json_scope_and_same_run(
    database: tuple[Any, str],
) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    seed_findings_summary(store)
    assert store.query_findings_summary([FINDINGS_SUMMARY_SCOPE]) == FINDINGS_SUMMARY_ROWS
    assert store.query_findings_summary(["other"]) == []
    conn.execute("BEGIN READ ONLY")
    conn.execute("SELECT set_config('traust.scope_ids', %s, true)", ('["local"]',))
    assert conn.execute("SELECT count(*) FROM findings_summary").fetchone() == (2,)
    conn.execute("ROLLBACK")


def test_postgres_atomic_projection_failure(database: tuple[Any, str]) -> None:
    from psycopg import sql

    conn, _ = database
    store = Store(conn)
    store.init()
    payload = sample("vuln-findings")[0]
    second = json.loads(payload)["findings"][1]["id"]
    conn.execute(
        sql.SQL("ALTER TABLE finding ADD CHECK (finding_id <> {})").format(sql.Literal(second))
    )
    conn.commit()
    with pytest.raises(IngestError, match="23514"):
        store.ingest("vuln-findings", payload, run_binding())
    assert conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (0,)
    assert conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (0,)
    conn.commit()


def test_postgres_supersession_is_explicit(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    payload = sample("vuln-findings")[0]
    first = store.ingest("vuln-findings", payload, run_binding())
    corrected = json.loads(payload)
    corrected["findings"][0]["title"] = "Explicit corrected title"
    second = store.ingest(
        "vuln-findings",
        encode(corrected),
        run_binding(supersedes=first.binding_id),
    )
    assert conn.execute(
        "SELECT binding_id FROM current_binding WHERE artifact_name='vuln-findings'"
    ).fetchall() == [(second.binding_id,)]
    conn.commit()


def test_postgres_role_and_references_round_trip(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    payload = sample("report")[0]
    baseline = store.ingest(
        "report", payload, replace(run_binding(), role="baseline"), references=["s3://b/base.json"]
    )
    cumulative = store.ingest("report", payload, replace(run_binding(), role="cumulative"))
    assert baseline.binding_id != cumulative.binding_id
    record = store.get_binding(baseline.binding_id)
    assert record.binding.role == "baseline"
    assert record.references == ("s3://b/base.json",)
    assert record.byte_size == len(payload)
    assert store.get_binding(cumulative.binding_id).references == ()


def test_postgres_concurrent_same_binding(database: tuple[Any, str], postgres_dsn: str) -> None:
    import psycopg

    conn, schema = database
    Store(conn).init()
    payload = sample("vuln-findings")[0]
    barrier = Barrier(2)

    def ingest() -> Any:
        with psycopg.connect(postgres_dsn, options=f"-csearch_path={schema}") as peer:
            barrier.wait(timeout=10)
            return Store(peer).ingest("vuln-findings", payload, run_binding())

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ingest(), range(2)))
    assert sorted(result.already_bound for result in results) == [False, True]
    assert conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (1,)
    assert conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (1,)
    assert conn.execute("SELECT count(*) FROM finding").fetchone() == (2,)
    conn.commit()


def test_postgres_caller_transaction_is_untouched(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    conn.execute("CREATE TABLE caller_work (value TEXT)")
    conn.commit()
    conn.execute("BEGIN")
    conn.execute("INSERT INTO caller_work VALUES ('uncommitted')")
    with pytest.raises(IngestError, match="caller transaction is untouched"):
        store.ingest("vuln-findings", sample("vuln-findings")[0], run_binding())
    assert conn.execute("SELECT * FROM caller_work").fetchall() == [("uncommitted",)]
    conn.execute("ROLLBACK")


def test_postgres_report_findings_match_sqlite_row_for_row(database: tuple[Any, str]) -> None:
    """GAP A/B on the other dialect, from the one shared fixture.

    SQLite stores the flags as 0/1 and PostgreSQL as booleans; the projection
    must still say the same thing about the same bytes. Comparing normalised
    values rather than raw driver types is the point -- a dialect that
    silently coerced an absent flag to False would diverge here.
    """
    conn, _ = database
    store = Store(conn)
    store.init()
    result = store.ingest("report", report_with_findings(), run_binding())

    rows = conn.execute(
        "SELECT finding_id, fingerprint, validity, resolution, assurance, "
        "conflict, fp_overridden, fp_reassertion_blocked, refuted_awaiting_signoff, "
        "severity_override, validation_status "
        "FROM report_finding WHERE binding_id = %s ORDER BY finding_id",
        (result.binding_id,),
    ).fetchall()
    assert len(rows) == 2

    disposed, bare = rows
    assert disposed[:5] == (
        "FIND-001",
        "a" * 64,
        "confirmed",
        "fix_in_progress",
        "execution_proven",
    )
    assert (disposed[5], disposed[6], disposed[7], disposed[8]) == (False, True, True, False)
    assert disposed[9]["severity"] == "critical"
    assert disposed[10] == "confirmed"
    assert bare[0] == "FIND-002"
    assert all(value is None for value in bare[1:])
    conn.commit()


def test_postgres_report_blocking_preserves_false_and_absent(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    result = store.ingest("report", report_with_external_blocking(), run_binding())
    rows = conn.execute(
        "SELECT finding_id, remediation_effort, blocked_external "
        "FROM report_finding WHERE binding_id = %s ORDER BY finding_id",
        (result.binding_id,),
    ).fetchall()
    assert rows == [
        ("FIND-001", "m", 1),
        ("FIND-002", "m", 0),
        ("FIND-003", "blocked-external", None),
    ]
    conn.commit()


def test_postgres_subject_ownership_matches_sqlite(database: tuple[Any, str]) -> None:
    """GAP C on the other dialect, from the same fixture.

    is_branch_audit is INTEGER on SQLite and BOOLEAN here; the row must still
    say the same thing, and an absent flag must stay NULL on both.
    """
    conn, _ = database
    store = Store(conn)
    store.init()
    result = store.ingest("corpus-registry", sample("corpus-registry")[0], Binding())
    rows = conn.execute(
        "SELECT subject_id, tree, ownership, business_unit, product, ref_kind, "
        "is_branch_audit FROM subject_ownership WHERE binding_id = %s ORDER BY subject_id",
        (result.binding_id,),
    ).fetchall()
    assert rows == [
        (
            "findings/example/repo",
            "findings",
            "owned",
            "Platform Group",
            "example-product",
            None,
            False,
        ),
        (
            "other/example/repo@release-1.0",
            "other-findings",
            "external-bu",
            "Other Unit",
            None,
            "branch",
            True,
        ),
    ]
    conn.commit()


def test_postgres_report_current_collapses_restatements(database: tuple[Any, str]) -> None:
    """GAP D on the other dialect. The boolean/integer split matters here:
    disposition_aware is a CASE expression, so both must yield the same rank."""
    conn, _ = database
    store = Store(conn)
    store.init()
    audit = json.loads(report_with_findings())
    for finding in audit["findings"]:
        finding.pop("disposition", None)
    current = json.loads(report_with_findings())
    current["disposition_summary"] = {
        "layer_ref": "repo-findings-layer.json",
        "generated_at": "2026-01-02T00:00:00Z",
        "by_resolution": {
            "open": 2,
            "fix_in_progress": 0,
            "resolved": 0,
            "partially_resolved": 0,
            "risk_accepted": 0,
            "regression_introduced": 0,
        },
        "by_validity": {"confirmed": 1, "corrected": 0, "false_positive": 0, "not_verified": 1},
    }
    store.ingest("report", encode(audit), Binding(subject_id="repo/a", run_id="run:audit"))
    store.ingest("report", encode(current), Binding(subject_id="repo/a", run_id="run:current"))

    assert conn.execute("SELECT count(*) FROM report_finding").fetchone() == (4,)
    assert conn.execute("SELECT subject_id, disposition_aware FROM report_current").fetchall() == [
        ("repo/a", 1)
    ]
    assert conn.execute(
        "SELECT count(*) FROM report_finding f JOIN report_current c ON c.binding_id = f.binding_id"
    ).fetchone() == (2,)
    conn.commit()


def test_postgres_dashboard_views_agree_with_sqlite(database: tuple[Any, str]) -> None:
    """The three dashboard views, on the other dialect, from one fixture.

    This tier is what caught `is_branch_audit = 0`: the column is BOOLEAN
    here and INTEGER on SQLite, so the comparison was an UndefinedFunction
    error that SQLite accepted silently.
    """
    conn, _ = database
    store = Store(conn)
    store.init()
    subject = "findings/org/repo"
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "subjects": [
                    {
                        "subject_id": subject,
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Platform Group",
                        "is_branch_audit": False,
                    }
                ],
            }
        ),
        Binding(),
    )
    store.ingest("report", report_with_findings(), Binding(subject_id=subject, run_id="r1"))

    families = dict(
        conn.execute("SELECT family, count(*) FROM current_finding GROUP BY family").fetchall()
    )
    assert families == {"code": 2}
    conn.commit()  # the raw read above opens a txn on the transactional driver
    assert len(store.query_open_findings(["local"])) == 2
    assert store.query_hardening_findings(["local"]) == []
    # Owned, HEAD, fingerprinted -> exactly one distinct-exposure row.
    assert len(store.query_distinct_exposure(["local"])) == 1
    conn.commit()


def test_postgres_projects_and_orders_owasp_ratings(database: tuple[Any, str]) -> None:
    """The rating columns exist, type and order the same way on PostgreSQL."""
    import json

    from storage_samples import rated_threat_model

    conn, _ = database
    store = Store(conn)
    store.init()
    store.ingest("threat-model", rated_threat_model(), run_binding())
    rows = {
        row[0]: row[1:]
        for row in conn.execute(
            "SELECT threat_id, severity, likelihood_score, likelihood_level, impact_score, "
            "impact_level, impact_basis, risk_rating, score FROM traust_storage.threat"
        )
    }
    assert rows["T2"][:6] == ("high", 4.375, "medium", 7.25, "high", "technical")
    assert rows["T2"][6]["likelihood"]["factors"]["awareness"] == 9
    assert rows["T2"][7] is None, "no legacy score on a rated threat"
    assert rows["T1"][:7] == (None,) * 7 and rows["T1"][7] is not None
    if not conn.autocommit:
        conn.rollback()  # the raw read opened a transaction; the store needs an idle one
    current = {row[2]: row for row in store.query_threat_current(["local"])}
    assert current["T2"][-6:] == ("high", 4.375, "medium", 7.25, "high", "technical")
    assert json.loads(json.dumps(current["T2"][-7]))["severity"] == "high"
    exposure = store.query_threat_exposure(["local"])
    assert {row[-1] for row in exposure} == {"high", None}


def _pg_registry_owner(store: Store, product: str = "rhacm") -> str:
    return store.register_product_repo(
        store.register_product(product),
        store.register_repo("https://github.com/stolostron/acm-cli"),
    )


def _pg_cumulative(owner: str, supersedes: str | None = None) -> Binding:
    return Binding(
        subject_id="findings/rhacm/acm-cli",
        run_id="corpus:run:findings/rhacm/acm-cli",
        supersedes_binding_id=supersedes,
        role="cumulative",
        product_repo_id=owner,
    )


def test_postgres_registry_foreign_keys(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.register_product_repo("missing-product", "missing-repo")
    payload, _ = sample("report")
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.ingest("report", payload, _pg_cumulative("missing-product-repo"))
    owner = _pg_registry_owner(store)
    assert _pg_registry_owner(store) == owner
    result = store.ingest("report", payload, _pg_cumulative(owner))
    assert store.get_binding(result.binding_id).binding.product_repo_id == owner


def test_postgres_one_current_findings_current_per_product_repo(
    database: tuple[Any, str],
) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    owner = _pg_registry_owner(store)
    payload, _ = sample("report")
    first = store.ingest("report", payload, _pg_cumulative(owner))
    changed = json.loads(payload)
    changed["remediation_roadmap"].append(dict(changed["remediation_roadmap"][0]))
    with pytest.raises(IngestError, match=r"(?i)unique"):
        store.ingest("report", encode(changed), _pg_cumulative(owner))
    second = store.ingest("report", encode(changed), _pg_cumulative(owner, first.binding_id))
    rows = conn.execute(
        "SELECT binding_id FROM current_binding WHERE artifact_role = 'cumulative'"
    ).fetchall()
    conn.commit()
    assert rows == [(second.binding_id,)]


def _pg_shape(conn: Any) -> dict[str, list[tuple[Any, ...]]]:
    """Columns by name, FKs, indexes, views -- column order is ignored (ALTER appends)."""
    columns = conn.execute(
        "SELECT table_name, column_name, data_type, is_nullable, column_default "
        "FROM information_schema.columns WHERE table_schema = 'traust_storage' ORDER BY 1, 2"
    ).fetchall()
    indexes = conn.execute(
        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'traust_storage' ORDER BY 1"
    ).fetchall()
    foreign_keys = conn.execute(
        "SELECT conrelid::regclass::text, pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE contype = 'f' AND connamespace = 'traust_storage'::regnamespace ORDER BY 1, 2"
    ).fetchall()
    # PostgreSQL stores b.* expanded in the table's physical column order, which
    # differs after ALTER TABLE ADD COLUMN; compare each definition's lines unordered.
    views = [
        (name, sorted(definition.splitlines()))
        for name, definition in conn.execute(
            "SELECT viewname, definition FROM pg_views "
            "WHERE schemaname = 'traust_storage' ORDER BY 1"
        ).fetchall()
    ]
    conn.commit()
    return {"columns": columns, "indexes": indexes, "foreign_keys": foreign_keys, "views": views}


def test_postgres_migrate_bootstraps_empty_and_runs_a_step(
    database: tuple[Any, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty -> bootstrap; then, with REVISION one ahead, a step through 001_to_002."""
    conn, _ = database
    Store(conn).init()
    expected = _pg_shape(conn)
    conn.execute("DROP SCHEMA traust_storage CASCADE")
    conn.commit()
    assert Store(conn).migrate() == 0
    assert _pg_shape(conn) == expected
    owner = _pg_registry_owner(Store(conn))
    for module in ("traust_contracts.v1.storage.store", "traust_contracts.v1.storage.sql"):
        monkeypatch.setattr(f"{module}.REVISION", REVISION + 1)
    with pytest.raises(IngestError, match="explicit migration"):
        Store(conn).init()
    assert Store(conn).migrate() == REVISION
    Store(conn).init()
    assert _pg_shape(conn) == expected
    rows = conn.execute(
        "SELECT (SELECT revision FROM traust_storage_meta), "
        "(SELECT count(*) FROM product_repo WHERE product_repo_id = %s)",
        (owner,),
    ).fetchone()
    conn.commit()
    assert rows == (REVISION + 1, 1)


def test_postgres_inventory_tables(database: tuple[Any, str]) -> None:
    conn, _ = database
    store = Store(conn)
    store.init()
    owner = _pg_registry_owner(store)
    store.register_product_repo_version(owner, "2.15", "Operator", ["storage"], ["a", "b"])
    store.register_product_repo_version(owner, "2.15", "Operator", None, ["c"])
    store.register_repo_owner(owner, "Stolostron / ACM", individuals=["x"])
    rows = conn.execute(
        "SELECT v.images, o.individuals FROM product_repo_version v "
        "JOIN repo_owner o ON o.product_repo_id = v.product_repo_id"
    ).fetchall()
    conn.commit()
    assert rows == [(["c"], ["x"])]
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.register_repo_owner("0" * 64, "team")
