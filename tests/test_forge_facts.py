"""Upgrade safety and the persisted/derived boundary for XWING-2214."""

import sqlite3

import pytest

from traust_contracts.v1.storage import IngestError, Store
from traust_contracts.v1.storage.sql import REVISION


def test_revision_one_upgrade_adds_facts_without_changing_existing_rows():
    conn = sqlite3.connect(":memory:")
    store = Store(conn)
    store.init()
    product = store.register_product("example")
    conn.execute("DROP TABLE portfolio_forge_facts")
    conn.execute("UPDATE traust_storage_meta SET revision = 1")
    conn.commit()
    with pytest.raises(IngestError, match="migration"):
        store.init()
    assert store.migrate() == 1
    assert conn.execute("SELECT revision FROM traust_storage_meta").fetchone() == (REVISION,)
    assert store.register_product("example") == product
    assert conn.execute("SELECT count(*) FROM portfolio_forge_facts").fetchone() == (0,)


def test_unknown_measurements_and_missing_url_filings_remain_distinct():
    conn = sqlite3.connect(":memory:")
    Store(conn).init()
    for key in ("filing-a", "filing-b"):
        conn.execute(
            """INSERT INTO portfolio_forge_facts
                       (identity, repo_key, has_audit, status, observed_at)
                       VALUES (?, ?, ?, ?, ?)""",
            (f"key:{key}", key, True, "no-repo-url", "2026-10-01T00:00:00+00:00"),
        )
    assert conn.execute("SELECT repo_url, changed_lines FROM portfolio_forge_facts").fetchall() == [
        (None, None),
        (None, None),
    ]
    columns = {row[1] for row in conn.execute("PRAGMA table_info(portfolio_forge_facts)")}
    assert not columns & {
        "risk_tier",
        "exposure",
        "audit_age_days",
        "churn_ratio",
        "live_crit_high",
    }
    assert {"audited_sha", "audit_date", "has_audit"} <= columns
    assert not conn.execute(
        "SELECT name FROM sqlite_master WHERE name='security_repo_state'"
    ).fetchall()
