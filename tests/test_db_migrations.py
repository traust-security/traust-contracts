"""The upgrade channel: ordered, hash-stamped, additive, data-preserving.

Rules a bad change could break: scripts run in filename order, whole, once;
a changed or removed script is refused rather than re-run; a dry run plans
without touching the database; and an applied upgrade never loses a row.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import bootstrap_namespaces_sqlite, skip_postgres

from traust_contracts.v1 import migrations
from traust_contracts.v1.ledger import sql as ledger_sql
from traust_contracts.v1.ops import sql as ops_sql
from traust_contracts.v1.storage import sql as storage_sql

MODULES = (storage_sql, ops_sql, ledger_sql)
NOTE = "-- a future additive upgrade\nALTER TABLE {table} ADD COLUMN note TEXT;\n"


def _sqlite() -> sqlite3.Connection:
    conn = bootstrap_namespaces_sqlite(*MODULES)
    conn.isolation_level = None
    return conn


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_channel(root: Path, name: str, body: str) -> Path:
    """One script in both dialects of a channel rooted at ``root``."""
    for dialect, table in (("sqlite", "repository"), ("postgres", "traust.repository")):
        upgrades = root / dialect / "upgrades"
        upgrades.mkdir(parents=True, exist_ok=True)
        (upgrades / name).write_text(body.format(table=table), encoding="utf-8")
    return root


@pytest.fixture
def channel(tmp_path: Path) -> Path:
    """A channel carrying one future additive upgrade, dialect-paired."""
    return _write_channel(tmp_path, "0001_add_note.sql", NOTE)


def test_a_fresh_bootstrap_stamps_the_channel_empty() -> None:
    conn = _sqlite()
    assert migrations.run_upgrades(conn, "sqlite") == []
    assert migrations.run_upgrades(conn, "sqlite") == []  # idempotent
    assert conn.execute("SELECT name, sha256 FROM db_upgrade").fetchall() == []


def test_names_must_be_slugs_numbered_gaplessly_from_one(tmp_path: Path) -> None:
    with pytest.raises(migrations.MigrationError, match="NNNN_slug"):
        root = _write_channel(tmp_path / "a", "add_note.sql", "SELECT 1;")
        migrations.upgrade_files("sqlite", root=root)
    with pytest.raises(migrations.MigrationError, match="gapless"):
        root = _write_channel(tmp_path / "b", "0002_add_note.sql", "SELECT 1;")
        migrations.upgrade_files("sqlite", root=root)
    with pytest.raises(migrations.MigrationError, match="gapless"):
        root = tmp_path / "c"
        for name in ("0001_a.sql", "0001_b.sql", "0002_c.sql"):
            _write_channel(root, name, "SELECT 1;")
        migrations.upgrade_files("sqlite", root=root)
    root = _write_channel(tmp_path / "d", "0001_a.sql", "SELECT 1;")
    _write_channel(tmp_path / "d", "0002_b.sql", "SELECT 1;")
    assert [p.name for p in migrations.upgrade_files("sqlite", root=root)] == [
        "0001_a.sql",
        "0002_b.sql",
    ]


def test_the_shipped_channel_is_dialect_paired() -> None:
    assert [p.name for p in migrations.upgrade_files("sqlite")] == [
        p.name for p in migrations.upgrade_files("postgres")
    ]


def test_a_script_carries_no_transaction_statements(tmp_path: Path) -> None:
    root = _write_channel(
        tmp_path, "0001_owned.sql", "BEGIN;\nALTER TABLE {table} ADD COLUMN note TEXT;\nCOMMIT;\n"
    )
    with pytest.raises(migrations.MigrationError, match="owns those"):
        migrations.pending_upgrades("sqlite", {}, root=root)


def test_pending_refuses_drift_in_both_directions(channel: Path) -> None:
    pending = migrations.pending_upgrades("sqlite", {}, root=channel)
    assert [u.name for u in pending] == ["0001_add_note"]
    sha256 = pending[0].sha256
    assert len(sha256) == 64
    assert migrations.pending_upgrades("sqlite", {"0001_add_note": sha256}, root=channel) == []
    with pytest.raises(migrations.MigrationError, match="changed after"):
        migrations.pending_upgrades("sqlite", {"0001_add_note": "0" * 64}, root=channel)
    with pytest.raises(migrations.MigrationError, match="no longer ships"):
        migrations.pending_upgrades("sqlite", {"0002_gone": sha256}, root=channel)


def test_an_upgrade_adds_its_column_and_preserves_every_row(channel: Path) -> None:
    conn = _sqlite()
    for url in ("https://example.com/r1", "https://example.com/r2"):
        conn.execute("INSERT INTO repository (url, public) VALUES (?, 1)", (url,))
    before = conn.execute("SELECT * FROM repository").fetchall()
    assert len(before) == 2

    applied = migrations.run_upgrades(conn, "sqlite", root=channel)
    assert [u.name for u in applied] == ["0001_add_note"]

    after = conn.execute("SELECT * FROM repository").fetchall()
    assert [row[:-1] for row in after] == before  # every column, every row, unchanged
    assert all(row[-1] is None for row in after)  # the new column invents nothing
    stamps = conn.execute("SELECT name, sha256, applied_at FROM db_upgrade").fetchall()
    assert [(name, sha) for name, sha, _ in stamps] == [
        ("0001_add_note", _sha256(channel / "sqlite" / "upgrades" / "0001_add_note.sql"))
    ]
    assert all(at for _, _, at in stamps)
    assert migrations.run_upgrades(conn, "sqlite", root=channel) == []  # once, ever


def test_a_dry_run_plans_without_touching_the_database(channel: Path) -> None:
    conn = _sqlite()
    conn.execute("INSERT INTO repository (url, public) VALUES ('https://example.com/r', 1)")

    planned = migrations.run_upgrades(conn, "sqlite", root=channel, dry_run=True)
    assert [u.name for u in planned] == ["0001_add_note"]

    assert migrations.applied_upgrades(conn, "sqlite") == {}  # no stamp table was created
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("SELECT note FROM repository")  # and no DDL ran


def test_a_raced_apply_loses_to_the_stamp_and_moves_on(
    channel: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _sqlite()
    migrations.run_upgrades(conn, "sqlite", root=channel)  # another process applied it

    real, reads = migrations.applied_upgrades, 0

    def stale_snapshot(c: Any, dialect: str) -> dict[str, str]:
        nonlocal reads
        reads += 1
        return {} if reads == 1 else real(c, dialect)

    monkeypatch.setattr(migrations, "applied_upgrades", stale_snapshot)
    raced = migrations.run_upgrades(conn, "sqlite", root=channel)
    assert [u.name for u in raced] == ["0001_add_note"]  # reported, not re-applied
    assert conn.execute("SELECT count(*) FROM db_upgrade").fetchone()[0] == 1


def test_postgres_stamps_applies_and_preserves(postgres_dsn: str, tmp_path: Path) -> None:
    try:
        import psycopg
    except ImportError:
        skip_postgres("psycopg is not installed")
    try:
        conn = psycopg.connect(postgres_dsn, autocommit=True)
    except psycopg.OperationalError:
        skip_postgres("local database is unavailable")
        return

    for schema in ("traust_ledger", "traust_ops", "traust"):
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    for module in MODULES:
        for path in module.bootstrap_files("postgres"):
            for statement in module.bootstrap_statements("postgres", path):
                conn.execute(statement)

    try:
        assert migrations.run_upgrades(conn, "postgres") == []  # fresh: empty channel
        assert conn.execute("SELECT name, sha256 FROM traust.db_upgrade").fetchall() == []

        channel = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
        for url in ("https://example.com/r1", "https://example.com/r2"):
            conn.execute("INSERT INTO traust.repository (url, public) VALUES (%s, true)", (url,))
        before = conn.execute("SELECT * FROM traust.repository").fetchall()

        applied = migrations.run_upgrades(conn, "postgres", root=channel)
        assert [u.name for u in applied] == ["0001_add_note"]

        after = conn.execute("SELECT * FROM traust.repository").fetchall()
        assert [row[:-1] for row in after] == before
        assert all(row[-1] is None for row in after)
        script = channel / "postgres" / "upgrades" / "0001_add_note.sql"
        stamps = conn.execute("SELECT name, sha256 FROM traust.db_upgrade").fetchall()
        assert stamps == [("0001_add_note", _sha256(script))]
        assert migrations.run_upgrades(conn, "postgres", root=channel) == []
    finally:
        conn.close()
