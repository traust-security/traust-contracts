"""The upgrade channel: ordered, hash-stamped, additive, data-preserving.

Rules a bad change could break: scripts run in filename order, whole, once;
a changed or removed script is refused rather than re-run; a dry run plans
without touching the database; and an applied upgrade never loses a row.
"""

from __future__ import annotations

import hashlib
import logging
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


def test_a_fresh_bootstrap_applies_the_shipped_channel_whole() -> None:
    conn = _sqlite()
    applied = migrations.run_upgrades(conn, "sqlite")
    assert [u.name for u in applied] == ["0001_repository_disposition"]
    assert migrations.run_upgrades(conn, "sqlite") == []
    stamps = conn.execute("SELECT name, sha256 FROM db_upgrade").fetchall()
    assert [name for name, _ in stamps] == ["0001_repository_disposition"]
    columns = [row[1] for row in conn.execute("PRAGMA table_info(repository)").fetchall()]
    assert {"disposition", "gone_streak"} <= set(columns)


def test_the_shipped_first_script_preserves_every_row() -> None:
    conn = _sqlite()
    for url in ("https://example.com/r1", "https://example.com/r2"):
        conn.execute("INSERT INTO repository (url, public) VALUES (?, 1)", (url,))
    before = conn.execute("SELECT * FROM repository").fetchall()

    migrations.run_upgrades(conn, "sqlite")

    after = conn.execute("SELECT * FROM repository").fetchall()
    assert [row[:7] for row in after] == before  # every baseline column, every row
    assert all(row[7] is None for row in after)  # disposition: existing rows stay active
    assert all(row[11] == 0 for row in after)  # gone_streak starts at 0


def test_stamp_channel_brings_a_pre_channel_store_on_at_the_head() -> None:
    """A store from before the channel - current shape, no stamps - is stamped
    as having run everything shipped: nothing runs, nothing is re-run, and the
    store is on the routine from the head."""
    conn = _sqlite()  # the baseline, as a pre-channel store would have it
    # the shape is already current: the column 0001 would add is there by hand of
    # the bootstrap, exactly the store this exists for
    migrations.run_upgrades(conn, "sqlite")  # a current store for reference
    conn.execute("DROP TABLE db_upgrade")  # ...minus the channel's bookkeeping

    stamped = migrations.stamp_channel(conn, "sqlite")

    assert [upgrade.name for upgrade in stamped] == ["0001_repository_disposition"]
    assert migrations.stamp_channel(conn, "sqlite") == []  # idempotent: known store
    assert migrations.run_upgrades(conn, "sqlite") == []  # nothing pending, nothing runs
    stamps = conn.execute("SELECT name, sha256 FROM db_upgrade").fetchall()
    assert stamps == [("0001_repository_disposition", stamped[0].sha256)]


def test_stamp_channel_refuses_drift_like_the_runner() -> None:
    conn = _sqlite()
    migrations.run_upgrades(conn, "sqlite")
    # a stamp whose script changed after it was recorded: fix forward, never re-stamp
    conn.execute(
        "UPDATE db_upgrade SET sha256 = ? WHERE name = '0001_repository_disposition'",
        (("0") * 64,),
    )
    with pytest.raises(migrations.MigrationError, match="changed after"):
        migrations.stamp_channel(conn, "sqlite")


def test_stamp_channel_never_stamps_over_an_enrolled_behind_store(tmp_path: Path) -> None:
    """A store on the channel with pending work is the runner's to advance,
    never the stamping's to presume: stamping it would mark unrun scripts done."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    conn = _sqlite()
    migrations.run_upgrades(conn, "sqlite", root=root)  # on the channel, at its head
    _write_channel(root, "0002_add_note2.sql", NOTE.replace("note", "note2"))  # later ship

    with pytest.raises(migrations.MigrationError, match="on the channel and behind"):
        migrations.stamp_channel(conn, "sqlite", root=root)
    # and the pending script is still pending: nothing was stamped over
    assert [u.name for u in migrations.run_upgrades(conn, "sqlite", root=root, dry_run=True)] == [
        "0002_add_note2"
    ]


def test_a_failed_stamp_leaves_no_stranded_empty_table(tmp_path: Path) -> None:
    """A stamp that fails without a concurrent winner must not strand the
    store behind an empty stamp table - the next open would read it as
    enrolled and run scripts against an already-current shape."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    conn = _sqlite()
    real = conn.execute

    class failing:  # an insert error with no concurrent winner
        def execute(self, sql: str) -> Any:
            if sql.startswith("BEGIN") or sql in ("COMMIT", "ROLLBACK"):
                return None
            if sql.startswith("INSERT INTO db_upgrade"):
                raise sqlite3.OperationalError("disk I/O error")
            return real(sql)

    with pytest.raises(sqlite3.OperationalError):
        migrations.stamp_channel(failing(), "sqlite", root=root)

    # the empty bookkeeping is gone: the store is still pre-channel, and a retry stamps
    assert (
        conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'db_upgrade'").fetchone()[0]
        == 0
    )
    stamped = migrations.stamp_channel(conn, "sqlite", root=root)
    assert [upgrade.name for upgrade in stamped] == ["0001_add_note"]


def test_a_comment_apostrophe_cannot_conceal_a_transaction_statement(tmp_path: Path) -> None:
    """Comments are stripped before literals, so apostrophes in two -- lines
    cannot pair up and swallow an intervening COMMIT from the scan."""
    sneaky = (
        "-- don't do this by hand\nCOMMIT;\n-- it's committed now\n"
        "ALTER TABLE {table} ADD COLUMN note TEXT;\n"
    )
    root = _write_channel(tmp_path, "0001_sneaky.sql", sneaky)
    conn = _sqlite()

    with pytest.raises(migrations.MigrationError, match="carries its own transaction statement"):
        migrations.run_upgrades(conn, "sqlite", root=root)


def test_a_quoted_literal_is_never_mistaken_for_a_transaction_statement(tmp_path: Path) -> None:
    """A value's text is not a statement: 'text; COMMIT' inside a literal
    passes the scan."""
    literal = (
        "-- a value that looks like a transaction\n"
        "INSERT INTO {table} (url, public) VALUES ('text; COMMIT', 1);\n"
    )
    root = _write_channel(tmp_path, "0001_literal.sql", literal)
    conn = _sqlite()

    assert [u.name for u in migrations.run_upgrades(conn, "sqlite", root=root)] == ["0001_literal"]


def test_an_older_channel_opens_a_newer_stamped_database(tmp_path: Path) -> None:
    """The rollback story: redeploy the older pair, the database stays
    forward. A stamp beyond the shipped channel's head is ahead - tolerated,
    nothing pending, nothing refused - and going forward again needs nothing."""
    v4 = _write_channel(tmp_path / "v4", "0001_add_note.sql", NOTE)
    _write_channel(v4, "0002_add_note2.sql", NOTE.replace("note", "note2"))
    v3 = _write_channel(tmp_path / "v3", "0001_add_note.sql", NOTE)
    conn = _sqlite()
    migrations.run_upgrades(conn, "sqlite", root=v4)  # the v4 deployment stamped both

    assert migrations.run_upgrades(conn, "sqlite", root=v3) == []  # v3 opens: ahead, no-op
    assert (
        migrations.pending_upgrades("sqlite", migrations.applied_upgrades(conn, "sqlite"), root=v3)
        == []
    )
    assert migrations.stamp_channel(conn, "sqlite", root=v3) == []  # known, ahead and current

    assert migrations.run_upgrades(conn, "sqlite", root=v4) == []  # forward again: nothing to do


def test_a_stamp_within_the_span_is_still_drift(tmp_path: Path) -> None:
    """Ahead-tolerance loosens nothing within the channel's span: a stamp for a
    script the channel no longer ships - removed or renamed - still refuses."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    _write_channel(root, "0002_add_note2.sql", NOTE.replace("note", "note2"))
    conn = _sqlite()
    migrations.run_upgrades(conn, "sqlite", root=root)
    (root / "sqlite" / "upgrades" / "0002_add_note2.sql").unlink()
    _write_channel(root, "0002_renamed.sql", NOTE.replace("note", "note2"))  # renamed in place

    with pytest.raises(migrations.MigrationError, match="no longer ships"):
        migrations.pending_upgrades(
            "sqlite", migrations.applied_upgrades(conn, "sqlite"), root=root
        )


def test_an_inline_comment_apostrophe_cannot_conceal_a_commit(tmp_path: Path) -> None:
    """The scanner walks comments, blocks and literals in one pass: an
    apostrophe in an inline -- comment never pairs with a later value's and
    swallows an intervening COMMIT."""
    sneaky = (
        "SELECT 1; -- don't commit by hand\n"
        "COMMIT;\n"
        "INSERT INTO {table} (url, public) VALUES ('later', 1);\n"
    )
    root = _write_channel(tmp_path, "0001_sneaky.sql", sneaky)
    conn = _sqlite()

    with pytest.raises(migrations.MigrationError, match="carries its own transaction statement"):
        migrations.run_upgrades(conn, "sqlite", root=root)


def test_destructive_work_inside_a_literal_is_still_destructive(tmp_path: Path) -> None:
    """Dynamic SQL is destructive work: EXECUTE '… DROP …' is flagged at plan
    time even though the drop lives in a string literal."""
    dynamic = "DO $$ BEGIN EXECUTE 'ALTER TABLE {table} DROP COLUMN public'; END $$;\n"
    root = _write_channel(tmp_path, "0001_dynamic.sql", dynamic)

    with pytest.raises(migrations.MigrationError, match="without a"):
        migrations.pending_upgrades("sqlite", {}, root=root)


def test_a_stamp_that_is_not_an_upgrades_name_refuses(tmp_path: Path) -> None:
    """The stamp table is the channel's bookkeeping: a name that is not an
    upgrade's refuses as such - never a ValueError, never silently ahead."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    sha = _sha256(root / "sqlite" / "upgrades" / "0001_add_note.sql")
    for name in ("future", "0002"):
        with pytest.raises(migrations.MigrationError, match="not an upgrade's name"):
            migrations.pending_upgrades("sqlite", {name: sha}, root=root)


def test_an_ahead_database_with_an_in_span_gap_refuses(tmp_path: Path) -> None:
    """A newer contracts stamps every script it ships, so a database ahead of
    this channel has every in-span script stamped too - a gap means its
    history is inconsistent, and old scripts never run against it."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    _write_channel(root, "0002_add_note2.sql", NOTE.replace("note", "note2"))
    sha = _sha256(root / "sqlite" / "upgrades" / "0001_add_note.sql")

    with pytest.raises(migrations.MigrationError, match="history is inconsistent"):
        migrations.pending_upgrades("sqlite", {"0003_future": sha}, root=root)


def test_stamp_channel_treats_a_won_race_as_a_no_op(tmp_path: Path) -> None:
    """Two openers plan the same stamps; the one whose insert loses to the
    other's commit rolls back, re-reads, and stamps nothing."""
    root = _write_channel(tmp_path, "0001_add_note.sql", NOTE)
    conn = _sqlite()
    real = conn.execute

    class raced:  # simulates the concurrent winner committing mid-transaction
        def execute(self, sql: str) -> Any:
            if sql.startswith("BEGIN") or sql in ("COMMIT", "ROLLBACK"):
                return None  # no transaction of our own: the winner commits in autocommit
            if sql.startswith("INSERT INTO db_upgrade"):
                real(sql)  # the concurrent opener's commit lands first
                raise sqlite3.IntegrityError("UNIQUE constraint failed: db_upgrade.name")
            return real(sql)

    stamped = migrations.stamp_channel(raced(), "sqlite", root=root)

    assert stamped == []  # lost the race: the winner's stamps stand, ours are nothing
    stamps = conn.execute("SELECT name, sha256 FROM db_upgrade").fetchall()
    assert len(stamps) == 1 and stamps[0][0] == "0001_add_note"  # stamped exactly once


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
    # mid-file: postgres loads a whole file as one statement
    root = _write_channel(tmp_path / "b", "0001_mid.sql", "SELECT 1;\nCOMMIT;\nSELECT 2;\n")
    with pytest.raises(migrations.MigrationError, match="owns those"):
        migrations.pending_upgrades("postgres", {}, root=root)
    # a trigger's BEGIN is not a transaction statement
    root = _write_channel(
        tmp_path / "c",
        "0001_trigger.sql",
        "CREATE TRIGGER t AFTER UPDATE ON {table} FOR EACH ROW BEGIN\n"
        "  UPDATE {table} SET note = 'x';\nEND;\n",
    )
    assert [u.name for u in migrations.pending_upgrades("sqlite", {}, root=root)] == [
        "0001_trigger"
    ]
    # house style: the trigger's BEGIN on its own line is still mid-statement
    root = _write_channel(
        tmp_path / "d",
        "0001_trigger.sql",
        "CREATE TRIGGER t AFTER UPDATE ON {table}\nFOR EACH ROW\nBEGIN\n"
        "  UPDATE {table} SET note = 'x';\nEND;\n",
    )
    assert [u.name for u in migrations.pending_upgrades("sqlite", {}, root=root)] == [
        "0001_trigger"
    ]


def test_pending_refuses_drift_but_tolerates_ahead(channel: Path) -> None:
    pending = migrations.pending_upgrades("sqlite", {}, root=channel)
    assert [u.name for u in pending] == ["0001_add_note"]
    sha256 = pending[0].sha256
    assert len(sha256) == 64
    assert migrations.pending_upgrades("sqlite", {"0001_add_note": sha256}, root=channel) == []
    with pytest.raises(migrations.MigrationError, match="changed after"):
        migrations.pending_upgrades("sqlite", {"0001_add_note": "0" * 64}, root=channel)
    with pytest.raises(migrations.MigrationError, match="no longer ships"):
        migrations.pending_upgrades("sqlite", {"0001_gone": sha256}, root=channel)
    # a stamp beyond the channel's head is ahead, not drift: the database was
    # stamped by a newer contracts, and this one opens it
    assert (
        migrations.pending_upgrades(
            "sqlite", {"0001_add_note": sha256, "0002_future": sha256}, root=channel
        )
        == []
    )


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
    assert migrations.run_upgrades(conn, "sqlite", root=channel) == []


def test_the_channel_logs_what_debugging_needs(
    channel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    conn = _sqlite()
    with caplog.at_level(logging.DEBUG, logger="traust_contracts.v1.migrations"):
        migrations.run_upgrades(conn, "sqlite", root=channel)
        migrations.run_upgrades(conn, "sqlite", root=channel)

    text = " ".join(record.message for record in caplog.records)
    assert "db channel applying dialect=sqlite pending=1 names=['0001_add_note']" in text
    applied = [r for r in caplog.records if getattr(r, "outcome", None) == "applied"]
    assert len(applied) == 1
    assert "name=0001_add_note" in applied[0].getMessage()
    assert "sha256=" in applied[0].getMessage()
    assert "duration_ms=" in applied[0].getMessage()
    assert "db channel up to date dialect=sqlite" in text  # quiet at INFO on a no-op open


def test_a_dry_run_plans_without_touching_the_database(channel: Path) -> None:
    conn = _sqlite()
    conn.execute("INSERT INTO repository (url, public) VALUES ('https://example.com/r', 1)")

    planned = migrations.run_upgrades(conn, "sqlite", root=channel, dry_run=True)
    assert [u.name for u in planned] == ["0001_add_note"]

    assert migrations.applied_upgrades(conn, "sqlite") == {}  # no stamp table was created
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("SELECT note FROM repository")  # and no DDL ran


def test_a_shape_that_arrived_by_hand_fails_as_a_channel_error(channel: Path) -> None:
    conn = _sqlite()
    conn.execute("ALTER TABLE repository ADD COLUMN note TEXT")  # applied by hand, no stamp

    with pytest.raises(migrations.MigrationError, match="without a stamp") as raised:
        migrations.run_upgrades(conn, "sqlite", root=channel)

    assert isinstance(raised.value.__cause__, sqlite3.OperationalError)
    assert conn.execute("SELECT count(*) FROM db_upgrade").fetchone()[0] == 0


def test_destructive_sql_without_a_declared_reason_is_refused(tmp_path: Path) -> None:
    root = _write_channel(tmp_path, "0001_drop.sql", "DROP TABLE {table};")
    with pytest.raises(migrations.MigrationError, match="destructive SQL"):
        migrations.pending_upgrades("sqlite", {}, root=root)
    root = _write_channel(
        tmp_path / "b", "0001_dropcol.sql", "ALTER TABLE {table} DROP COLUMN note;"
    )
    with pytest.raises(migrations.MigrationError, match="destructive SQL"):
        migrations.pending_upgrades("sqlite", {}, root=root)
    # a block comment is not a hiding place
    root = _write_channel(
        tmp_path / "c", "0001_hidden.sql", "SELECT 1; /* later */ DROP TABLE {table};"
    )
    with pytest.raises(migrations.MigrationError, match="destructive SQL"):
        migrations.pending_upgrades("sqlite", {}, root=root)


def test_a_guard_clause_is_not_destructive_sql(tmp_path: Path) -> None:
    body = (
        "CREATE TABLE guard (id TEXT, FOREIGN KEY (id) REFERENCES {table} (id) ON DELETE RESTRICT);"
    )
    root = _write_channel(tmp_path, "0001_guard.sql", body)
    assert [u.name for u in migrations.pending_upgrades("sqlite", {}, root=root)] == ["0001_guard"]


def test_a_declared_destructive_upgrade_applies_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = _write_channel(
        tmp_path,
        "0001_supersede.sql",
        "-- destructive: repository superseded by repository_v2\nDROP TABLE {table};",
    )
    conn = _sqlite()
    with caplog.at_level(logging.WARNING, logger="traust_contracts.v1.migrations"):
        applied = migrations.run_upgrades(conn, "sqlite", root=root)

    assert [u.name for u in applied] == ["0001_supersede"]
    assert applied[0].destructive == "repository superseded by repository_v2"
    warned = [r for r in caplog.records if "DESTRUCTIVE" in r.message]
    assert len(warned) == 1
    assert "reason=repository superseded by repository_v2" in warned[0].getMessage()
    stamps = conn.execute("SELECT name, sha256 FROM db_upgrade").fetchall()
    assert [name for name, _ in stamps] == ["0001_supersede"]


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
    assert raced == []  # nothing ran here: the other open applied and stamped it
    assert conn.execute("SELECT count(*) FROM db_upgrade").fetchone()[0] == 1


def _postgres(postgres_dsn: str) -> Any:
    """An isolated database: these tests rebuild schemas from scratch, and the
    behavior suite already owns traust_test under xdist's loadfile distribution."""
    import psycopg

    admin = psycopg.connect(postgres_dsn, autocommit=True)
    try:
        admin.execute("DROP DATABASE IF EXISTS traust_migrations_test")
        admin.execute("CREATE DATABASE traust_migrations_test")
    finally:
        admin.close()
    return psycopg.connect(postgres_dsn, autocommit=True, dbname="traust_migrations_test")


def _drop_postgres(postgres_dsn: str) -> None:
    import psycopg

    admin = psycopg.connect(postgres_dsn, autocommit=True)
    try:
        admin.execute("DROP DATABASE IF EXISTS traust_migrations_test")
    finally:
        admin.close()


def test_postgres_stamps_applies_and_preserves(postgres_dsn: str, tmp_path: Path) -> None:
    try:
        import psycopg
    except ImportError:
        skip_postgres("psycopg is not installed")
    try:
        conn = _postgres(postgres_dsn)
    except psycopg.OperationalError:
        skip_postgres("local database is unavailable")
        return

    for module in MODULES:
        for path in module.bootstrap_files("postgres"):
            for statement in module.bootstrap_statements("postgres", path):
                conn.execute(statement)

    shipped = migrations.upgrade_files("postgres")
    try:
        applied = migrations.run_upgrades(conn, "postgres")  # fresh: the shipped channel
        assert [u.name for u in applied] == ["0001_repository_disposition"]
        stamps = conn.execute("SELECT name, sha256 FROM traust.db_upgrade").fetchall()
        assert stamps == [("0001_repository_disposition", _sha256(shipped[0]))]

        channel = _write_channel(tmp_path, "0002_add_note.sql", NOTE)
        for dialect in ("postgres", "sqlite"):  # the fixture channel carries the shipped scripts
            for path in migrations.upgrade_files(dialect):
                target = channel / dialect / "upgrades" / path.name
                target.write_bytes(path.read_bytes())
        for url in ("https://example.com/r1", "https://example.com/r2"):
            conn.execute("INSERT INTO traust.repository (url, public) VALUES (%s, true)", (url,))
        before = conn.execute("SELECT * FROM traust.repository").fetchall()

        applied = migrations.run_upgrades(conn, "postgres", root=channel)
        assert [u.name for u in applied] == ["0002_add_note"]

        after = conn.execute("SELECT * FROM traust.repository").fetchall()
        assert [row[:-1] for row in after] == before
        assert all(row[-1] is None for row in after)
        script = channel / "postgres" / "upgrades" / "0002_add_note.sql"
        stamps = conn.execute("SELECT name, sha256 FROM traust.db_upgrade").fetchall()
        assert ("0002_add_note", _sha256(script)) in stamps
        assert migrations.run_upgrades(conn, "postgres", root=channel) == []
        assert migrations.run_upgrades(conn, "postgres", root=channel) == []
    finally:
        conn.close()
        _drop_postgres(postgres_dsn)
