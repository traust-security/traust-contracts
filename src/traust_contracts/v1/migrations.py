"""The database upgrade channel: ordered scripts, hash-stamped on the database.

The db contract ships as one unit (see traust_contracts.v1.db): the current
schema files are the baseline, and the channel starts empty. A later change
to an existing database's shape lands as a script in
db/v1/migrations/<dialect>/upgrades/NNNN_slug.sql rather than an edit readers
can miss. A script is four-digit, gapless from 0001, dialect-paired, additive
only (never DROP, never DELETE: no data is lost), and carries no transaction
statements - the runner owns those, applying each script whole with its stamp
in one transaction.

The stamp is the sha256 of the file's bytes: the only record of what ran. A
shipped script is immutable; one whose hash no longer matches its stamp is
refused (fix forward with a new script), and so is a stamp whose script the
channel no longer ships. A database with no stamp table predates the runner:
version 0, recreated rather than migrated (db/v1/traust/README.md).

The runner executes over a DBAPI connection in autocommit mode (sqlite3
isolation_level=None, psycopg autocommit=True) and manages its own
transactions. Concurrent opens are safe: an apply whose stamp insert loses a
race rolls back, re-reads, and skips a script another process applied first.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from traust_contracts.paths import migrations_dir
from traust_contracts.v1.sql import Dialect, bootstrap_statements

__all__ = [
    "MigrationError",
    "Upgrade",
    "applied_upgrades",
    "pending_upgrades",
    "run_upgrades",
    "stamp_table_statements",
    "upgrade_files",
]

_NAME = re.compile(r"\A([0-9]{4})_([a-z][a-z0-9_]*)\Z")
_TRANSACTION = {"BEGIN", "BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"}

_STAMP_TABLE: dict[str, str] = {"postgres": "traust.db_upgrade", "sqlite": "db_upgrade"}
_BEGIN: dict[str, str] = {"postgres": "BEGIN", "sqlite": "BEGIN IMMEDIATE"}
_EXISTS: dict[str, str] = {
    "postgres": (
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'traust' AND table_name = 'db_upgrade'"
    ),
    "sqlite": "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'db_upgrade'",
}


class MigrationError(Exception):
    """The channel, or a database's stamps, violate the upgrade contract."""


@dataclass(frozen=True)
class Upgrade:
    """One authored upgrade script, loaded and ready to apply whole."""

    name: str
    sha256: str
    statements: tuple[str, ...]


class _Connection(Protocol):
    """The DBAPI surface the runner uses: autocommit execute, no params."""

    def execute(self, sql: str) -> Any: ...


def stamp_table_statements(dialect: Dialect) -> list[str]:
    """Load the stamp-table DDL, which the runner - not bootstrap - creates."""
    path = migrations_dir() / dialect / "stamp_table.sql"
    return list(bootstrap_statements(dialect, path))


def upgrade_files(dialect: Dialect, *, root: Path | None = None) -> list[Path]:
    """Ordered upgrade scripts for a dialect; the channel may be empty.

    Names are NNNN_slug.sql, unique, four-digit and gapless from 0001, so the
    order scripts run in is the order they are read in. A missing upgrades
    directory is an empty channel, not an error.
    """
    directory = (root or migrations_dir()) / dialect / "upgrades"
    paths = sorted(directory.glob("*.sql")) if directory.is_dir() else []
    numbers = []
    for path in paths:
        if _NAME.match(path.stem) is None:
            raise MigrationError(f"upgrade names are NNNN_slug.sql: {path.name}")
        numbers.append(int(path.stem[:4]))
    if numbers != list(range(1, len(numbers) + 1)):
        raise MigrationError(
            f"upgrade numbering is not gapless from 0001: {[p.name for p in paths]}"
        )
    return paths


def pending_upgrades(
    dialect: Dialect, applied: Mapping[str, str], *, root: Path | None = None
) -> list[Upgrade]:
    """The scripts a database has not run, in order; drift is refused either way.

    ``applied`` maps script name to the sha256 stamped on the database. A
    script whose hash differs from its stamp changed after databases applied
    it; a stamp with no script in the channel was removed from it. Both are
    contract violations, not re-runs.
    """
    paths = upgrade_files(dialect, root=root)
    authored = {path.stem for path in paths}
    for name in sorted(set(applied) - authored):
        raise MigrationError(f"the database ran upgrade {name}, which the channel no longer ships")
    pending: list[Upgrade] = []
    for path in paths:
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        stamped = applied.get(path.stem)
        if stamped == sha256:
            continue
        if stamped is not None:
            raise MigrationError(
                f"upgrade {path.stem} changed after databases applied it: "
                "fix forward with a new script"
            )
        statements = tuple(bootstrap_statements(dialect, path))
        for statement in statements:
            if statement.split(";", 1)[0].strip().upper() in _TRANSACTION:
                raise MigrationError(
                    f"{path.name} carries its own transaction statement; the runner owns those"
                )
        pending.append(Upgrade(path.stem, sha256, statements))
    return pending


def applied_upgrades(conn: _Connection, dialect: Dialect) -> dict[str, str]:
    """Read the stamp table: script name to stamped sha256.

    No stamp table means version 0: every authored script is pending.
    """
    if not conn.execute(_EXISTS[dialect]).fetchall():
        return {}
    rows = conn.execute(f"SELECT name, sha256 FROM {_STAMP_TABLE[dialect]}").fetchall()
    return {str(name): str(sha) for name, sha in rows}


def run_upgrades(
    conn: _Connection, dialect: Dialect, *, dry_run: bool = False, root: Path | None = None
) -> list[Upgrade]:
    """Apply pending upgrades, each whole with its stamp in one transaction.

    Returns what ran - or, with ``dry_run``, what would run, touching nothing:
    no DDL, not even the stamp table. Scripts come from ``root`` when given,
    else the shipped channel; the stamp table is always the shipped one.
    """
    if dry_run:
        return pending_upgrades(dialect, applied_upgrades(conn, dialect), root=root)
    for statement in stamp_table_statements(dialect):
        conn.execute(statement)
    pending = pending_upgrades(dialect, applied_upgrades(conn, dialect), root=root)
    for upgrade in pending:
        try:
            conn.execute(_BEGIN[dialect])
            for statement in upgrade.statements:
                conn.execute(statement)
            conn.execute(
                f"INSERT INTO {_STAMP_TABLE[dialect]} (name, sha256) "
                f"VALUES ('{upgrade.name}', '{upgrade.sha256}')"
            )
            conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            if applied_upgrades(conn, dialect).get(upgrade.name) == upgrade.sha256:
                continue  # a concurrent open applied it first
            raise
    return pending
