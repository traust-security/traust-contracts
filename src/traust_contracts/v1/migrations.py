"""The database upgrade channel: ordered scripts, hash-stamped on the database.

The db contract ships as one unit (see traust_contracts.v1.db): the current
schema files are the baseline, and the channel starts empty. A later change
to an existing database's shape lands as a script in
db/v1/migrations/<dialect>/upgrades/NNNN_slug.sql rather than an edit readers
can miss. A script is four-digit, gapless from 0001, dialect-paired,
data-preserving - destructive SQL (DROP, TRUNCATE, DELETE) is rare, deliberate
and declared with a '-- destructive: <reason>' line the runner refuses to
load without - and carries no transaction
statements - the runner owns those, applying each script whole with its stamp
in one transaction.

The stamp is the sha256 of the file's bytes: the only record of what ran. A
shipped script is immutable; one whose hash no longer matches its stamp is
refused (fix forward with a new script), and so is a stamp whose script the
channel no longer ships. A database with no stamp table predates the runner:
version 0, brought on by `stamp_channel` - presumed current, stamped at the
head - rather than migrated.

The runner executes over a DBAPI connection in autocommit mode (sqlite3
isolation_level=None, psycopg autocommit=True) and manages its own
transactions. Concurrent opens are safe: an apply whose stamp insert loses a
race rolls back, re-reads, and skips a script another process applied first.

The channel also runs backward: an upgrade may ship a paired down script
(``<dialect>/downgrades/NNNN_slug.sql``, the same name), and
``run_downgrades`` rolls back the most recently applied scripts head first,
whole and transactionally, removing each stamp with its down. A script that
declared destructive work never rolls back - what it removed is gone - and
one without a down file never does; the whole requested range is validated
before anything runs.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
import time
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
    "run_downgrades",
    "run_upgrades",
    "stamp_channel",
    "stamp_table_statements",
    "upgrade_files",
]

_NAME = re.compile(r"\A([0-9]{4})_([a-z][a-z0-9_]*)\Z")
# Statement-initial transaction statements, anywhere in a file - postgres loads a
# whole file as one statement, so a per-statement check only saw the first token.
# A statement start is the file start or a semicolon, never a bare line start: a
# trigger body's BEGIN on its own line is mid-statement.
_TRANSACTION = re.compile(
    r"(?im)(?:\A|;)\s*(?:BEGIN(?:\s+IMMEDIATE)?|START\s+TRANSACTION|COMMIT|ROLLBACK)\b"
)
# Statement-initial DROP/TRUNCATE/DELETE, or a DROP COLUMN anywhere.
_DESTRUCTIVE = re.compile(r"(?im)(?:\A|;)\s*(?:DROP|TRUNCATE|DELETE)\b|\bDROP\s+COLUMN\b")
_DESTRUCTIVE_MARKER = "-- destructive:"

_STAMP_TABLE: dict[str, str] = {"postgres": "traust.db_upgrade", "sqlite": "db_upgrade"}
_BEGIN: dict[str, str] = {"postgres": "BEGIN", "sqlite": "BEGIN IMMEDIATE"}

log = logging.getLogger(__name__)
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
    destructive: str | None = None


def _code(sql: str) -> str:
    """Authored SQL with ``--`` lines and ``/* … */`` blocks removed, for scans."""
    without_blocks = re.sub(r"/\*.*?\*/", "", sql, flags=re.S)
    return "\n".join(
        line for line in without_blocks.splitlines() if not line.lstrip().startswith("--")
    )


def _destructive_reason(sql: str) -> str | None:
    """The reason a destructive script declares, or None when it declares none."""
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(_DESTRUCTIVE_MARKER):
            reason = stripped.split(":", 1)[1].strip()
            if reason:
                return reason
    return None


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
    return _upgrades_with_state(dialect, applied, root=root)[1]


def _upgrades_with_state(
    dialect: Dialect, applied: Mapping[str, str], *, root: Path | None = None
) -> tuple[list[Upgrade], list[Upgrade]]:
    """(applied, pending) shipped scripts, each in channel order; drift is
    refused either way - the shared read behind planning, running and rolling
    back."""
    paths = upgrade_files(dialect, root=root)
    authored = {path.stem for path in paths}
    for name in sorted(set(applied) - authored):
        raise MigrationError(f"the database ran upgrade {name}, which the channel no longer ships")
    done: list[Upgrade] = []
    pending: list[Upgrade] = []
    for path in paths:
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        stamped = applied.get(path.stem)
        if stamped is not None and stamped != sha256:
            raise MigrationError(
                f"upgrade {path.stem} changed after databases applied it: "
                "fix forward with a new script"
            )
        upgrade = _load_upgrade(dialect, path)
        (done if stamped is not None else pending).append(upgrade)
    return done, pending


def _load_upgrade(dialect: Dialect, path: Path) -> Upgrade:
    """One authored script, loaded and checked: whole-file hash, split
    statements, no transaction statements of its own, destructive SQL only
    with a declared reason."""
    sql = path.read_text(encoding="utf-8")
    code = _code(sql)
    if _TRANSACTION.search(code):
        raise MigrationError(
            f"{path.name} carries its own transaction statement; the runner owns those"
        )
    reason = _destructive_reason(sql)
    if _DESTRUCTIVE.search(code) and reason is None:
        raise MigrationError(
            f"{path.name} carries destructive SQL (DROP, TRUNCATE, DELETE) without a "
            "declared reason: add a '-- destructive: <reason>' line - destructive "
            "scripts are deliberate, reviewed, and rare"
        )
    return Upgrade(
        path.stem,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        tuple(bootstrap_statements(dialect, path)),
        destructive=reason,
    )


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
        planned = pending_upgrades(dialect, applied_upgrades(conn, dialect), root=root)
        log.info(
            "db channel dry run dialect=%s planned=%d names=%s",
            dialect,
            len(planned),
            [upgrade.name for upgrade in planned],
            extra={
                "operation": "db.upgrade.dry_run",
                "outcome": "planned",
                "count": len(planned),
            },
        )
        return planned
    if not conn.execute(_EXISTS[dialect]).fetchall():
        try:
            for statement in stamp_table_statements(dialect):
                conn.execute(statement)
        except Exception:
            if not conn.execute(_EXISTS[dialect]).fetchall():  # a concurrent open won the create
                raise
    pending = pending_upgrades(dialect, applied_upgrades(conn, dialect), root=root)
    if not pending:
        log.debug(
            "db channel up to date dialect=%s",
            dialect,
            extra={"operation": "db.upgrade", "outcome": "up_to_date"},
        )
        return pending
    log.info(
        "db channel applying dialect=%s pending=%d names=%s",
        dialect,
        len(pending),
        [upgrade.name for upgrade in pending],
        extra={"operation": "db.upgrade", "outcome": "applying", "count": len(pending)},
    )
    ran: list[Upgrade] = []
    for upgrade in pending:
        if upgrade.destructive:
            log.warning(
                "db upgrade DESTRUCTIVE dialect=%s name=%s sha256=%s reason=%s",
                dialect,
                upgrade.name,
                upgrade.sha256,
                upgrade.destructive,
                extra={"operation": "db.upgrade", "outcome": "destructive"},
            )
        started = time.perf_counter()
        try:
            conn.execute(_BEGIN[dialect])
            for statement in upgrade.statements:
                conn.execute(statement)
            conn.execute(
                f"INSERT INTO {_STAMP_TABLE[dialect]} (name, sha256) "
                f"VALUES ('{upgrade.name}', '{upgrade.sha256}')"
            )
            conn.execute("COMMIT")
        except Exception as error:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            if applied_upgrades(conn, dialect).get(upgrade.name) == upgrade.sha256:
                log.info(
                    "db upgrade raced away dialect=%s name=%s - a concurrent open applied it first",
                    dialect,
                    upgrade.name,
                    extra={"operation": "db.upgrade", "outcome": "raced"},
                )
                continue  # a concurrent open applied it first
            log.error(
                "db upgrade failed dialect=%s name=%s sha256=%s error_type=%s error=%s",
                dialect,
                upgrade.name,
                upgrade.sha256,
                type(error).__name__,
                error,
                extra={
                    "operation": "db.upgrade",
                    "outcome": "failed",
                    "error_type": type(error).__name__,
                },
            )
            raise MigrationError(
                f"upgrade {upgrade.name} failed to apply and no concurrent open stamped it: "
                "the script is wrong, or the shape is already there without a stamp - "
                "applied by hand - so recreate the database or fix forward with a new script"
            ) from error
        duration_ms = (time.perf_counter() - started) * 1000
        log.info(
            "db upgrade applied dialect=%s name=%s sha256=%s statements=%d duration_ms=%.1f",
            dialect,
            upgrade.name,
            upgrade.sha256,
            len(upgrade.statements),
            duration_ms,
            extra={
                "operation": "db.upgrade",
                "outcome": "applied",
                "count": len(upgrade.statements),
                "duration_ms": duration_ms,
            },
        )
        ran.append(upgrade)
    return ran


def _down_file(dialect: Dialect, name: str, *, root: Path | None = None) -> Path | None:
    """The paired down script for an upgrade, when the channel ships one:
    ``<dialect>/downgrades/<name>.sql``, the same name as its upgrade."""
    path = (root or migrations_dir()) / dialect / "downgrades" / f"{name}.sql"
    return path if path.is_file() else None


def run_downgrades(
    conn: _Connection, dialect: Dialect, *, steps: int = 1, root: Path | None = None
) -> list[Upgrade]:
    """Roll back the most recently applied scripts, head first, whole and
    transactionally - the channel runs forward and backward.

    A script rolls back only when its upgrade shipped a paired down script
    (``downgrades/NNNN_slug.sql``); one that declared destructive work never
    does - what it removed is gone - and one without a down file never does.
    The whole requested range is validated before anything runs, so a refusal
    leaves the store exactly as it was. A down script's own DROPs are its
    point - restoring the pre-upgrade shape - so only the transaction-statement
    rule applies to it. Each down runs whole with its stamp's removal in one
    transaction; a race that loses the rollback to a concurrent open is a
    no-op, mirroring the upgrades. Returns what rolled back, head first.
    """
    if steps < 1:
        raise MigrationError(f"downgrade steps are at least 1, not {steps}")
    if not conn.execute(_EXISTS[dialect]).fetchall():
        return []  # nothing applied: nothing to roll back
    done, _ = _upgrades_with_state(dialect, applied_upgrades(conn, dialect), root=root)
    candidates: list[tuple[Upgrade, Path]] = []
    for upgrade in reversed(done):
        if len(candidates) == steps:
            break
        if upgrade.destructive:
            raise MigrationError(
                f"upgrade {upgrade.name} declared destructive work ({upgrade.destructive}): "
                "what it removed is gone - it cannot roll back"
            )
        down = _down_file(dialect, upgrade.name, root=root)
        if down is None:
            raise MigrationError(
                f"upgrade {upgrade.name} ships no down script (downgrades/{upgrade.name}.sql): "
                "it cannot roll back"
            )
        candidates.append((upgrade, down))
    rolled: list[Upgrade] = []
    for upgrade, down in candidates:
        sql = down.read_text(encoding="utf-8")
        if _TRANSACTION.search(_code(sql)):
            raise MigrationError(
                f"{down.name} carries its own transaction statement; the runner owns those"
            )
        statements = tuple(bootstrap_statements(dialect, down))
        started = time.perf_counter()
        try:
            conn.execute(_BEGIN[dialect])
            for statement in statements:
                conn.execute(statement)
            conn.execute(f"DELETE FROM {_STAMP_TABLE[dialect]} WHERE name = '{upgrade.name}'")
            conn.execute("COMMIT")
        except Exception as error:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            if applied_upgrades(conn, dialect).get(upgrade.name) is None:
                log.info(
                    "db downgrade raced away dialect=%s name=%s - rolled back by a concurrent open",
                    dialect,
                    upgrade.name,
                    extra={"operation": "db.downgrade", "outcome": "raced"},
                )
                continue
            log.error(
                "db downgrade failed dialect=%s name=%s error_type=%s error=%s",
                dialect,
                upgrade.name,
                type(error).__name__,
                error,
                extra={"operation": "db.downgrade", "outcome": "failed"},
            )
            raise MigrationError(
                f"downgrade {upgrade.name} failed to apply and no concurrent open rolled it "
                "back first: the script is wrong, or the shape is not what its upgrade left"
            ) from error
        duration_ms = (time.perf_counter() - started) * 1000
        log.info(
            "db downgrade applied dialect=%s name=%s sha256=%s statements=%d duration_ms=%.1f",
            dialect,
            upgrade.name,
            upgrade.sha256,
            len(statements),
            duration_ms,
            extra={
                "operation": "db.downgrade",
                "outcome": "applied",
                "count": len(statements),
                "duration_ms": duration_ms,
            },
        )
        rolled.append(upgrade)
    return rolled


def stamp_channel(
    conn: _Connection, dialect: Dialect, *, root: Path | None = None
) -> list[Upgrade]:
    """Mark every shipped script as applied, in one transaction: a store from
    before the channel, presumed current, starts on it at the head.

    The stamping is the channel's first act on such a store - the marker that it
    is on the routine, at the start. Nothing is verified about the live shape: a
    store someone changed by hand is that operator's to resolve when a later
    script refuses what does not fit. A store already on the channel is never
    stamped over: known and current is a no-op, known and behind is refused (run
    the channel, never stamp over pending work), and drift is refused either
    way. A concurrent open that wins the stamping makes this one a no-op.
    Returns what it stamped - nothing when the channel already knows the store.
    """
    if not conn.execute(_EXISTS[dialect]).fetchall():
        try:
            for statement in stamp_table_statements(dialect):
                conn.execute(statement)
        except Exception:
            if not conn.execute(_EXISTS[dialect]).fetchall():  # a concurrent open won the create
                raise
    applied = applied_upgrades(conn, dialect)
    if applied:
        remaining = pending_upgrades(dialect, applied, root=root)  # drift refused inside
        if remaining:
            raise MigrationError(
                "the store is on the channel and behind ("
                f"{', '.join(upgrade.name for upgrade in remaining)}): run the channel, "
                "never stamp over its pending work"
            )
        log.debug(
            "db channel stamp dialect=%s already known",
            dialect,
            extra={"operation": "db.channel.stamp", "outcome": "known"},
        )
        return []
    to_stamp = pending_upgrades(dialect, {}, root=root)
    if not to_stamp:
        return []
    try:
        conn.execute(_BEGIN[dialect])
        for upgrade in to_stamp:
            conn.execute(
                f"INSERT INTO {_STAMP_TABLE[dialect]} (name, sha256) "
                f"VALUES ('{upgrade.name}', '{upgrade.sha256}')"
            )
        conn.execute("COMMIT")
    except Exception:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        stamped = applied_upgrades(conn, dialect)
        if all(stamped.get(upgrade.name) == upgrade.sha256 for upgrade in to_stamp):
            log.info(  # a concurrent open stamped the store first: nothing of ours to do
                "db channel stamp raced away dialect=%s names=%s",
                dialect,
                [upgrade.name for upgrade in to_stamp],
                extra={"operation": "db.channel.stamp", "outcome": "raced"},
            )
            return []
        if not stamped:
            # nothing committed and the stamp table is this attempt's empty
            # bookkeeping: drop it, restoring the pre-channel state a retry
            # expects - an empty table must never read as an enrolled store
            conn.execute(f"DROP TABLE {_STAMP_TABLE[dialect]}")
        raise
    log.info(
        "db channel stamped dialect=%s scripts=%d names=%s - presumed current, at the head",
        dialect,
        len(to_stamp),
        [upgrade.name for upgrade in to_stamp],
        extra={"operation": "db.channel.stamp", "outcome": "stamped", "count": len(to_stamp)},
    )
    return to_stamp
