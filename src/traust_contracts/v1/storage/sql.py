"""Read authored SQL in deterministic table-then-view bootstrap order."""

import re
from functools import cache
from pathlib import Path

from traust_contracts.paths import storage_dir
from traust_contracts.v1.sql import Dialect
from traust_contracts.v1.sql import bootstrap_files as _bootstrap_files
from traust_contracts.v1.sql import bootstrap_statements as bootstrap_statements

CONTRACT_VERSION = "v1"
#: Storage schema revision, stamped in traust_storage_meta and checked on
#: open. Bump it whenever the DDL changes, so a database created under an
#: older schema is refused instead of failing on its first read or write.
#: 1: baseline (0.50.0). Rebaselined: the registry, report_finding.blocked_external
#: and every earlier change are part of revision 1. Databases created under any
#: earlier schema are recreated, not migrated.
#: Each later step adds migrations/NNN_to_NNN+1.sql; Store.migrate() runs them.
#: 2: cached Portfolio forge observations (XWING-2214).
REVISION = 2


@cache
def query(dialect: Dialect, filename: str) -> str:
    return (storage_dir() / dialect / "queries" / filename).read_text(encoding="utf-8")


#: Views that other views select FROM, in the order they must be created.
#: Alphabetical order is not dependency order -- `current_finding` sorts
#: before `report_current` but selects from it, and PostgreSQL resolves a
#: view's references at CREATE time, so the glob order alone fails there
#: while silently succeeding on SQLite.
#: THE SCHEMA IS THE REFERENCE FOR WHAT A VIEW MUST CARRY. A view is not
#: correct because its numbers match another projection -- two projections
#: dropping the same fields agree perfectly and are both wrong. Check it
#: against the artifact's JSON Schema, and let
#: tests/test_view_contract_coverage.py fail you if a declared field never
#: reaches SQL. See storage/v1/README.md, "The schema is the reference".
VIEW_ORDER: tuple[str, ...] = (
    "binding_current.sql",
    "report_current.sql",
    "ownership_current.sql",
    "current_finding.sql",
    "threat_current.sql",
    "validation_current.sql",
    "finding_first_seen.sql",
    "finding_timeline.sql",
    "pqc_posture.sql",
    "sla_clock.sql",
    "sla_threshold.sql",
    # Reads current_finding, so it must follow it.
    "pattern_exposure.sql",
    # Reads threat_current and current_binding.
    "attack_coverage.sql",
)


def bootstrap_files(dialect: Dialect) -> list[Path]:
    """Return dependency-ordered tables followed by dependency-ordered views."""
    return _bootstrap_files(
        storage_dir(),
        dialect,
        first_tables=(
            "product",
            "repo",
            "product_repo",
            "artifact_evidence",
            "artifact_binding",
            "artifact_location",
        ),
        view_order=VIEW_ORDER,
    )


def migration_files(dialect: Dialect, from_revision: int) -> list[Path]:
    """Return the delta files that take ``from_revision`` to ``REVISION``, in order.

    A delta file holds only what re-running the schema files cannot do:
    ALTER, DROP, data UPDATEs. New tables, indexes and views come from the
    schema and view files themselves, which Store.migrate() re-runs.
    """
    directory = storage_dir() / dialect / "migrations"
    paths = [
        directory / f"{step:03d}_to_{step + 1:03d}.sql" for step in range(from_revision, REVISION)
    ]
    missing = [path.name for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing {dialect} migration: {', '.join(missing)}")
    return paths


_VIEW_NAME = re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.]+)")


def view_names(dialect: Dialect) -> list[str]:
    """Names of the views storage owns, in creation order, read from the SQL."""
    names = []
    for path in bootstrap_files(dialect):
        if path.parent.name == "views":
            match = _VIEW_NAME.search(path.read_text(encoding="utf-8"))
            if match is None:
                raise ValueError(f"no CREATE VIEW in {path.name}")
            names.append(match.group(1))
    return names
