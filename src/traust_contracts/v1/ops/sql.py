"""Read authored SQL in deterministic table-then-view bootstrap order (ops).

The traust_ops namespace of the one-owner data model: traust's own
application state, written by continuous ops. Postgres: the traust_ops
schema. SQLite: `ops_` table prefixes, bootstrapped into the same database
file as the traust namespace. The db version itself is owned by
traust_contracts.v1.db.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts.paths import ops_dir
from traust_contracts.v1.db import REVISION
from traust_contracts.v1.sql import Dialect
from traust_contracts.v1.sql import bootstrap_files as _bootstrap_files
from traust_contracts.v1.sql import bootstrap_statements as bootstrap_statements

__all__ = [
    "CONTRACT_VERSION",
    "REVISION",
    "TABLE_ORDER",
    "VIEW_ORDER",
    "bootstrap_files",
    "bootstrap_statements",
]

CONTRACT_VERSION = "v1"

#: Tables other tables reference, in dependency order. Bootstraps after
#: storage (run_order references repository and artifact); run_order.sql
#: then closes the cycle, adding assessment.run_order_id's FK on Postgres.
TABLE_ORDER: tuple[str, ...] = (
    "run_batch",
    "run_order",
    "spend_event",
    "feed_snapshot",
    "assessment_input",
)

#: Views other views select FROM, in creation order. None yet.
VIEW_ORDER: tuple[str, ...] = ()


def bootstrap_files(dialect: Dialect) -> list[Path]:
    """Return dependency-ordered tables preceded by the namespace file."""
    return _bootstrap_files(
        ops_dir(),
        dialect,
        first_tables=TABLE_ORDER,
        view_order=VIEW_ORDER,
    )
