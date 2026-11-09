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
    "run_order_fork_scheduled_upgrade",
    "spend_event_metadata_upgrade",
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


def run_order_fork_scheduled_upgrade(dialect: Dialect) -> list[str]:
    """Load the explicit additive upgrade for a database missing run_order.fork_scheduled_at.

    Callers must inspect run_order first and apply these statements only when
    the column is absent. It applies whole (one transaction on SQLite; apply it outside
    an open one). Existing orders carry no stamp: none is inferred.
    """
    path = ops_dir() / dialect / "upgrades" / "run_order_fork_scheduled.sql"
    return list(bootstrap_statements(dialect, path))


def spend_event_metadata_upgrade(dialect: Dialect) -> list[str]:
    """Load the explicit additive upgrade for spend events missing adoption metadata.

    Inspect spend_event first: apply only when repository_id, repository_label,
    loc, batch, and note are all absent. SQLite owns its transaction; apply outside
    an open one. Postgres callers must apply the statements in one transaction.
    Existing events retain null metadata, with no canonical identity inferred.
    """
    path = ops_dir() / dialect / "upgrades" / "spend_event_metadata.sql"
    return list(bootstrap_statements(dialect, path))
