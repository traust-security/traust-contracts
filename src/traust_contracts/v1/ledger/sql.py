"""Read authored Ledger SQL in deterministic bootstrap order.

The traust_ledger namespace of the one-owner data model: append-only proof
of decisions - one Merkle tree and signature per layer, many layers per
repository. Bootstraps after the traust namespace, whose repository,
repository_ref and decision rows it references. The db version itself is
owned by traust_contracts.v1.db.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts.paths import ledger_dir
from traust_contracts.v1.db import REVISION
from traust_contracts.v1.sql import Dialect
from traust_contracts.v1.sql import bootstrap_files as _bootstrap_files
from traust_contracts.v1.sql import bootstrap_statements as bootstrap_statements

__all__ = [
    "CONTRACT_VERSION",
    "POSTGRES_SCHEMA",
    "REVISION",
    "TABLE_ORDER",
    "bootstrap_files",
    "bootstrap_statements",
]

CONTRACT_VERSION = "v1"
POSTGRES_SCHEMA = "traust_ledger"

#: Tables other tables reference, in dependency order; the complete table
#: inventory.
TABLE_ORDER: tuple[str, ...] = (
    "layers",
    "events",
)


def bootstrap_files(dialect: Dialect, version: str = "v1") -> list[Path]:
    """Return the namespace followed by authored tables in dependency order."""
    return _bootstrap_files(
        ledger_dir(version), dialect, first_tables=TABLE_ORDER, exact_tables=True
    )
