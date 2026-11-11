"""Regenerate a Ledger v1 DDL model doc from the checked-in SQL.

Reads db/v1/traust_ledger/{sqlite,postgres}/schema/*.sql and emits the table model as a
single Mermaid class diagram. Ledger has no artifact profiles or views — it is
a flat, FK-ordered table set — so this stays a plain rendering of `TABLE_ORDER`
over the shared `traust_contracts.v1.ddl_model` primitives. Nothing here is
recalled; run it whenever the DDL moves.

    python3 -m traust_contracts.v1.ledger.build_ledger_ddl_model \
        --out ../traust/docs/ledger-v1-ddl-model.md
"""

from __future__ import annotations

import argparse
from pathlib import Path

from traust_contracts.paths import ledger_dir
from traust_contracts.v1.ddl_model import load_tables, render_diagram
from traust_contracts.v1.ledger.sql import TABLE_ORDER


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out", type=Path, required=True, help="e.g. ../traust/docs/ledger-v1-ddl-model.md"
    )
    args = ap.parse_args()
    tables = load_tables(ledger_dir())
    out = args.out

    lines = [
        "# db/v1/traust_ledger DDL — table model",
        "",
        "<!-- GENERATED FILE — do not edit by hand; edits are overwritten on the next run.",
        "     Regenerate from a checkout when the db/v1/traust_ledger DDL changes:",
        "       python -m traust_contracts.v1.ledger.build_ledger_ddl_model \\",
        "         --out ../traust/docs/ledger-v1-ddl-model.md",
        "     To change the prose, edit",
        "     src/traust_contracts/v1/ledger/build_ledger_ddl_model.py, then regenerate. -->",
        "",
        f"**{len(tables)} tables, one dialect pair.** SQLite and PostgreSQL declare",
        "the same tables, the same column names, in the same foreign-key order.",
        "Only TYPES diverge where the dialect demands it, shown as",
        "`sqlite|postgres` (`INTEGER|BIGINT`, `TEXT|TIMESTAMPTZ`). PostgreSQL",
        "relations live in the fixed `traust_ledger` schema; SQLite uses the",
        "database file as its namespace.",
        "",
        "Legend: `+` primary key, arrows are declared foreign keys.",
        "",
        f"## Tables ({len(tables)})",
        "",
        render_diagram(list(TABLE_ORDER), tables, direction="TB"),
        "",
    ]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(tables)} tables)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
