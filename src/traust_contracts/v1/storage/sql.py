"""Read authored SQL in deterministic table-then-view bootstrap order.

The traust namespace of the one-owner data model: domain tables - inventory,
dependencies, assessments & findings. Each namespace owns its directory and
loader under db/v1/ - traust_ops and traust_ledger - with cross-schema FKs
as the contract between them on Postgres, and table prefixes (`ops_`,
`ledger_`) bootstrapped into one SQLite file. The db version itself is
owned by traust_contracts.v1.db.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts.paths import storage_dir
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
    "manifest_sbom_binding_upgrade",
]

CONTRACT_VERSION = "v1"

#: Tables other tables reference, in dependency order; the loader appends the
#: remaining schema files alphabetically, so a table must appear here whenever
#: another table's FK reaches it and alphabetical order would invert that.
#: Three FKs close cycles and are ALTERs on Postgres (SQLite does not check
#: parent existence at CREATE): sbom.artifact_id (added in artifact.sql),
#: repository_ref.manifest_sbom_assessment_id (added in assessment.sql), and
#: assessment.run_order_id (added by the ops bootstrap, since run_order
#: references storage tables back).
TABLE_ORDER: tuple[str, ...] = (
    "repository",
    "sbom",
    "repository_ref",
    "product",
    "release",
    "component",
    "team",
    "ownership",
    "advisory",
    "package",
    "dependency",
    "image",
    "advisory_package",
    "assessment",
    "artifact",
    "finding",
    "cwe",
    "finding_cwe",
    "finding_label",
    "finding_external_ref",
    "decision",
    "decision_approver",
    "review_item",
    "occurrence",
    "location",
    "remediation",
    "remediation_finding",
)

#: Views other views select FROM, in creation order (filenames), because
#: Postgres resolves a view's references at CREATE. retired.sql first drops the
#: views an older contract created.
VIEW_ORDER: tuple[str, ...] = (
    "retired.sql",
    "unowned.sql",
    "ownership_current.sql",
    "finding_primary_cwe.sql",
)


def bootstrap_files(dialect: Dialect) -> list[Path]:
    """Return dependency-ordered tables followed by dependency-ordered views."""
    return _bootstrap_files(
        storage_dir(),
        dialect,
        first_tables=TABLE_ORDER,
        view_order=VIEW_ORDER,
    )


def manifest_sbom_binding_upgrade(dialect: Dialect) -> list[str]:
    """Load the explicit additive upgrade for a database missing the scan column.

    Callers must inspect repository_ref first and apply these statements only
    when manifest_sbom_assessment_id is absent. This does not run on bootstrap
    or infer bindings for existing SBOMs: old coverage remains unknown.
    """
    path = storage_dir() / dialect / "upgrades" / "manifest_sbom_binding.sql"
    return list(bootstrap_statements(dialect, path))
