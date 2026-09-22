"""Read authored SQL in deterministic table-then-view bootstrap order."""

import json
import re
import sqlite3
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Literal

from traust_contracts.paths import storage_dir

Dialect = Literal["postgres", "sqlite"]


def metadata_object(pairs: list[tuple[str, object]]) -> dict:
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate storage metadata key")
        values[key] = value
    return values


def load_metadata() -> dict[str, str | int]:
    metadata = json.loads(
        (storage_dir() / "metadata.json").read_text(encoding="utf-8"),
        object_pairs_hook=metadata_object,
    )
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"contract_version", "revision", "baseline_id"}
        or metadata["contract_version"] != "v1"
        or type(metadata["revision"]) is not int
        or metadata["revision"] < 1
        or not isinstance(metadata["baseline_id"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", metadata["baseline_id"])
    ):
        raise ValueError("invalid storage metadata")
    return metadata


METADATA = load_metadata()
CONTRACT_VERSION = METADATA["contract_version"]
BASELINE_ID = METADATA["baseline_id"]
#: 3 (2026-09-19): ownership_current. Views are CREATE ... IF NOT EXISTS,
#: so an existing store keeps the definitions it was built with -- and the
#: pre-3 ones join subject_ownership raw, which double-counts every finding
#: once per corpus-registry import. Failing closed here is deliberate: a
#: store on the old revision may ALREADY be serving inflated numbers.
#: 4 (2026-09-19): threat + priv_profile tables and their views. Revision 3
#: covered an intermediate priv_profile shape that carried the summary counts
#: as columns; 0.18.2 moved them into operator_privilege. Tables and views are
#: CREATE ... IF NOT EXISTS, so a store built on that shape keeps it and reads
#: the lifted columns as NULL -- silently, since the upsert simply stops
#: filling them. Same failure mode as revision 2, so the same refusal.
#: 5 (2026-09-19): layer_event -- the TIME DIMENSION. The ledger's dated
#: transition stream was ingested and discarded (layer_metadata kept only
#: repo/created/merkle_root), so a store on revision 4 has no history table
#: at all and every trend, MTTR and SLA view over it returns nothing.
#: 6 (2026-09-19): sla_threshold, and finding_sla now honours the policy.
#: A store on 5 has a finding_sla with no threshold and no breach column.
#: 7 (2026-09-19): sla_clock. The policy-level clock was resolved through
#: the per-severity join, so an unclocked severity aged from a different
#: timestamp than its siblings under one policy.
#: 8 (2026-09-19): pqc_posture and pqc_readiness_rollup.
#: 9 (2026-09-20): threat-model replaces threat-register as the family;
#: threat gains attack_refs and threat_current resolves per SUBJECT.
#: 10 (2026-09-20): validation_current and validation_exposure. The
#: evidence lens -- what actually happened when a claimed finding was
#: attempted against a running system -- had a projection and no view.
#: 11 (2026-09-20): validation supersession is per ENVIRONMENT. A hub run
#: and a spoke run are not re-runs of each other; collapsing on subject
#: alone deleted a 290-verdict disagreement on one subject alone.
#: 12 (2026-09-21): advisory_exposure. Blast radius fanned out of the
#: impact-analysis blob, one row per repo an advisory reaches, with the
#: evidence strength carried rather than collapsed.
#: 13 (2026-09-21): validation_finding gains the eight remaining fields
#: validated_findings[] declares, evidence_grade and soundness_flag among
#: them; advisory_exposure carries all 40 impact-analysis fields. A store
#: on 12 is missing columns, not just rows.
#: 14 (2026-09-21): the three secondary projections carry what their
#: schemas declare. report_finding held 6 of the 27 fields report.findings[]
#: declares, cloud_config_finding 9 of 22, layer_event 11 of 16 -- the
#: closure in revision 12/13 was scoped to DISPOSITION (validity,
#: resolution, fingerprint, ownership), which is what v_open needed, and
#: never to the analytical columns. category, cwes, locations, cvss,
#: description, remediation, effective_severity and risk_weight.lambda
#: among them: every axis a pattern, compliance or risk-index view cuts by.
#: A store on 13 is missing columns, not rows, and the upsert simply stops
#: filling them -- the same silent shape as revisions 2 and 4, so the same
#: refusal.
#: 15 (2026-09-21): the five dashboards that had no view now have one.
#: compliance_result, verification_finding, verification_regression,
#: remediation_source and attack_chain are new fan-out tables; the views
#: over them are compliance_posture, verification_current,
#: verification_regression_current, remediation_current and attack_coverage,
#: plus pattern_exposure over the columns revision 14 added. current_finding
#: gains category, cwes and effective_severity so a pattern rollup does not
#: re-join the finding tables. A store on 14 has neither the tables nor the
#: views, so every one of those consumers returns nothing.
REVISION = METADATA["revision"]


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
    root = storage_dir() / dialect
    schema = {path.name: path for path in (root / "schema").glob("*.sql")}
    first = [schema.pop(name) for name in ("artifact_evidence.sql", "artifact_binding.sql")]
    namespace = [root / "namespace.sql"] if dialect == "postgres" else []
    views = {path.name: path for path in (root / "views").glob("*.sql")}
    ordered = [views.pop(name) for name in VIEW_ORDER if name in views]
    return [
        *namespace,
        *first,
        *sorted(schema.values()),
        *ordered,
        *sorted(views.values()),
    ]


def reserved_objects(dialect: Dialect) -> set[str]:
    pattern = re.compile(
        r"CREATE\s+(?:UNIQUE\s+)?(?:TABLE|VIEW|INDEX)\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
        re.IGNORECASE,
    )
    return {
        name
        for path in bootstrap_files(dialect)
        for name in pattern.findall(path.read_text(encoding="utf-8"))
    }


def bootstrap_statements(dialect: Dialect, path: Path) -> Iterator[str]:
    """Yield driver-safe statements while preserving authored file boundaries."""
    sql = path.read_text(encoding="utf-8")
    if dialect == "postgres":
        yield sql
        return
    statement = ""
    for line in sql.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            yield statement
            statement = ""
    if statement.strip():
        raise ValueError(f"incomplete SQLite statement in {path.name}")
