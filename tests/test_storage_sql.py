"""Authored SQL execution, dependency order, profiles, and package resources."""

import json
import re
import sqlite3
import tomllib
from pathlib import Path

from storage_samples import (
    ALL_SECONDARY_PROJECTION_TABLES,
    FAMILIES,
    INVENTORY_TABLES,
    PROJECTION_TABLES,
    REGISTRY_TABLES,
    RUN_BOUND,
)

from traust_contracts.paths import storage_dir
from traust_contracts.v1.storage.sql import REVISION, bootstrap_files, bootstrap_statements

TABLES = {
    *REGISTRY_TABLES,
    *INVENTORY_TABLES,
    "artifact_evidence",
    "artifact_binding",
    "artifact_location",
    "traust_storage_meta",
    "portfolio_forge_facts",
    *PROJECTION_TABLES.values(),
    *ALL_SECONDARY_PROJECTION_TABLES,
}
POSTGRES_SCHEMA = "traust_storage"


def test_storage_revision_matches_migration_placeholder() -> None:
    # Revision 1 is the rebaselined schema (0.50.0). Every later step needs a
    # delta file so Store.migrate() can build up to REVISION; the next step's
    # file exists as a placeholder.
    assert REVISION == 5
    for dialect in ("sqlite", "postgres"):
        migrations = storage_dir() / dialect / "migrations"
        assert sorted(p.name for p in migrations.glob("*.sql")) == [
            f"{step:03d}_to_{step + 1:03d}.sql" for step in range(1, REVISION + 1)
        ]


POSTGRES_RELATIONS = {
    *TABLES,
    "attack_coverage",
    "compliance_posture",
    "pattern_exposure",
    "remediation_current",
    "verification_current",
    "verification_regression_current",
    "census_exposure",
    "census_population",
    "current_binding",
    "current_finding",
    "distinct_exposure",
    "findings_summary",
    "hardening_findings",
    "open_findings",
    "report_current",
}
POSTGRES_RELATION_REFERENCE = re.compile(
    r"(?:CREATE TABLE IF NOT EXISTS|CREATE OR REPLACE VIEW|INSERT INTO|REFERENCES|FROM|JOIN|"
    r"UPDATE|ALTER TABLE|DELETE FROM)\s+([a-z_][a-z0-9_.]*)",
    re.IGNORECASE,
)
POSTGRES_INDEX_REFERENCE = re.compile(
    r"CREATE (?:UNIQUE )?INDEX IF NOT EXISTS [a-z_][a-z0-9_]*\s+ON\s+"
    r"([a-z_][a-z0-9_.]*)",
    re.IGNORECASE,
)
DIALECTS = ("sqlite", "postgres")
VIEW_DECLARATION = re.compile(
    r"CREATE (?:OR REPLACE )?VIEW (?:IF NOT EXISTS )?(?:traust_storage\.)?([a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)
COLUMN_ALIAS = re.compile(r"\bAS\s+([a-z_][a-z0-9_]*)\s*$", re.IGNORECASE)
SELECT_KEYWORD = re.compile(r"\bSELECT\b", re.IGNORECASE)


def _uncommented(sql: str) -> str:
    """Drop line comments. No storage SQL puts `--` inside a string literal."""
    return "\n".join(line.split("--")[0] for line in sql.splitlines())


def _top_level_projection(sql: str) -> str:
    """The text between a view's own SELECT and its own FROM, ignoring subqueries."""
    body = _uncommented(sql)
    select = SELECT_KEYWORD.search(body)
    assert select, "view declares no SELECT"
    depth = 0
    index = select.end()
    while index < len(body):
        character = body[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif (
            depth == 0
            and body[index : index + 4].upper() == "FROM"
            and not body[index - 1].isalnum()
            and not body[index + 4].isalnum()
        ):
            return body[select.end() : index]
        index += 1
    raise AssertionError("view declares no top-level FROM")


def _output_columns(sql: str) -> list[str]:
    """Output column names of a view: its alias, else the bare column, else `*`.

    Normalising to the *output* name is the point — the two dialects may reach
    columns through different table aliases, which a consumer never sees and
    must not be gated on.
    """
    items: list[str] = []
    current = ""
    depth = 0
    for character in _top_level_projection(sql):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            items.append(current)
            current = ""
        else:
            current += character
    items.append(current)
    columns = []
    for item in items:
        collapsed = " ".join(item.split())
        alias = COLUMN_ALIAS.search(collapsed)
        columns.append(alias.group(1) if alias else collapsed.rsplit(".", maxsplit=1)[-1])
    return columns


def _declared_views(dialect: str) -> dict[str, list[str]]:
    views = {}
    for path in sorted((storage_dir() / dialect / "views").glob("*.sql")):
        sql = path.read_text()
        declaration = VIEW_DECLARATION.search(sql)
        assert declaration, f"{path.name} declares no view"
        views[declaration.group(1)] = _output_columns(sql)
    return views


def test_view_names_are_read_from_the_sql_not_the_filename() -> None:
    """`views/binding_current.sql` declares a view called `current_binding`.

    Every parity check below keys on the declared name for that reason; one
    keyed on filenames would assert against an identifier no consumer can use.
    """
    for dialect in DIALECTS:
        names = set(_declared_views(dialect))
        assert names == {
            "attack_coverage",
            "compliance_posture",
            "pattern_exposure",
            "remediation_current",
            "verification_current",
            "verification_regression_current",
            "advisory_exposure",
            "census_exposure",
            "census_population",
            "current_binding",
            "current_finding",
            "current_finding_detail",
            "distinct_exposure",
            "exposure_trend",
            "finding_first_seen",
            "finding_sla",
            "finding_timeline",
            "ownership_current",
            "findings_summary",
            "hardening_findings",
            "open_findings",
            "operator_privilege",
            "pqc_posture",
            "pqc_readiness_rollup",
            "report_current",
            "sla_clock",
            "sla_threshold",
            "threat_current",
            "threat_exposure",
            "validation_current",
            "validation_exposure",
        }, dialect
        assert "binding_current" in {
            path.stem for path in (storage_dir() / dialect / "views").glob("*.sql")
        }


def test_view_output_columns_are_identical_across_dialects() -> None:
    """A dashboard is only backend-independent if its view returns one shape."""
    sqlite_views, postgres_views = (_declared_views(dialect) for dialect in DIALECTS)
    assert sorted(sqlite_views) == sorted(postgres_views)
    for name, columns in sqlite_views.items():
        assert columns == postgres_views[name], (
            f"view {name} projects {columns} on sqlite but {postgres_views[name]} on postgres"
        )
    assert sqlite_views["findings_summary"] == [
        "scope_id",
        "subject_id",
        "run_id",
        "layer_id",
        "repo",
        "severity",
        "verdict",
        "finding_count",
    ]
    assert sqlite_views["current_binding"] == ["*"]


def test_upsert_columns_match_the_table_definition() -> None:
    """An upsert that omits a column silently drops that data forever.

    Only the Go generator compared these, and it caught a real one:
    priv_profile.tier2_required_vs_granted was missing from the generated
    upsert because the column name contains a DIGIT. Python never noticed --
    sqlite3 ignores extra named parameters, so the projector happily passed a
    value into a statement with nowhere to put it.
    """
    for dialect in DIALECTS:
        root = storage_dir() / dialect
        for schema_path in sorted((root / "schema").glob("*.sql")):
            table = schema_path.stem
            upsert_path = root / "queries" / f"{table}.upsert.sql"
            if not upsert_path.is_file():
                continue
            ddl = schema_path.read_text(encoding="utf-8")
            body = ddl.split("(", 1)[1]
            declared = []
            for line in body.splitlines():
                line = line.strip()
                # Every column type in use across both dialects. Narrowing
                # this list silently shrinks what the gate compares.
                match = re.match(
                    r"^([a-z_0-9]+)\s+(TEXT|INTEGER|JSONB|BOOLEAN|BIGINT"
                    r"|TIMESTAMPTZ|REAL|DOUBLE|BYTEA|BLOB)\b",
                    line,
                )
                if match:
                    declared.append(match.group(1))
            insert = upsert_path.read_text(encoding="utf-8").split("(", 1)[1].split(")", 1)[0]
            inserted = [c.strip() for c in insert.split(",") if c.strip()]
            assert inserted == declared, (
                f"{dialect}/{table}: upsert columns {inserted} != table columns {declared}"
            )


def test_read_queries_exist_in_both_dialects_and_target_views() -> None:
    """The per-dialect tax on a new dashboard aggregate is two `.list.sql` files.

    `.upsert.sql` parity was already gated; a read query landing on one dialect
    only was not, which is the shape that breaks a database adopter silently.
    """
    per_dialect = {
        dialect: {path.name for path in (storage_dir() / dialect / "queries").glob("*.list.sql")}
        for dialect in DIALECTS
    }
    assert per_dialect["sqlite"], "no read queries found"
    assert per_dialect["sqlite"] == per_dialect["postgres"], (
        f"read queries differ: {per_dialect['sqlite'] ^ per_dialect['postgres']}"
    )
    views = set(_declared_views("sqlite"))
    for name in per_dialect["sqlite"]:
        assert name.removesuffix(".list.sql") in views, (
            f"{name} reads something other than a declared view"
        )


def test_search_queries_exist_in_both_dialects_with_matching_parameters() -> None:
    """Registry enumeration reads (`.search.sql`) must land on both dialects.

    `.list.sql` parity is gated for scoped views; the registry `search` reads
    target tables (not views), so they need their own gate: a query that only
    one database can serve breaks SDK generation and any database adopter
    silently.
    """
    per_dialect = {
        dialect: {path.name for path in (storage_dir() / dialect / "queries").glob("*.search.sql")}
        for dialect in DIALECTS
    }
    assert per_dialect["sqlite"], "no search queries found"
    assert per_dialect["sqlite"] == per_dialect["postgres"], (
        f"search queries differ: {per_dialect['sqlite'] ^ per_dialect['postgres']}"
    )
    placeholder = {"postgres": re.compile(r"%\((\w+)\)s"), "sqlite": re.compile(r":(\w+)\b")}
    for name in per_dialect["sqlite"]:
        params = {}
        for dialect in DIALECTS:
            sql = (storage_dir() / dialect / "queries" / name).read_text(encoding="utf-8")
            params[dialect] = placeholder[dialect].findall(sql)
        assert params["postgres"] == params["sqlite"], (
            f"{name}: placeholders differ between dialects"
        )
        assert len(set(params["postgres"])) == len(params["postgres"]), (
            f"{name}: a placeholder is used more than once"
        )


def test_sqlite_bootstrap_statements_execute_and_reexecute() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        for _ in range(2):
            conn.execute("BEGIN")
            for path in bootstrap_files("sqlite"):
                for statement in bootstrap_statements("sqlite", path):
                    conn.execute(statement)
                    assert conn.in_transaction
            conn.execute("COMMIT")
        assert conn.execute("SELECT * FROM current_binding").fetchall() == []
        assert conn.execute("SELECT * FROM findings_summary").fetchall() == []
        assert conn.execute("PRAGMA foreign_key_list(artifact_binding)").fetchall()
        for table in PROJECTION_TABLES.values():
            assert conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
    finally:
        conn.close()


def test_postgres_relations_use_the_storage_schema() -> None:
    root = storage_dir() / "postgres"
    assert (root / "namespace.sql").read_text().strip() == (
        "CREATE SCHEMA IF NOT EXISTS traust_storage;"
    )
    for path in root.rglob("*.sql"):
        if path.name == "namespace.sql":
            continue
        # Strip comments first. Prose legitimately says "counted from
        # subject_ownership", and a bare FROM-regex reads that as an
        # unqualified relation. Third time comments have tripped a scanner
        # in this file, hence _uncommented() rather than reworded prose.
        sql = _uncommented(path.read_text())
        references = [
            *POSTGRES_RELATION_REFERENCE.findall(sql),
            *POSTGRES_INDEX_REFERENCE.findall(sql),
        ]
        for relation in references:
            unqualified = relation.rsplit(".", maxsplit=1)[-1]
            if unqualified in POSTGRES_RELATIONS:
                assert relation == f"{POSTGRES_SCHEMA}.{unqualified}", (
                    f"{path.relative_to(root)} contains unqualified relation {relation}"
                )


def test_storage_profiles_cover_schemas_and_only_project_the_first_slice() -> None:
    document = json.loads((storage_dir() / "profiles.json").read_text())
    profiles = document["artifacts"]
    assert document["version"] == 1
    assert set(profiles) == set(FAMILIES)
    assert {
        name: profile["projection"] for name, profile in profiles.items() if "projection" in profile
    } == PROJECTION_TABLES
    assert profiles["vuln-findings"] == {
        "class": "run-bound",
        "required": ["subject_id", "run_id"],
        "projection": "finding",
    }
    assert {
        name for name, profile in profiles.items() if profile["class"] == "run-bound"
    } == RUN_BOUND
    assert profiles["triage"]["required"] == ["subject_id", "run_id"]
    assert profiles["layer"]["required"] == ["layer_id"]


def test_storage_package_resources() -> None:
    root = storage_dir()
    assert (root / "README.md").is_file()
    assert (root / "profiles.json").is_file()
    for dialect in ["postgres", "sqlite"]:
        files = bootstrap_files(dialect)
        expected_prefix = [
            *(f"{table}.sql" for table in REGISTRY_TABLES),
            "artifact_evidence.sql",
            "artifact_binding.sql",
            "artifact_location.sql",
        ]
        if dialect == "postgres":
            expected_prefix.insert(0, "namespace.sql")
        assert [path.name for path in files[: len(expected_prefix)]] == expected_prefix
        schema_files = {path.stem for path in (root / dialect / "schema").glob("*.sql")}
        assert schema_files == TABLES
        for entity in TABLES - {"traust_storage_meta"}:
            assert "CREATE TABLE" in (root / dialect / "schema" / f"{entity}.sql").read_text()
        for entity in [
            "artifact_evidence",
            "artifact_binding",
            "artifact_location",
            *PROJECTION_TABLES.values(),
        ]:
            assert (root / dialect / "queries" / f"{entity}.upsert.sql").is_file()
        assert {path.stem for path in (root / dialect / "views").glob("*.sql")} == {
            "binding_current",
            "attack_coverage",
            "compliance_posture",
            "pattern_exposure",
            "remediation_current",
            "verification_current",
            "verification_regression_current",
            "advisory_exposure",
            "census_exposure",
            "census_population",
            "current_finding",
            "current_finding_detail",
            "distinct_exposure",
            "exposure_trend",
            "finding_first_seen",
            "finding_sla",
            "finding_timeline",
            "ownership_current",
            "findings_summary",
            "hardening_findings",
            "open_findings",
            "operator_privilege",
            "pqc_posture",
            "pqc_readiness_rollup",
            "report_current",
            "sla_clock",
            "sla_threshold",
            "threat_current",
            "threat_exposure",
            "validation_current",
            "validation_exposure",
        }
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    targets = project["tool"]["hatch"]["build"]["targets"]
    assert targets["wheel"]["force-include"]["storage/v1"] == "traust_contracts/storage/v1"
    assert "/tests/fixtures/storage" in targets["sdist"]["exclude"]


def test_dashboard_view_filters_match_the_contract_enums() -> None:
    """The view SQL hard-codes disposition values; this is what keeps them true.

    The harness projection once excluded 'in_progress' where the enum says
    'fix_in_progress', so every in-progress finding silently vanished from
    open exposure. SQL files cannot import an enum, so the next best thing
    is a test that fails the moment they disagree.
    """
    from traust_contracts.v1.enums import DispositionResolution, Validity

    closed = {DispositionResolution.RESOLVED.value, DispositionResolution.RISK_ACCEPTED.value}
    non_exposure = {Validity.FALSE_POSITIVE.value, Validity.HARDENING.value}

    for dialect in DIALECTS:
        # Comments deliberately NAME the values this gate exists to catch
        # (see the open_findings header), so scan the SQL only.
        sql = _uncommented((storage_dir() / dialect / "views" / "open_findings.sql").read_text())
        quoted = set(re.findall(r"'([a-z_]+)'", sql))
        assert closed <= quoted, f"{dialect}: open_findings lost a closed resolution"
        assert non_exposure <= quoted, f"{dialect}: open_findings lost a non-exposure validity"
        # Every quoted value must BE an enum member -- a typo'd value filters
        # nothing and is invisible until someone counts.
        known = (
            {m.value for m in DispositionResolution}
            | {m.value for m in Validity}
            | {"code", "policy", "owned"}
        )
        assert quoted <= known, f"{dialect}: unknown value(s) {quoted - known}"

        hardening = _uncommented(
            (storage_dir() / dialect / "views" / "hardening_findings.sql").read_text()
        )
        assert f"'{Validity.HARDENING.value}'" in hardening

        # current_finding_detail restates the census classification per row,
        # so its hard-coded values are gated the same way. 'triage' is the
        # artifact name its triage join matches and 'closed' is the census's
        # derived class name; neither is a disposition enum member.
        detail = _uncommented(
            (storage_dir() / dialect / "views" / "current_finding_detail.sql").read_text()
        )
        detail_quoted = set(re.findall(r"'([a-z_]+)'", detail))
        detail_known = known | {"triage", "closed"}
        assert detail_quoted <= detail_known, f"{dialect}: unknown value(s) {detail_quoted - detail_known}"


def test_the_spine_unions_both_finding_families() -> None:
    """A view reading only report_finding omits every policy finding --
    Thousands of them in a corpus, and silently."""
    for dialect in DIALECTS:
        sql = (storage_dir() / dialect / "views" / "current_finding.sql").read_text()
        assert "report_finding" in sql and "cloud_config_finding" in sql
        assert sql.count("UNION ALL") == 1
        # It must go through report_current, or a repo's findings are counted
        # once per restatement (measured 49% inflation).
        assert "report_current" in sql
        assert "ownership_current" in sql, "ownership is the denominator"
    assert "subject_ownership" not in sql, (
        "the spine must read DEDUPLICATED ownership: subject_ownership accumulates "
        "one row set per registry import, and joining it raw fans every finding out "
        "across generations"
    )


def test_distinct_exposure_keeps_both_lens_filters() -> None:
    """Dropping either one silently changes what the number means."""
    for dialect in DIALECTS:
        sql = (storage_dir() / dialect / "views" / "distinct_exposure.sql").read_text()
        assert "ownership = 'owned'" in sql
        # 0, not FALSE: the column is INTEGER on BOTH dialects. It was
        # briefly BOOLEAN on PostgreSQL, which the Go generator refuses --
        # it requires identical column types across dialects.
        assert "is_branch_audit = 0" in sql
        assert "fingerprint IS NOT NULL" in sql


def test_views_are_created_in_dependency_order() -> None:
    """Alphabetical order is not dependency order: current_finding sorts
    before report_current but selects from it, and PostgreSQL resolves a
    view's references at CREATE time."""
    for dialect in DIALECTS:
        names = [p.name for p in bootstrap_files(dialect) if "/views/" in str(p)]
        assert names.index("report_current.sql") < names.index("current_finding.sql")
        assert names.index("binding_current.sql") < names.index("report_current.sql")
        for dependent in (
            "open_findings.sql",
            "hardening_findings.sql",
            "distinct_exposure.sql",
            "current_finding_detail.sql",
        ):
            assert names.index("current_finding.sql") < names.index(dependent)


def test_distinct_exposure_is_one_row_per_fingerprint() -> None:
    """Lens 2 counts distinct PROBLEMS. Grouping by severity or business
    unit as well splits one problem into several when it surfaces at
    different severities across repos -- measured +219 against
    findings.db's v_distinct_owned before this was corrected."""
    for dialect in DIALECTS:
        sql = _uncommented(
            (storage_dir() / dialect / "views" / "distinct_exposure.sql").read_text()
        )
        group_by = sql[sql.upper().rindex("GROUP BY") :]
        assert "fingerprint" in group_by
        for splitter in ("severity", "business_unit", "subject_id", "ownership"):
            assert splitter not in group_by, (
                f"{dialect}: grouping by {splitter} splits one fingerprint into several rows"
            )
