"""Executed SQLite protocol: bindings, projections, history, and scope."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    FINDINGS_SUMMARY_ROWS,
    FINDINGS_SUMMARY_SCOPE,
    report_with_external_blocking,
    report_with_findings,
    seed_findings_summary,
)
from storage_samples import (
    ALL_SECONDARY_PROJECTION_TABLES,
    FAMILIES,
    INVENTORY_TABLES,
    PROJECTION_TABLES,
    REGISTRY_TABLES,
    RUN_BOUND,
    encode,
    rated_threat_model,
    sample,
)

from traust_contracts.v1.storage import Binding, IngestError, Store, binding_id
from traust_contracts.v1.storage.sql import CONTRACT_VERSION, REVISION
from traust_contracts.v1.storage.store import _threat_score

TABLES = [
    *REGISTRY_TABLES,
    *INVENTORY_TABLES,
    "portfolio_forge_facts",
    "artifact_binding",
    "artifact_evidence",
    "artifact_location",
    *sorted(set(PROJECTION_TABLES.values()) | ALL_SECONDARY_PROJECTION_TABLES),
]


@pytest.fixture
def store() -> Iterator[Store]:
    conn = sqlite3.connect(":memory:")
    storage = Store(conn)
    storage.init()
    yield storage
    conn.close()


def run_binding(
    *,
    scope: str = "local",
    subject: str = "sci:inventory-item:42",
    run: str = "sci:scan-result:7",
    layer: str | None = None,
    supersedes: str | None = None,
) -> Binding:
    return Binding(scope, subject, run, layer, supersedes)


def binding_for(name: str) -> Binding:
    if name in RUN_BOUND:
        return run_binding()
    if name == "layer":
        return Binding(layer_id="ledger:layer:1")
    return Binding()


def assert_empty(store: Store) -> None:
    for name in TABLES:
        assert store.conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0] == 0


def test_init_revision_and_dependency_shape(store: Store) -> None:
    conn = store.conn
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == {*TABLES, "traust_storage_meta"}
    views = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='view'")}
    assert views == {
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
    assert conn.execute("PRAGMA foreign_keys").fetchone() == (1,)
    original = conn.execute("SELECT * FROM traust_storage_meta").fetchall()
    assert len(original) == 1 and original[0][:3] == (1, CONTRACT_VERSION, REVISION)
    store.init()
    assert conn.execute("SELECT * FROM traust_storage_meta").fetchall() == original
    conn.execute("ALTER TABLE report_finding DROP COLUMN blocked_external")
    conn.execute("UPDATE traust_storage_meta SET revision=?", (REVISION + 1,))
    conn.commit()
    legacy_dump = tuple(conn.iterdump())
    with pytest.raises(IngestError, match=r"explicit migration"):
        store.init()
    assert tuple(conn.iterdump()) == legacy_dump


def test_binding_id_golden_vector_and_presence_encoding() -> None:
    digest = hashlib.sha256(b"").hexdigest()
    present = Binding(subject_id="sci:inventory-item:42")
    assert binding_id(digest, "triage", present) == (
        "90933ec74bd66618428c4def90f4af4cb9a2ab60bc9bd24a20b64814ca2dba56"
    )
    assert binding_id(digest, "triage", Binding()) != binding_id(
        digest, "triage", Binding(subject_id="")
    )
    with pytest.raises(IngestError, match="NUL"):
        binding_id(digest, "triage", Binding(subject_id="bad\x00id"))


@pytest.mark.parametrize("name", FAMILIES)
def test_all_artifacts_ingest_and_project(store: Store, name: str) -> None:
    payload, _ = sample(name)
    result = store.ingest(name, payload, binding_for(name))
    assert store.get_binding(result.binding_id).binding == binding_for(name)
    # Evidence record keeps digest and byte_size, not payload.
    row = store.conn.execute(
        "SELECT digest, byte_size FROM artifact_evidence WHERE digest = ?", (result.digest,)
    ).fetchone()
    assert row == (result.digest, len(payload))
    table = PROJECTION_TABLES[name]
    count = store.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    # Fan-out families project one row per item in their sample.
    fan_out = {"vuln-findings": 2, "corpus-registry": 2, "threat-model": 2, "layer": 3}
    assert count == fan_out.get(name, 1)


def test_global_evidence_dedup_is_private_and_binding_scoped(store: Store) -> None:
    payload, _ = sample("adr-registry")
    first = store.ingest("adr-registry", payload, Binding(scope_id="a"))
    second = store.ingest("adr-registry", payload, Binding(scope_id="b"))
    retry = store.ingest("adr-registry", payload, Binding(scope_id="b"))
    assert first.digest == second.digest == retry.digest
    assert first.binding_id != second.binding_id == retry.binding_id
    assert not first.already_bound and not second.already_bound and retry.already_bound
    assert store.conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (1,)
    assert store.conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (2,)


def test_evidence_record_tracks_byte_size(store: Store) -> None:
    payload, _ = sample("vuln-findings")
    result = store.ingest("vuln-findings", payload, run_binding())
    row = store.conn.execute(
        "SELECT byte_size FROM artifact_evidence WHERE digest = ?", (result.digest,)
    ).fetchone()
    assert row[0] == len(payload)


def test_role_absent_keeps_v1_binding_identity() -> None:
    digest = hashlib.sha256(b"").hexdigest()
    present = Binding(subject_id="sci:inventory-item:42")
    roled = Binding(subject_id="sci:inventory-item:42", role="baseline")
    assert binding_id(digest, "triage", present) == (
        "90933ec74bd66618428c4def90f4af4cb9a2ab60bc9bd24a20b64814ca2dba56"
    )
    assert binding_id(digest, "report", roled) == (
        "d0da85a98aa803d79ba2fed07a8f991c706f2fbb44f3692cbd3ad8662961cb0b"
    )


def test_baseline_and_cumulative_reports_are_distinct_bindings(store: Store) -> None:
    payload, _ = sample("report")
    baseline = store.ingest("report", payload, replace(run_binding(), role="baseline"))
    cumulative = store.ingest("report", payload, replace(run_binding(), role="cumulative"))
    assert baseline.digest == cumulative.digest
    assert baseline.binding_id != cumulative.binding_id
    assert store.get_binding(baseline.binding_id).binding.role == "baseline"
    assert store.get_binding(cumulative.binding_id).binding.role == "cumulative"
    assert store.conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (1,)


@pytest.mark.parametrize("name,role", [("report", "latest"), ("vuln-findings", "baseline")])
def test_role_must_be_declared_by_profile(store: Store, name: str, role: str) -> None:
    payload, _ = sample(name)
    with pytest.raises(IngestError, match="role"):
        store.ingest(name, payload, replace(run_binding(), role=role))
    assert_empty(store)


def test_supersession_must_keep_role(store: Store) -> None:
    payload, _ = sample("report")
    first = store.ingest("report", payload, replace(run_binding(), role="baseline"))
    corrected = json.loads(payload)
    corrected["remediation_roadmap"].append(dict(corrected["remediation_roadmap"][0]))
    with pytest.raises(IngestError, match="context mismatch"):
        store.ingest(
            "report",
            encode(corrected),
            replace(run_binding(supersedes=first.binding_id), role="cumulative"),
        )


def test_references_attach_to_binding_and_round_trip(store: Store) -> None:
    payload, _ = sample("report")
    refs = ["s3://sci-reports/scans/42/7/report.json", "git+repo@abc123:findings/x.json"]
    result = store.ingest("report", payload, run_binding(), references=refs)
    assert store.get_binding(result.binding_id).references == tuple(sorted(refs))


def test_get_binding_returns_byte_size(store: Store) -> None:
    payload, _ = sample("report")
    result = store.ingest("report", payload, run_binding())
    record = store.get_binding(result.binding_id)
    assert record.byte_size == len(payload)
    assert record.artifact_digest == hashlib.sha256(payload).hexdigest()


def test_references_stay_inside_their_binding(store: Store) -> None:
    payload, _ = sample("adr-registry")
    a = store.ingest("adr-registry", payload, Binding(scope_id="a"), references=["file:///a"])
    b = store.ingest("adr-registry", payload, Binding(scope_id="b"))
    assert a.digest == b.digest
    assert store.get_binding(a.binding_id).references == ("file:///a",)
    assert store.get_binding(b.binding_id).references == ()


def test_retry_adds_references_without_duplicates(store: Store) -> None:
    payload, _ = sample("report")
    first = store.ingest("report", payload, run_binding(), references=["s3://a/r.json"])
    retry = store.ingest(
        "report", payload, run_binding(), references=["s3://a/r.json", "s3://mirror/r.json"]
    )
    assert retry.already_bound
    assert store.get_binding(first.binding_id).references == (
        "s3://a/r.json",
        "s3://mirror/r.json",
    )


@pytest.mark.parametrize("references", ["s3://bare-string", [""], ["bad\x00ref"], [1]])
def test_references_are_validated_before_any_write(store: Store, references: Any) -> None:
    payload, _ = sample("report")
    with pytest.raises(IngestError, match="references"):
        store.ingest("report", payload, run_binding(), references=references)
    assert_empty(store)


@pytest.mark.parametrize("name,missing", [("vuln-findings", "subject_id"), ("triage", "run_id")])
def test_run_profile_requires_explicit_context(store: Store, name: str, missing: str) -> None:
    payload, _ = sample(name)
    values: dict[str, Any] = {"subject_id": "subject", "run_id": "run"}
    values[missing] = None
    with pytest.raises(IngestError, match=missing):
        store.ingest(name, payload, Binding(**values))
    assert_empty(store)


def test_layer_profile_requires_layer_only(store: Store) -> None:
    payload, _ = sample("layer")
    with pytest.raises(IngestError, match="layer_id"):
        store.ingest("layer", payload)
    result = store.ingest("layer", payload, Binding(layer_id="ledger/layer:team/a"))
    assert store.get_binding(result.binding_id).binding.layer_id == "ledger/layer:team/a"


def test_explicit_supersession_is_current_and_backfill_order_free(store: Store) -> None:
    initial, _ = sample("vuln-findings")
    context = run_binding(layer="ledger:layer:1")
    first = store.ingest("vuln-findings", initial, context)
    corrected = json.loads(initial)
    corrected["findings"][0]["title"] = "Corrected title"
    second = store.ingest(
        "vuln-findings",
        encode(corrected),
        run_binding(layer="ledger:layer:1", supersedes=first.binding_id),
    )
    assert store.conn.execute(
        "SELECT binding_id FROM current_binding WHERE artifact_name='vuln-findings'"
    ).fetchall() == [(second.binding_id,)]
    assert store.get_binding(first.binding_id).artifact_digest == first.digest
    assert store.get_binding(second.binding_id).artifact_digest == second.digest


def test_supersession_rejects_missing_cross_context_and_branches(store: Store) -> None:
    payload, _ = sample("vuln-findings")
    first = store.ingest("vuln-findings", payload, run_binding())
    changed = json.loads(payload)
    changed["findings"][0]["title"] = "Corrected title one"
    with pytest.raises(IngestError, match="not found"):
        store.ingest("vuln-findings", encode(changed), run_binding(supersedes="0" * 64))
    with pytest.raises(IngestError, match="context mismatch"):
        store.ingest(
            "vuln-findings",
            encode(changed),
            run_binding(scope="other", supersedes=first.binding_id),
        )
    successor = store.ingest(
        "vuln-findings", encode(changed), run_binding(supersedes=first.binding_id)
    )
    changed["findings"][0]["title"] = "Corrected title two"
    with pytest.raises(IngestError):
        store.ingest("vuln-findings", encode(changed), run_binding(supersedes=first.binding_id))
    assert store.conn.execute("SELECT count(*) FROM current_binding").fetchone() == (1,)
    assert store.get_binding(successor.binding_id).binding.supersedes_binding_id == first.binding_id


def test_findings_summary_joins_same_run_and_optional_layer_repo(store: Store) -> None:
    """The SQLite half of the cross-dialect parity pair.

    Fixture and expectation are shared with
    `test_storage_postgres.py::test_postgres_findings_summary_uses_json_scope_and_same_run`
    so the two views cannot drift behind separately-authored setups.
    """
    seed_findings_summary(store)
    assert store.query_findings_summary([FINDINGS_SUMMARY_SCOPE]) == FINDINGS_SUMMARY_ROWS
    assert store.query_findings_summary(["other"]) == []


def test_projection_failure_rolls_back_evidence_and_binding(store: Store) -> None:
    payload, _ = sample("vuln-findings")
    second = json.loads(payload)["findings"][1]["id"]
    store.conn.execute(
        "CREATE TRIGGER fail_second BEFORE INSERT ON finding "
        f"WHEN NEW.finding_id = '{second}' BEGIN SELECT RAISE(ABORT, 'blocked'); END"
    )
    with pytest.raises(IngestError, match="SQLITE"):
        store.ingest("vuln-findings", payload, run_binding())
    assert_empty(store)


def test_caller_transaction_and_error_logs_preserve_evidence_boundary(
    store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    payload, _ = sample("vuln-findings")
    store.conn.execute("BEGIN")
    with pytest.raises(IngestError, match="caller transaction is untouched"):
        store.ingest("vuln-findings", payload, run_binding())
    store.conn.execute("ROLLBACK")
    marker = b'PRIVATE_ROW_CONTENT:{"broken"'
    try:
        store.ingest("vuln-findings", marker, run_binding())
    except IngestError as error:
        assert error.payload is marker
        logging.getLogger(__name__).exception("save failed")
    else:
        pytest.fail("invalid evidence was accepted")
    assert "PRIVATE_ROW_CONTENT" not in caplog.text


def test_fixture_remains_exact(store: Store) -> None:
    payload = (
        Path(__file__).parent / "fixtures/storage/vuln-findings-populated.test.json"
    ).read_bytes()
    result = store.ingest("vuln-findings", payload, run_binding())
    assert result.digest == hashlib.sha256(payload).hexdigest()
    assert store.conn.execute("SELECT count(*) FROM finding").fetchone() == (5,)


def test_patch_evidence_projects_into_a_queryable_column(store: Store) -> None:
    """Exact bytes were always kept in artifact_evidence; the column was not."""
    item = {
        "kind": "mutation",
        "outcome": "proves",
        "base_observation": "mutant 7 survives at oauth.go:212",
        "patched_observation": "19 caught, 0 uncaught",
        "tool": "mewt 4.0.0",
        "deterministic_steps": "ran",
    }
    for name in ("remediation", "verification"):
        payload, _ = sample(name)
        document = json.loads(payload)
        document["evidence"] = [item]
        result = store.ingest(name, encode(document), binding_for(name))

        row = store.conn.execute(
            f"SELECT evidence FROM {PROJECTION_TABLES[name]} WHERE binding_id = ?",
            (result.binding_id,),
        ).fetchone()
        assert row is not None, f"{name} row missing"
        assert json.loads(row[0]) == [item], f"{name} evidence not projected"


def test_absent_patch_evidence_projects_as_null(store: Store) -> None:
    """Optional means optional: a report without evidence still projects."""
    for name in ("remediation", "verification"):
        payload, _ = sample(name)
        assert "evidence" not in json.loads(payload)
        result = store.ingest(name, payload, binding_for(name))
        row = store.conn.execute(
            f"SELECT evidence FROM {PROJECTION_TABLES[name]} WHERE binding_id = ?",
            (result.binding_id,),
        ).fetchone()
        assert row[0] is None


def test_report_findings_project_disposition_and_fingerprint(store: Store) -> None:
    """GAP A/B: what was locked in report.findings is now queryable.

    The blob is unchanged -- this is an index over it, not a replacement.
    """
    result = store.ingest("report", report_with_findings(), binding_for("report"))

    rows = store.conn.execute(
        "SELECT finding_id, fingerprint, validity, resolution, assurance, "
        "conflict, fp_overridden, fp_reassertion_blocked, refuted_awaiting_signoff, "
        "severity_override, validation_status "
        "FROM report_finding WHERE binding_id = ? ORDER BY finding_id",
        (result.binding_id,),
    ).fetchall()
    assert len(rows) == 2, "every finding projects, disposed or not"

    disposed, bare = rows
    assert disposed[:5] == (
        "FIND-001",
        "a" * 64,
        "confirmed",
        "fix_in_progress",
        "execution_proven",
    )
    # The two-person-rule flags survive the projection.
    assert (disposed[5], disposed[6], disposed[7], disposed[8]) == (0, 1, 1, 0)
    assert json.loads(disposed[9])["severity"] == "critical"
    assert disposed[10] == "confirmed"

    # A finding with no disposition still projects, carrying identity only.
    assert bare[0] == "FIND-002"
    assert all(value is None for value in bare[1:])


def test_report_blocking_projects_true_false_and_absent_independently(store: Store) -> None:
    result = store.ingest("report", report_with_external_blocking(), binding_for("report"))
    rows = store.conn.execute(
        "SELECT finding_id, remediation_effort, blocked_external "
        "FROM report_finding WHERE binding_id = ? ORDER BY finding_id",
        (result.binding_id,),
    ).fetchall()
    assert rows == [
        ("FIND-001", "m", 1),
        ("FIND-002", "m", 0),
        ("FIND-003", "blocked-external", None),
    ]


@pytest.mark.parametrize("invalid", ["true", 1, 0, None])
def test_report_invalid_blocking_is_rejected_before_storage(store: Store, invalid: Any) -> None:
    document = json.loads(report_with_external_blocking())
    document["findings"][0]["blocked_external"] = invalid
    with pytest.raises(IngestError, match="validation"):
        store.ingest("report", encode(document), binding_for("report"))
    assert_empty(store)


def test_report_projection_is_consistent_with_source(store: Store) -> None:
    """The projection must faithfully represent the source document."""
    payload = report_with_findings()
    result = store.ingest("report", payload, binding_for("report"))
    stored = store.conn.execute(
        "SELECT findings FROM report WHERE binding_id = ?", (result.binding_id,)
    ).fetchone()[0]
    assert json.loads(stored) == json.loads(payload)["findings"]


def test_absent_disposition_flag_is_null_not_false(store: Store) -> None:
    """ "Nobody overrode this FP" and "no record either way" differ, and the
    two-person rule depends on the difference."""
    document = json.loads(report_with_findings())
    del document["findings"][0]["disposition"]["fp_overridden"]
    result = store.ingest("report", encode(document), binding_for("report"))
    value = store.conn.execute(
        "SELECT fp_overridden FROM report_finding WHERE binding_id = ? AND finding_id = ?",
        (result.binding_id, "FIND-001"),
    ).fetchone()[0]
    assert value is None


def test_subject_ownership_projects_the_denominator_columns(store: Store) -> None:
    """GAP C: ownership had no contract home, so "X% of our repos" was
    uncomputable from storage/v1. These are the columns every cut divides by."""
    payload, _ = sample("corpus-registry")
    result = store.ingest("corpus-registry", payload, Binding())
    rows = store.conn.execute(
        "SELECT subject_id, tree, ownership, business_unit, product, ref_kind, "
        "is_branch_audit FROM subject_ownership WHERE binding_id = ? ORDER BY subject_id",
        (result.binding_id,),
    ).fetchall()
    assert rows == [
        (
            "findings/example/repo",
            "findings",
            "owned",
            "Platform Group",
            "example-product",
            None,
            0,
        ),
        (
            "other/example/repo@release-1.0",
            "other-findings",
            "external-bu",
            "Other Unit",
            None,
            "branch",
            1,
        ),
    ]


def test_ownership_joins_findings_to_a_denominator(store: Store) -> None:
    """The point of the projection: a finding can be cut by who owns it.

    Before this table the join had no left-hand side at all -- storage/v1
    knew a finding's subject_id and nothing about that subject.
    """
    store.ingest("corpus-registry", sample("corpus-registry")[0], Binding())
    store.ingest(
        "report",
        report_with_findings(),
        Binding(subject_id="findings/example/repo", run_id="run:1"),
    )
    rows = store.conn.execute(
        "SELECT o.ownership, o.business_unit, count(*) "
        "FROM report_finding f "
        "JOIN artifact_binding b ON b.binding_id = f.binding_id "
        "JOIN subject_ownership o ON o.subject_id = b.subject_id "
        "GROUP BY o.ownership, o.business_unit"
    ).fetchall()
    assert rows == [("owned", "Platform Group", 2)]


def test_branch_re_audits_are_separable_from_head(store: Store) -> None:
    """is_branch_audit is the column a denominator must exclude on.

    A large share of audits are branch re-audits of the same code, so a
    coverage number that counts them is overstated. Without this column the
    exclusion cannot be expressed at all.
    """
    result = store.ingest("corpus-registry", sample("corpus-registry")[0], Binding())
    head = store.conn.execute(
        "SELECT count(*) FROM subject_ownership WHERE binding_id = ? AND is_branch_audit = 0",
        (result.binding_id,),
    ).fetchone()[0]
    total = store.conn.execute(
        "SELECT count(*) FROM subject_ownership WHERE binding_id = ?", (result.binding_id,)
    ).fetchone()[0]
    assert (head, total) == (1, 2), "the sample carries one HEAD audit and one branch re-audit"


def test_absent_is_branch_audit_is_null_not_false(store: Store) -> None:
    """ "Not a branch audit" and "unknown" must not collapse: the second is a
    registry gap and should be visible as one."""
    document = json.loads(sample("corpus-registry")[0])
    del document["subjects"][0]["is_branch_audit"]
    result = store.ingest("corpus-registry", encode(document), Binding())
    value = store.conn.execute(
        "SELECT is_branch_audit FROM subject_ownership WHERE binding_id = ? AND subject_id = ?",
        (result.binding_id, "findings/example/repo"),
    ).fetchone()[0]
    assert value is None


def _audit_and_findings_current(subject: str = "repo/a") -> tuple[bytes, bytes]:
    """The same finding set, restated as a plain audit and a disposition-aware
    findings-current report. Neither supersedes the other."""
    audit = json.loads(report_with_findings())
    for finding in audit["findings"]:
        finding.pop("disposition", None)
    current = json.loads(report_with_findings())
    current["disposition_summary"] = {
        "layer_ref": "repo-findings-layer.json",
        "generated_at": "2026-01-02T00:00:00Z",
        "by_resolution": {
            "open": 2,
            "fix_in_progress": 0,
            "resolved": 0,
            "partially_resolved": 0,
            "risk_accepted": 0,
            "regression_introduced": 0,
        },
        "by_validity": {
            "confirmed": 1,
            "corrected": 0,
            "false_positive": 0,
            "not_verified": 1,
        },
    }
    return encode(audit), encode(current)


def test_report_current_collapses_restatements_of_one_subject(store: Store) -> None:
    """GAP D: both restatements are legitimately current, so counting
    report_finding directly counts every finding once per restatement."""
    audit, current = _audit_and_findings_current()
    store.ingest("report", audit, Binding(subject_id="repo/a", run_id="run:audit"))
    store.ingest("report", current, Binding(subject_id="repo/a", run_id="run:current"))

    naive = store.conn.execute("SELECT count(*) FROM report_finding").fetchone()[0]
    distinct = store.conn.execute(
        "SELECT count(DISTINCT finding_id) FROM report_finding"
    ).fetchone()[0]
    assert (naive, distinct) == (4, 2), "the double count this view exists to fix"

    rows = store.conn.execute("SELECT subject_id, disposition_aware FROM report_current").fetchall()
    assert rows == [("repo/a", 1)], "exactly one, and the disposition-aware one"

    counted = store.conn.execute(
        "SELECT count(*) FROM report_finding f JOIN report_current c ON c.binding_id = f.binding_id"
    ).fetchone()[0]
    assert counted == 2, "each finding counted once"


def test_report_current_prefers_disposition_awareness_over_recency(store: Store) -> None:
    """Order of ingest must not decide the answer -- the layer does."""
    audit, current = _audit_and_findings_current()
    store.ingest("report", current, Binding(subject_id="repo/a", run_id="run:current"))
    store.ingest("report", audit, Binding(subject_id="repo/a", run_id="run:audit"))
    assert store.conn.execute("SELECT disposition_aware FROM report_current").fetchall() == [(1,)]


def test_report_current_is_deterministic_among_equals(store: Store) -> None:
    """Two reports of the same layer for one subject still yield ONE row."""
    first = json.loads(report_with_findings())
    first["title"] = "Audit one"
    second = json.loads(report_with_findings())
    second["title"] = "Audit two"
    for payload, run in ((first, "run:1"), (second, "run:2")):
        store.ingest("report", encode(payload), Binding(subject_id="repo/a", run_id=run))
    assert store.conn.execute("SELECT count(*) FROM report_current").fetchall() == [(1,)]

    # Force the recency signal to a tie. Without a tie-break the view would
    # return both rows, and "the current report" would depend on nothing.
    store.conn.execute("UPDATE artifact_binding SET bound_at = '2026-01-01T00:00:00Z'")
    assert store.conn.execute("SELECT count(*) FROM report_current").fetchall() == [(1,)]


def test_report_current_keeps_distinct_subjects_apart(store: Store) -> None:
    """Collapsing restatements must not collapse different repos."""
    audit, current = _audit_and_findings_current()
    for subject in ("repo/a", "repo/b"):
        store.ingest("report", audit, Binding(subject_id=subject, run_id=f"{subject}:audit"))
        store.ingest("report", current, Binding(subject_id=subject, run_id=f"{subject}:cur"))
    assert store.conn.execute(
        "SELECT subject_id FROM report_current ORDER BY subject_id"
    ).fetchall() == [("repo/a",), ("repo/b",)]


def _cloud_config_with_findings() -> bytes:
    """Shaped from REAL corpus findings, not invented.

    The first attempt guessed: provider="checkov" (it is an enum of clouds),
    status="FAILED" (it is confirmed|suppressed|needs_review), and omitted
    fact_ids / effective_severity / disposition.assurance, all required.
    Two findings on ONE resource differing only by check_id -- the case
    check_id exists to separate.
    """
    document = json.loads(sample("cloud-config-findings-current")[0])
    base = {
        "fact_ids": ["cca-d26590b3507a"],
        "framework": "bicep",
        "provider": "azure",
        "rationale": "r" * 30,
        "locations": [
            {
                "file_path": "/modules/rp-cosmos-account.bicep",
                "resource": "Microsoft.DocumentDB/databaseAccounts.cosmosDbAccount",
                "file_line_range": [8, 51],
            }
        ],
        "cwe": "CWE-284",
        "validation_status": "not_verified",
        "disposition": {
            "validity": "not_verified",
            "resolution": "open",
            "assurance": "claimed",
            "last_updated": "2026-07-29T06:10:00Z",
            "events": [],
        },
    }
    document["findings"] = [
        {
            **base,
            "id": "CCA-ARO-HCP-001",
            "check_id": "CKV_AZURE_101",
            "title": "Ensure that Azure Cosmos DB disables public network access",
            "severity": "high",
            "effective_severity": "high",
            "scanner_severity": "unrated",
            "status": "confirmed",
            "fingerprint": "b" * 64,
            "fingerprint_algo": "v3",
        },
        {
            **base,
            "id": "CCA-ARO-HCP-002",
            "check_id": "CKV_AZURE_99",
            "title": "Ensure that Cosmos DB accounts have restricted firewall rules",
            "severity": "low",
            "effective_severity": "low",
            "status": "needs_review",
        },
    ]
    return encode(document)


def test_cloud_config_findings_project_into_queryable_rows(store: Store) -> None:
    """A whole class of repos and their findings were absent from every
    storage/v1 query while present in findings.db, because this family
    projected one row and kept its findings in a JSON column."""
    payload = _cloud_config_with_findings()
    result = store.ingest("cloud-config-findings-current", payload, run_binding())

    rows = store.conn.execute(
        "SELECT finding_id, check_id, framework, provider, status, severity, "
        "fingerprint, validity, resolution, fp_overridden "
        "FROM cloud_config_finding WHERE binding_id = ? ORDER BY finding_id",
        (result.binding_id,),
    ).fetchall()
    assert len(rows) == 2, "every finding projects, disposed or not"

    first, second = rows
    assert first[:6] == (
        "CCA-ARO-HCP-001",
        "CKV_AZURE_101",
        "bicep",
        "azure",
        "confirmed",
        "high",
    )
    assert first[6] == "b" * 64
    assert first[7:10] == ("not_verified", "open", None)
    # check_id is what separates two findings on ONE resource.
    assert second[0] == "CCA-ARO-HCP-002" and second[1] == "CKV_AZURE_99"
    assert second[4] == "needs_review" and second[6] is None

    # Evidence record present.
    assert store.conn.execute(
        "SELECT byte_size FROM artifact_evidence WHERE digest = ?", (result.digest,)
    ).fetchone()[0] == len(payload)


def test_cloud_config_findings_are_separable_by_check(store: Store) -> None:
    """Two findings on the same resource must not be indistinguishable."""
    result = store.ingest(
        "cloud-config-findings-current", _cloud_config_with_findings(), run_binding()
    )
    checks = store.conn.execute(
        "SELECT count(DISTINCT check_id) FROM cloud_config_finding WHERE binding_id = ?",
        (result.binding_id,),
    ).fetchone()[0]
    assert checks == 2


def _registry(subject: str, *, ownership: str = "owned", branch: bool = False) -> bytes:
    return encode(
        {
            "version": 1,
            "subjects": [
                {
                    "subject_id": subject,
                    "tree": "findings",
                    "ownership": ownership,
                    "business_unit": "Platform Group",
                    "is_branch_audit": branch,
                }
            ],
        }
    )


def _seed_dashboard(store: Store, *, ownership: str = "owned", branch: bool = False) -> None:
    """A code report and a policy report for one subject, plus its ownership."""
    subject = "findings/org/repo"
    store.ingest(
        "corpus-registry", _registry(subject, ownership=ownership, branch=branch), Binding()
    )
    store.ingest("report", report_with_findings(), Binding(subject_id=subject, run_id="r1"))
    store.ingest(
        "cloud-config-findings-current",
        _cloud_config_with_findings(),
        Binding(subject_id=subject, run_id="r1"),
    )


def test_the_spine_unions_code_and_policy_findings(store: Store) -> None:
    """A dashboard reading only report_finding omits every policy finding."""
    _seed_dashboard(store)
    families = dict(
        store.conn.execute("SELECT family, count(*) FROM current_finding GROUP BY family")
    )
    assert families == {"code": 2, "policy": 2}


def test_the_spine_carries_ownership(store: Store) -> None:
    """Ownership is the denominator and lives in neither finding table."""
    _seed_dashboard(store)
    rows = set(store.conn.execute("SELECT DISTINCT ownership, business_unit FROM current_finding"))
    assert rows == {("owned", "Platform Group")}


def test_open_findings_excludes_hardening_and_false_positives(store: Store) -> None:
    _seed_dashboard(store)
    store.conn.execute("UPDATE report_finding SET validity='hardening' WHERE finding_id='FIND-001'")
    store.conn.execute(
        "UPDATE report_finding SET validity='false_positive' WHERE finding_id='FIND-002'"
    )
    store.conn.commit()
    ids = {r[3] for r in store.query_open_findings(["local"])}
    assert "FIND-001" not in ids and "FIND-002" not in ids


def test_open_findings_keeps_partial_fixes_and_regressions(store: Store) -> None:
    """Open is anything not AFFIRMATIVELY closed -- these are still exposure."""
    _seed_dashboard(store)
    for resolution in ("fix_in_progress", "partially_resolved", "regression_introduced"):
        store.conn.execute(
            "UPDATE report_finding SET resolution=? WHERE finding_id='FIND-001'", (resolution,)
        )
        store.conn.commit()
        ids = {r[3] for r in store.query_open_findings(["local"])}
        assert "FIND-001" in ids, resolution
    store.conn.execute(
        "UPDATE report_finding SET resolution='resolved' WHERE finding_id='FIND-001'"
    )
    store.conn.commit()
    assert "FIND-001" not in {r[3] for r in store.query_open_findings(["local"])}


def test_hardening_is_separate_from_open(store: Store) -> None:
    _seed_dashboard(store)
    store.conn.execute("UPDATE report_finding SET validity='hardening' WHERE finding_id='FIND-001'")
    store.conn.commit()
    assert {r[3] for r in store.query_hardening_findings(["local"])} == {"FIND-001"}
    assert "FIND-001" not in {r[3] for r in store.query_open_findings(["local"])}


def test_distinct_exposure_excludes_unowned_and_branch_audits(store: Store) -> None:
    """Both filters carry meaning: upstream/external-bu are Lens 1 only, and
    branch re-audits of the same code overstate coverage."""
    _seed_dashboard(store)
    assert store.query_distinct_exposure(["local"]), "owned HEAD audit must appear"

    for kwargs in ({"ownership": "upstream"}, {"branch": True}):
        other = Store(sqlite3.connect(":memory:"))
        other.init()
        _seed_dashboard(other, **kwargs)
        assert other.query_distinct_exposure(["local"]) == [], kwargs


def test_census_exposure_classifies_every_finding_exactly_once(store: Store) -> None:
    """Exhaustive and mutually exclusive, or the census over- or under-counts.

    A consumer FILTERS this view instead of restating the disposition policy,
    so a finding that falls through every branch -- or matches two -- is a
    silent arithmetic error in every cut built on top of it.
    """
    _seed_dashboard(store)
    store.conn.execute("UPDATE report_finding SET validity='hardening' WHERE finding_id='FIND-001'")
    store.conn.execute(
        "UPDATE report_finding SET resolution='risk_accepted' WHERE finding_id='FIND-002'"
    )
    store.conn.commit()
    total = store.conn.execute("SELECT COUNT(*) FROM current_finding").fetchone()[0]
    rows = store.query_census_exposure(["local"])
    assert sum(row[8] for row in rows) == total
    assert {row[7] for row in rows} <= {"false_positive", "hardening", "closed", "open"}


def test_census_exposure_prefers_validity_over_resolution(store: Store) -> None:
    """A hardening item that is also resolved is hardening, not closed.

    Ordering matters: classify it as closed and posture debt vanishes from
    the backlog the moment someone marks it fixed on one subject.
    """
    _seed_dashboard(store)
    store.conn.execute(
        "UPDATE report_finding SET validity='hardening', resolution='resolved' "
        "WHERE finding_id='FIND-001'"
    )
    store.conn.commit()
    classes = {
        row[7]: row[8]
        for row in store.query_census_exposure(["local"])
        if row[5] == "code" and row[7] == "hardening"
    }
    assert classes.get("hardening") == 1


def test_census_population_counts_a_subject_with_no_findings(store: Store) -> None:
    """The denominator comes from ownership, not from findings.

    A subject that was audited clean is still coverage. Counting the
    denominator from findings drops it and overstates every percentage
    divided by it -- which is the specific way census numbers drifted.
    """
    _seed_dashboard(store)
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "subjects": [
                    {
                        "subject_id": "findings/org/repo",
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Platform Group",
                        "is_branch_audit": False,
                    },
                    {
                        "subject_id": "findings/org/clean",
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Platform Group",
                        "is_branch_audit": False,
                    },
                ],
            }
        ),
        Binding(),
    )
    rows = store.query_census_population(["local"])
    assert len(rows) == 1
    subjects, branch_reaudits, with_report = rows[0][4], rows[0][5], rows[0][6]
    assert (subjects, branch_reaudits, with_report) == (2, 0, 1)


def test_reimporting_the_registry_does_not_double_the_numbers(store: Store) -> None:
    """The shape that made every view wrong on the second import.

    corpus-registry restates the whole population and carries an `updated`
    timestamp, so each import is new content, a new digest and a new
    binding; subject_ownership keeps a row set per binding. Measured on the
    live corpus before ownership_current: one re-import DOUBLED both
    current_finding and the census population.
    Invisible in the suite until now because the store was always fresh.
    """
    _seed_dashboard(store)

    def numbers() -> tuple[int, int, int]:
        findings = store.conn.execute("SELECT COUNT(*) FROM current_finding").fetchone()[0]
        population = store.conn.execute("SELECT SUM(subjects) FROM census_population").fetchone()[0]
        exposure = store.conn.execute("SELECT SUM(occurrences) FROM census_exposure").fetchone()[0]
        return findings, population, exposure

    before = numbers()
    assert before[0] and before[1] and before[2]

    # Byte-different content -- exactly what `updated` guarantees per import.
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "updated": "2026-09-19T00:00:00Z",
                "subjects": [
                    {
                        "subject_id": "findings/org/repo",
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Platform Group",
                        "is_branch_audit": False,
                    }
                ],
            }
        ),
        Binding(),
    )
    assert store.conn.execute("SELECT COUNT(*) FROM subject_ownership").fetchone()[0] == 2, (
        "the raw table is expected to accumulate -- that is why the view exists"
    )
    assert numbers() == before


def test_ownership_current_takes_the_latest_declaration(store: Store) -> None:
    """A re-import is also how ownership CHANGES. Deduplicating must not
    freeze the first answer -- a repo moving business unit has to land."""
    _seed_dashboard(store)
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "updated": "2026-09-19T00:00:00Z",
                "subjects": [
                    {
                        "subject_id": "findings/org/repo",
                        "tree": "findings",
                        "ownership": "upstream",
                        "business_unit": "Storage Group",
                        "is_branch_audit": False,
                    }
                ],
            }
        ),
        Binding(),
    )
    rows = set(store.conn.execute("SELECT DISTINCT ownership, business_unit FROM current_finding"))
    assert rows == {("upstream", "Storage Group")}


def test_threat_keys_are_scoped_to_their_subject(store: Store) -> None:
    """Every threat model numbers its threats from T1.

    The in-model id is unique only within its own model, so a projection
    keyed on it alone would keep ONE threat per number across the whole
    model set. The key is derived from the subject, not read from the
    document.
    """
    payload, _ = sample("threat-model")
    for subject in ("findings/example/repo", "findings/example/other"):
        store.ingest("threat-model", payload, Binding(subject_id=subject, run_id="r1"))
    rows = store.conn.execute(
        "SELECT threat_key, threat_id, subject_id FROM threat WHERE threat_id='T1'"
    ).fetchall()
    assert len(rows) == 2, "both subjects' T1 must survive"
    assert len({r[0] for r in rows}) == 2, "their keys must differ"
    assert {r[2] for r in rows} == {"findings/example/repo", "findings/example/other"}


def test_threat_carries_its_attack_refs(store: Store) -> None:
    """Column 11, and the input to any ATT&CK coverage rollup.

    Present on a small fraction of threats in the live corpus despite being
    default since harness 0.82.0, so it is exactly the field a projection
    drops without anyone noticing -- which is what the first cut of this
    one did.
    """
    payload, _ = sample("threat-model")
    store.ingest("threat-model", payload, Binding(subject_id="findings/example/repo", run_id="r1"))
    row = store.conn.execute("SELECT attack_refs FROM threat WHERE threat_id='T1'").fetchone()
    assert row is not None and row[0], "attack_refs must reach the projection"
    assert json.loads(row[0]) == ["T1190", "T1078"]


_RATING_COLUMNS = (
    "severity, likelihood_score, likelihood_level, impact_score, impact_level, "
    "impact_basis, risk_rating, impact, likelihood, score"
)


def test_rated_threat_projects_its_owasp_rating(store: Store) -> None:
    """The rating reaches SQL whole, with its derived values typed beside it.

    Before these columns an OWASP-rated threat projected with NULL impact,
    likelihood and score -- present in the table and unrankable.
    """
    payload = rated_threat_model()
    store.ingest("threat-model", payload, Binding(subject_id="findings/example/repo", run_id="r1"))
    row = store.conn.execute(
        f"SELECT {_RATING_COLUMNS} FROM threat WHERE threat_id='T2'"
    ).fetchone()
    assert row[:6] == ("high", 4.375, "medium", 7.25, "high", "technical")
    rating = json.loads(row[6])
    assert rating == json.loads(payload)["threats"][1]["risk_rating"], "factors and reasons kept"
    assert row[7:] == (None, None, None), "no legacy labels and no legacy score on a rated threat"


def test_legacy_threat_keeps_its_labels_and_score(store: Store) -> None:
    store.ingest(
        "threat-model",
        rated_threat_model(),
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    row = store.conn.execute(
        f"SELECT {_RATING_COLUMNS} FROM threat WHERE threat_id='T1'"
    ).fetchone()
    assert row[:7] == (None,) * 7, "an unrated threat has no rating columns"
    assert row[7:] == ("critical", "almost_certain", _threat_score("critical", "almost_certain"))


def test_threat_current_carries_the_rating(store: Store) -> None:
    _seed_dashboard(store)
    store.ingest(
        "threat-model",
        rated_threat_model(),
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    rows = {row[2]: row for row in store.query_threat_current(["local"])}
    # The rating columns are appended after the existing ones, so readers
    # that index the older columns by position are unaffected.
    assert rows["T2"][-6:] == ("high", 4.375, "medium", 7.25, "high", "technical")
    assert json.loads(rows["T2"][-7])["severity"] == "high"
    assert rows["T1"][-7:] == (None,) * 7


def test_threat_exposure_splits_rated_from_legacy_and_orders_by_severity(store: Store) -> None:
    """A rated threat and a legacy one never share an exposure row."""
    _seed_dashboard(store)
    store.ingest(
        "threat-model",
        rated_threat_model(),
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    rows = store.query_threat_exposure(["local"])
    by_severity = {(row[-1], row[5], row[6]) for row in rows}
    assert ("high", None, None) in by_severity, "the rated threat groups by severity"
    assert (None, "critical", "almost_certain") in by_severity, "the legacy one by its labels"
    severities = [row[-1] for row in rows if row[-1] is not None]
    assert severities == ["high"]


def test_threat_exposure_keeps_partially_mitigated_and_marks_evidence(store: Store) -> None:
    """Two collapses that would each overstate coverage.

    partially_mitigated is the largest status bucket in the real register
    by a wide margin, and a threat with no evidence is modelled rather
    than proven -- a different claim from unmitigated.
    """
    _seed_dashboard(store)
    payload, _ = sample("threat-model")
    store.ingest("threat-model", payload, Binding(subject_id="findings/example/repo", run_id="r1"))
    rows = store.query_threat_exposure(["local"])
    by_status = {row[7]: row[8] for row in rows}
    assert set(by_status) == {"unmitigated", "partially_mitigated"}
    assert by_status["unmitigated"] == 1, "the evidenced threat"
    assert by_status["partially_mitigated"] == 0, "no evidence on that one"


def test_operator_privilege_flags_follow_rbac_flag_presence(store: Store) -> None:
    """A flag key appears ONLY when it matched, so presence is the signal.

    The fixture matches two of the seven patterns; the other five must read
    as 0 rather than NULL, or a dashboard filter drops the row entirely.
    """
    payload, _ = sample("operator-priv-profile")
    store.ingest(
        "operator-priv-profile",
        payload,
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    rows = store.query_operator_privilege(["local"])
    assert len(rows) == 1
    columns = [
        description[0]
        for description in store.conn.execute(
            "SELECT * FROM operator_privilege LIMIT 1"
        ).description
    ]
    row = dict(zip(columns, rows[0], strict=True))
    assert row["flag_secrets_access"] == 1
    assert row["flag_escalate_bind_impersonate"] == 1
    for absent in (
        "nodes_access",
        "wildcard_verbs",
        "wildcard_resources",
        "pods_exec",
        "rbac_write",
    ):
        assert row[f"flag_{absent}"] == 0, absent


def test_operator_privilege_extracts_summary_counts(store: Store) -> None:
    """The dashboard cuts by these, so the view surfaces them as columns --
    without the projection storing a second copy that can drift."""
    payload, _ = sample("operator-priv-profile")
    store.ingest(
        "operator-priv-profile",
        payload,
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    row = store.conn.execute(
        "SELECT workload_count, privileged_or_host_workloads, rbac_rule_count, "
        "distinct_rule_triples, no_scc_request_recorded FROM operator_privilege"
    ).fetchone()
    assert row == (2, 0, 1, 2, 1)


def test_ledger_events_project_and_carry_the_clock(store: Store) -> None:
    """The whole time dimension was being discarded.

    layer.events is an append-only dated transition stream and
    storage/v1 could previously only
    answer what is open NOW and nothing about when, how long, or what the
    estate looked like on any past date.
    """
    payload, _ = sample("layer")
    store.ingest("layer", payload, Binding(layer_id="ledger:layer:1"))
    rows = store.conn.execute(
        "SELECT finding_ref, occurred_at, validity, resolution FROM layer_event "
        "ORDER BY occurred_at"
    ).fetchall()
    assert len(rows) == 3
    assert [r[3] for r in rows] == [None, "regression_introduced", "resolved"]
    assert all(r[1] for r in rows), "occurred_at is what every duration is computed on"


def test_duration_uses_occurred_at_and_respects_the_offset(store: Store) -> None:
    """Two ways to get MTTR wrong, both seen in real data.

    recorded_at is when the ledger APPENDED -- a bulk re-stamp moves it for
    thousands of events at once and would report the whole corpus as fixed
    that day. And real events carry non-UTC offsets, so subtracting the
    strings naively is wrong by hours.

    The fixture resolves at 2026-07-26T01:46:00-04:00, which is
    05:46 UTC on the 26th: 4.24 days after a first observation of
    2026-07-22, not the 4.0 a naive date comparison would give.
    """
    _seed_dashboard(store)
    store.ingest("layer", sample("layer")[0], Binding(layer_id="ledger:layer:1"))
    row = store.conn.execute(
        "SELECT first_adjudicated, resolved_at, days_adjudicated_to_resolve "
        "FROM finding_timeline WHERE resolved_at IS NOT NULL"
    ).fetchone()
    assert row is not None, "the layer and report fixtures must share a fingerprint"
    assert row[2] > 4.0, "a naive string subtraction would give exactly 4.0"
    assert row[2] < 4.5


def test_open_findings_keep_a_null_duration_not_a_zero(store: Store) -> None:
    """A censored mean reads faster than reality.

    An open finding has no resolution date. Defaulting that to 0 would make
    every unfixed finding look instantly fixed; the column stays NULL so a
    consumer must decide what to do about the open ones.
    """
    _seed_dashboard(store)
    document = json.loads(sample("layer")[0])
    # Same finding, adjudicated but never closed -- the shape that a
    # censored mean silently drops.
    document["events"] = [
        event
        for event in document["events"]
        if (event.get("disposition") or {}).get("resolution") != "resolved"
    ]
    store.ingest("layer", encode(document), Binding(layer_id="ledger:layer:1"))
    rows = store.conn.execute(
        "SELECT resolved_at, days_to_resolve FROM finding_timeline"
    ).fetchall()
    assert rows, "the timeline must contain the open finding"
    for resolved_at, days in rows:
        assert resolved_at is None
        assert days is None, "an open finding must not report a duration of 0"


def test_sla_threshold_reads_only_the_default_profile(store: Store) -> None:
    """A deployment ships several profiles and marks one default.

    Selecting a stricter one is a query-time choice; resolving ALL of them
    here would give a finding two contradictory thresholds at once.
    """
    store.ingest("sla-policy", sample("sla-policy")[0], Binding())
    rows = store.query_sla_threshold(["local"])
    assert {row[2] for row in rows} == {"baseline"}, "contractual is not default"
    assert {row[4]: row[5] for row in rows} == {
        "critical": 7,
        "high": 30,
        "low": None,
    }


def test_a_null_threshold_is_tracked_never_overdue(store: Store) -> None:
    """resolve_days null is a real policy position, not zero days.

    A severity the policy tracks without clocking must never read as
    breached -- and must not read as compliant either. Both are claims the
    policy did not make.
    """
    _seed_dashboard(store)
    store.ingest("sla-policy", sample("sla-policy")[0], Binding())
    store.conn.execute("UPDATE report_finding SET severity='low'")
    store.conn.commit()
    rows = store.conn.execute(
        "SELECT resolve_days, breached FROM finding_sla WHERE severity='low'"
    ).fetchall()
    assert rows
    for resolve_days, breached in rows:
        assert resolve_days is None
        assert breached is None, "never overdue, and never affirmatively compliant"


def test_no_policy_means_unknown_not_compliant(store: Store) -> None:
    """The fail-open shape. With no policy ingested a finding has no
    threshold, so `breached` must be NULL -- reporting 0 would let an
    estate with no policy at all render as fully within SLA."""
    _seed_dashboard(store)
    rows = store.conn.execute(
        "SELECT resolve_days, breached, policy_name FROM finding_sla"
    ).fetchall()
    assert rows
    for resolve_days, breached, policy_name in rows:
        assert (resolve_days, breached, policy_name) == (None, None, None)


def test_clock_start_is_policy_and_moves_the_clock(store: Store) -> None:
    """The reason this is policy and not opinion.

    The same finding has three defensible start times and they give
    different answers. The sample policy says first_event, so the clock
    must start at the ledger adjudication, NOT at the report date the view
    used to hardcode.
    """
    _seed_dashboard(store)
    store.ingest("layer", sample("layer")[0], Binding(layer_id="ledger:layer:1"))
    store.ingest("sla-policy", sample("sla-policy")[0], Binding())
    row = store.conn.execute(
        "SELECT clock_start, clock_started_at, first_seen FROM finding_sla "
        "JOIN finding_timeline USING (scope_id, fingerprint) "
        "WHERE first_adjudicated IS NOT NULL LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row[0] == "first_event"
    assert row[1] != row[2], "the policy must move the clock off the report date"


def test_clock_start_applies_to_unclocked_severities_too(store: Store) -> None:
    """clock_start is a property of the POLICY, not of a severity.

    A severity the profile does not give a threshold is UNCLOCKED, but the
    policy still says where every clock starts. Resolving the clock through
    the per-severity join let those findings fall back to a different clock
    than their siblings -- measured on the live corpus, findings split
    roughly evenly between ageing from the report date and ageing from the
    ledger event, under one policy naming a single clock.
    """
    _seed_dashboard(store)
    store.ingest("layer", sample("layer")[0], Binding(layer_id="ledger:layer:1"))
    store.ingest("sla-policy", sample("sla-policy")[0], Binding())
    # 'medium' is absent from the sample profile, so it has no threshold.
    store.conn.execute("UPDATE report_finding SET severity='medium'")
    store.conn.commit()
    rows = store.conn.execute(
        "SELECT clock_start, resolve_days FROM finding_sla WHERE severity='medium'"
    ).fetchall()
    assert rows
    for clock_start, resolve_days in rows:
        assert resolve_days is None, "medium is unclocked under this profile"
        assert clock_start == "first_event", "but the POLICY clock still applies"


def test_rebaseline_events_project_and_assert_nothing(store: Store) -> None:
    """A rebaseline is a RENAME record, not evidence.

    They exist in bulk in the live corpus, appended by one migration that
    moved finding aliases out of mutable metadata into the Merkle-covered
    event stream. Because the source type was missing from the enum, every
    layer carrying one rejected outright, and with them real
    validation_report events that storage/v1 never saw.

    They must project, and they must stay out of validity precedence: an
    empty disposition is the invariant, so a consumer folding events into a
    current state skips them rather than reading a rename as a verdict.
    """
    document = json.loads(sample("layer")[0])
    document["events"].append(
        {
            "event_id": "d" * 64,
            "finding_ref": "FIND-001",
            "recorded_at": "2026-07-16T00:00:00+00:00",
            "occurred_at": "2026-07-16T00:00:00+00:00",
            "source": {
                "type": "rebaseline",
                "ref": "repo-old-report.json",
                "actor": {"kind": "machine", "identity": "migration/alias_tables_to_events"},
            },
            "disposition": {},
            "rationale": "Migrated from metadata.finding_aliases; values carried over unchanged.",
        }
    )
    store.ingest("layer", encode(document), Binding(layer_id="ledger:layer:1"))
    row = store.conn.execute(
        "SELECT validity, resolution FROM layer_event WHERE source_type='rebaseline'"
    ).fetchone()
    assert row == (None, None), "a rebaseline must assert no disposition"
    assert (
        store.conn.execute(
            "SELECT COUNT(*) FROM layer_event WHERE source_type='rebaseline'"
        ).fetchone()[0]
        == 1
    )


def test_every_dashboard_read_refuses_an_empty_scope(store: Store) -> None:
    """PostgreSQL fails closed, so an empty scope reads as 'no findings'
    when it means 'misconfigured'."""
    _seed_dashboard(store)
    for read in (
        store.query_open_findings,
        store.query_hardening_findings,
        store.query_distinct_exposure,
        store.query_census_population,
        store.query_census_exposure,
        store.query_threat_current,
        store.query_threat_exposure,
        store.query_operator_privilege,
        store.query_finding_timeline,
        store.query_exposure_trend,
        store.query_finding_sla,
        store.query_sla_threshold,
    ):
        with pytest.raises(IngestError, match="scope is required"):
            read([])
        assert read(["other-scope"]) == []


def test_threat_score_is_derived_not_read_from_the_document(store: Store) -> None:
    """`score` is not a schema field, so reading one leaves the column NULL.

    `$defs/threat` sets `additionalProperties: false` and declares no
    `score`, so a producer cannot legally emit one -- the projector used
    to read `threat["score"]` and every row in the live corpus came back
    NULL, taking `threat_exposure.top_score` and the `(status, score)`
    rank index with it. Derive it from the two enums that ARE required.
    """
    payload, _ = sample("threat-model")
    store.ingest("threat-model", payload, Binding(subject_id="findings/example/repo", run_id="r1"))
    scores = dict(store.conn.execute("SELECT threat_id, score FROM threat").fetchall())
    # critical (8) x almost_certain (16); high (4) x possible (4)
    assert scores == {"T1": 128, "T2": 16}
    top = store.conn.execute("SELECT MAX(top_score) FROM threat_exposure").fetchone()[0]
    assert top == 128, "the exposure view must be able to rank"


def test_threat_score_is_null_when_a_rating_is_off_contract() -> None:
    """Unrateable must not read as "rated, and it came out lowest".

    A zero would sort alongside genuinely low-ranked threats; None keeps
    an off-contract model out of the ordering instead of at the bottom of
    it. Tested directly because the schema rejects such a document at
    ingest -- the guard is for the day a value is added to one enum and
    not to the weight table.
    """
    assert _threat_score("catastrophic", "likely") is None
    assert _threat_score("high", "sometimes") is None
    assert _threat_score(None, None) is None
    assert _threat_score("low", "very_rare") == 1


def test_validation_exposure_keeps_not_attempted_visible(store: Store) -> None:
    """The lane's own work must not disappear into a filter.

    `not_attempted` dominates the live corpus. A view reporting only
    attempts would describe a fraction of the lane and read as though
    everything else had been refuted, so the verdict is carried
    uncollapsed and `attempted` is DERIVED beside it — a consumer can ask
    "of what we tried, how much held up" without restating the lane's own
    definition of an attempt.
    """
    _seed_dashboard(store)
    payload, _ = sample("validation")
    store.ingest("validation", payload, Binding(subject_id="findings/example/repo", run_id="r1"))
    rows = store.query_validation_exposure(["local"])
    assert rows, "the evidence lens must return something"
    columns = [
        description[0]
        for description in store.conn.execute(
            "SELECT * FROM validation_exposure LIMIT 1"
        ).description
    ]
    assert "attempted" in columns and "skip_reason" in columns
    # every row classified, none dropped
    total = store.conn.execute("SELECT COUNT(*) FROM validation_current").fetchone()[0]
    summed = sum(row[columns.index("findings")] for row in rows)
    assert summed == total, "every claimed finding is classified exactly once"


def test_validation_supersession_is_per_environment(store: Store) -> None:
    """A hub run and a spoke run are not re-runs of each other.

    Measured on the live corpus: one subject's hub and spoke runs
    covered the SAME findings and disagreed on a material share of the
    verdicts, some of
    them confirmed against one environment and refuted against the
    other. Collapsing on subject alone picked one arbitrarily and
    deleted the disagreement.
    """
    payload, _ = sample("validation")
    base = json.loads(payload)
    for environment in ("hub", "spoke"):
        document = json.loads(json.dumps(base))
        document["metadata"]["target_environment"] = environment
        store.ingest(
            "validation",
            json.dumps(document).encode(),
            Binding(subject_id="findings/example/repo", run_id=f"run:{environment}"),
        )
    environments = {
        row[0]
        for row in store.conn.execute("SELECT DISTINCT target_environment FROM validation_current")
    }
    assert environments == {"hub", "spoke"}, "both environments stay current"


def test_a_re_run_of_one_environment_supersedes_its_predecessor(store: Store) -> None:
    """Within an environment the newest run still wins."""
    payload, _ = sample("validation")
    base = json.loads(payload)
    for run in ("run:1", "run:2"):
        document = json.loads(json.dumps(base))
        document["metadata"]["target_environment"] = "hub"
        document["metadata"]["date"] = "2026-01-02" if run == "run:1" else "2026-01-03"
        store.ingest(
            "validation",
            json.dumps(document).encode(),
            Binding(subject_id="findings/example/repo", run_id=run),
        )
    runs = {row[0] for row in store.conn.execute("SELECT DISTINCT run_id FROM validation_current")}
    assert runs == {"run:2"}, "one environment, newest run only"


def test_an_unlabelled_run_is_never_merged_with_another(store: Store) -> None:
    """Absent environment means UNKNOWN, not "same as the others".

    Many live artifacts predate the field. Merging them on the
    assumption that they share an environment is exactly the guess that
    produced the 290-verdict conflict, so the partition falls back to
    run_id and every unlabelled run stays distinct. Noisier on purpose.
    """
    payload, _ = sample("validation")
    for run in ("run:a", "run:b"):
        store.ingest(
            "validation",
            payload,
            Binding(subject_id="findings/example/repo", run_id=run),
        )
    runs = {row[0] for row in store.conn.execute("SELECT DISTINCT run_id FROM validation_current")}
    assert runs == {"run:a", "run:b"}, "unknown environments are not merged"


def test_skip_reason_comes_from_the_step_the_producer_writes(store: Store) -> None:
    """The reason is not where the schema says it is.

    `validated_findings[]` declares `not_attempted_reason`, and measured
    across the live corpus that field is empty on every row — what the
    lane writes is `steps[].scope_reason`. Reading the declared key alone
    left skip_reason NULL on every not_attempted and
    blocked_by_scope rows, so "triage already ruled this out" and "we
    have no adapter for this surface" were indistinguishable.
    """
    payload, _ = sample("validation")
    document = json.loads(payload)
    document["validated_findings"] = [
        {
            "source_id": "p:r/FIND-001",
            "source_report": "r.json",
            "technique": "skip",
            "verdict": "not_attempted",
            "steps": [
                {
                    "step_id": "s1",
                    "adapter": "k8s",
                    "verb": "noop",
                    "classification": "safe",
                    "verdict": "not_attempted",
                    "scope_reason": "triage-false-positive",
                }
            ],
        },
        {
            "source_id": "p:r/FIND-002",
            "source_report": "r.json",
            "technique": "skip",
            "verdict": "not_attempted",
            "not_attempted_reason": "declared-wins",
            "steps": [
                {
                    "step_id": "s2",
                    "adapter": "k8s",
                    "verb": "noop",
                    "classification": "safe",
                    "verdict": "not_attempted",
                    "scope_reason": "no-poc-no-adapter",
                }
            ],
        },
        {
            "source_id": "p:r/FIND-003",
            "source_report": "r.json",
            "technique": "replay",
            "verdict": "confirmed",
            "steps": [],
        },
    ]
    store.ingest(
        "validation",
        json.dumps(document).encode(),
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    rows = dict(
        store.conn.execute(
            "SELECT source_finding_id, skip_reason FROM validation_finding"
        ).fetchall()
    )
    assert rows["FIND-001"] == "triage-false-positive", "read from the step"
    assert rows["FIND-002"] == "declared-wins", "a declared field still wins"
    assert rows["FIND-003"] is None, "an ATTEMPTED finding has no skip to explain"


def test_a_confirmed_finding_never_carries_a_skip_reason(store: Store) -> None:
    """Some steps of a PROVEN finding are still scoped out.

    The first cut read any step's scope_reason, which put a skip reason
    on 945 confirmed findings in the live corpus — reading as "we
    declined to test this" for something that was tested and held.
    """
    payload, _ = sample("validation")
    document = json.loads(payload)
    document["validated_findings"] = [
        {
            "source_id": "p:r/FIND-010",
            "source_report": "r.json",
            "technique": "replay",
            "verdict": "confirmed",
            "steps": [
                {
                    "step_id": "s1",
                    "adapter": "k8s",
                    "verb": "noop",
                    "classification": "safe",
                    "verdict": "not_attempted",
                    "scope_reason": "wrong-surface:tooling",
                },
                {
                    "step_id": "s2",
                    "adapter": "k8s",
                    "verb": "get",
                    "classification": "safe",
                    "verdict": "confirmed",
                },
            ],
        }
    ]
    store.ingest(
        "validation",
        json.dumps(document).encode(),
        Binding(subject_id="findings/example/repo", run_id="r1"),
    )
    reason = store.conn.execute(
        "SELECT skip_reason FROM validation_finding WHERE source_finding_id='FIND-010'"
    ).fetchone()[0]
    assert reason is None


def test_advisory_exposure_fans_out_and_keeps_evidence_strength(store: Store) -> None:
    """One advisory, many repos, and the evidence is not collapsed.

    "reachable at a call site" and "named in a manifest" are different
    claims. A rollup that blends them reads as though every hit needed
    the same urgency, and `direct` likewise separates a first-order
    dependency from a transitive one — the same advisory is a different
    remediation job depending on which.
    """
    payload, _ = sample("impact-analysis")
    store.ingest("impact-analysis", payload, Binding(scope_id="local"))
    columns = [
        d[0] for d in store.conn.execute("SELECT * FROM advisory_exposure LIMIT 1").description
    ]
    for carried in (
        "classification",
        "direct",
        "evidence_level",
        "l1_depends_on",
        "l1_version_in_range",
        "needs_manual_trace",
        "govulncheck",
        "sbom_scan",
        "manifest_version",
    ):
        assert carried in columns, f"{carried} must survive to the view"
    rows = store.query_advisory_exposure(["local"])
    assert rows, "the blast radius must be queryable"
    # one row per repo the advisory names, not one row per advisory
    named = len(json.loads(payload)["repos"])
    assert len(rows) == named, f"{named} repos named, {len(rows)} rows"


def test_a_re_analysed_advisory_supersedes_its_predecessor(store: Store) -> None:
    """Re-running an advisory must not double its blast radius."""
    payload, _ = sample("impact-analysis")
    document = json.loads(payload)
    for generated in ("2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"):
        document["metadata"]["generated_at"] = generated
        store.ingest("impact-analysis", json.dumps(document).encode(), Binding(scope_id="local"))
    bindings = store.conn.execute(
        "SELECT COUNT(*) FROM artifact_binding WHERE artifact_name='impact-analysis'"
    ).fetchone()[0]
    assert bindings == 2, "both analyses retained as evidence"
    assert len(store.query_advisory_exposure(["local"])) == len(document["repos"])


def test_widened_projections_round_trip_every_declared_field(store: Store) -> None:
    """Revision 14: a declared field reaches SQL, or it is unreachable.

    The gate in test_view_contract_coverage asserts the COLUMN exists.
    This asserts the upsert actually fills it -- the two failures are
    different, and the second is the one that leaves a correct-looking
    schema returning NULL for everything.

    Measured on a live corpus after this landed: description, remediation,
    cwes and locations reached every report finding, cvss and rationale the
    large majority. A few columns stayed NULL there because that corpus has
    no instance of them yet, which is a statement about the corpus and not
    about the projection.
    """
    payload = _cloud_config_with_findings()
    result = store.ingest("cloud-config-findings-current", payload, run_binding())
    row = store.conn.execute(
        "SELECT rationale, cwe, control_refs, locations, fact_ids, "
        "effective_severity FROM cloud_config_finding "
        "WHERE binding_id = ? ORDER BY finding_id LIMIT 1",
        (result.binding_id,),
    ).fetchone()
    assert row[0] and row[1] == "CWE-284", "prose and cwe reach the column"
    assert json.loads(row[3])[0]["file_path"].endswith(".bicep"), "locations keep their shape"
    assert json.loads(row[4]) == ["cca-d26590b3507a"], "fact_ids is a list, not a string"
    assert row[5], "effective_severity is required by the contract"

    document = json.loads(report_with_findings())
    finding = document["findings"][0]
    finding.update(
        {
            "category": "injection",
            "cwes": ["CWE-78"],
            "asvs_references": ["V5.3.8"],
            "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
            "effective_severity": "high",
            "origin": "vuln-scan",
            "passes": [1, 2],
            "isolation_dimensions": ["privilege"],
        }
    )
    result = store.ingest(
        "report", encode(document), Binding(subject_id="s-widened", run_id="r-widened")
    )
    row = store.conn.execute(
        "SELECT description, remediation, category, cwes, asvs_references, cvss, "
        "effective_severity, origin, passes, isolation_dimensions "
        "FROM report_finding WHERE binding_id = ? LIMIT 1",
        (result.binding_id,),
    ).fetchone()
    assert row[0] and row[1], "description and remediation are REQUIRED by the contract"
    assert row[2] == "injection"
    assert json.loads(row[3]) == ["CWE-78"]
    assert json.loads(row[4]) == ["V5.3.8"]
    assert json.loads(row[5])["score"] == 8.1, "cvss keeps score and vector together"
    assert (row[6], row[7]) == ("high", "vuln-scan")
    assert json.loads(row[8]) == [1, 2], "passes stays a list of integers"
    assert json.loads(row[9]) == ["privilege"]


def test_layer_event_flattens_risk_weight_and_keeps_rationale(store: Store) -> None:
    """risk_weight is flattened the way source and disposition already are.

    `lambda` is what a risk index multiplies by; leaving it inside a JSON
    blob is what kept the trends risk index in Python. rationale is
    REQUIRED by layer.schema.json and was dropped entirely -- an event
    stream without it records that something changed and never why.
    """
    document = json.loads(sample("layer")[0])
    event = document["events"][0]
    event["rationale"] = "confirmed against the running service"
    event["harness_version"] = "0.8.3"
    event["risk_weight"] = {
        "lambda": 0.25,
        "weights_version": "2026-07",
        "tenancy_profile": "multi_tenant",
        "profile_source": "org-parameters",
    }
    result = store.ingest("layer", encode(document), Binding(layer_id="ledger:layer:widened"))
    row = store.conn.execute(
        "SELECT rationale, harness_version, risk_lambda, risk_weights_version, "
        "risk_tenancy_profile, risk_profile_source FROM layer_event "
        "WHERE binding_id = ? LIMIT 1",
        (result.binding_id,),
    ).fetchone()
    assert row[0] == "confirmed against the running service"
    assert row[1] == "0.8.3"
    assert row[2] == 0.25, "lambda is a number, queryable without json_extract"
    assert row[3:] == ("2026-07", "multi_tenant", "org-parameters")


def test_layer_event_escapes_nul_only_in_query_projection(store: Store) -> None:
    document = json.loads(sample("layer")[0])
    document["events"][0]["rationale"] = "argv\x00--flag=value"
    payload = encode(document)

    result = store.ingest("layer", payload, Binding(layer_id="ledger:layer:nul-rationale"))

    rationale = store.conn.execute(
        "SELECT rationale FROM layer_event WHERE binding_id = ? LIMIT 1",
        (result.binding_id,),
    ).fetchone()[0]
    assert rationale == r"argv\u0000--flag=value"
    assert store.get_binding(result.binding_id).artifact_digest == result.digest
