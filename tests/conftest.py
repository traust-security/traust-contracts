"""Shared test fixtures."""

import json
import warnings
from typing import Any, Never

import pytest
from storage_samples import encode, sample

from traust_contracts.v1.storage import Binding, Store

POSTGRES_DSN = "postgresql://traust:traust-test-only@127.0.0.1:5432/traust_test"
POSTGRES_SETUP = (
    "Run:\n  podman run --name traust-postgres --rm -d "
    "-e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only "
    "-e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 "
    "-v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16"
)


def skip_postgres(reason: str) -> Never:
    warnings.warn(
        f"PostgreSQL E2E skipped: {reason}. {POSTGRES_SETUP}",
        pytest.PytestWarning,
        stacklevel=2,
    )
    pytest.skip(reason)


@pytest.fixture(scope="session")
def postgres_dsn() -> str:
    try:
        import psycopg
    except ImportError:
        skip_postgres("psycopg is not installed")
    try:
        with psycopg.connect(POSTGRES_DSN, connect_timeout=2):
            pass
    except psycopg.OperationalError:
        skip_postgres("local database is unavailable")
    return POSTGRES_DSN


FINDINGS_SUMMARY_SCOPE = "local"
FINDINGS_SUMMARY_SUBJECT = "sci:inventory-item:42"
FINDINGS_SUMMARY_RUN = "sci:scan-result:7"
FINDINGS_SUMMARY_LAYER = "ledger:layer:1"

# Full rows, not a column slice: an earlier pair of tests compared only the
# repo/severity/verdict/count tail, so a divergence in the binding columns
# would have passed both.
FINDINGS_SUMMARY_ROWS = [
    (
        FINDINGS_SUMMARY_SCOPE,
        FINDINGS_SUMMARY_SUBJECT,
        FINDINGS_SUMMARY_RUN,
        FINDINGS_SUMMARY_LAYER,
        "https://example.test/repo",
        "high",
        "true_positive",
        1,
    ),
    (
        FINDINGS_SUMMARY_SCOPE,
        FINDINGS_SUMMARY_SUBJECT,
        FINDINGS_SUMMARY_RUN,
        FINDINGS_SUMMARY_LAYER,
        "https://example.test/repo",
        "low",
        None,
        1,
    ),
]


def seed_findings_summary(store: Store) -> None:
    """Ingest the one fixture both dialects' findings_summary tests assert on.

    Shared so a divergence between the SQLite and PostgreSQL views cannot hide
    behind two independently-authored setups.
    """
    finding_payload, _ = sample("vuln-findings")
    triage = json.loads(sample("triage")[0])
    triage["findings"][0]["orig_id"] = "REPO-abcdef0-001"
    layer_payload, _ = sample("layer")
    context = Binding(
        FINDINGS_SUMMARY_SCOPE,
        FINDINGS_SUMMARY_SUBJECT,
        FINDINGS_SUMMARY_RUN,
        FINDINGS_SUMMARY_LAYER,
    )
    store.ingest("vuln-findings", finding_payload, context)
    store.ingest("triage", encode(triage), context)
    store.ingest("layer", layer_payload, Binding(layer_id=FINDINGS_SUMMARY_LAYER))
    # findings_summary gets repo from ownership, not layer_metadata.
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "subjects": [
                    {
                        "subject_id": FINDINGS_SUMMARY_SUBJECT,
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Test",
                        "repo_url": "https://example.test/repo",
                        "is_branch_audit": False,
                    }
                ],
            }
        ),
        Binding(scope_id=FINDINGS_SUMMARY_SCOPE),
    )


def report_with_findings() -> bytes:
    """A cumulative report: two findings, one fully disposed, one bare.

    The shipped sample has zero findings, so the fan-out was unexercised.
    """
    document = json.loads(sample("report")[0])
    document["findings"] = [
        {
            "id": "FIND-001",
            "title": "Disposed finding",
            "severity": "high",
            "description": "x" * 50,
            "cwes": ["CWE-79"],
            "locations": [{"path": "a/b.go"}],
            "remediation": "x" * 20,
            "fingerprint": "a" * 64,
            "validation_status": "confirmed",
            "disposition": {
                "validity": "confirmed",
                "resolution": "fix_in_progress",
                "assurance": "execution_proven",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
                "conflict": False,
                "fp_overridden": True,
                "fp_reassertion_blocked": True,
                "refuted_awaiting_signoff": False,
                "severity_override": {
                    "severity": "critical",
                    "by": "signer@example.test",
                    "at": "2026-01-02T00:00:00Z",
                },
            },
        },
        {
            "id": "FIND-002",
            "title": "Undisposed finding",
            "severity": "low",
            "description": "y" * 50,
            "cwes": ["CWE-200"],
            "locations": [{"path": "c/d.go"}],
            "remediation": "y" * 20,
        },
    ]
    return encode(document)


def report_with_external_blocking() -> bytes:
    """Independent true/false flags and an unmapped historical blocking label."""
    document = json.loads(report_with_findings())
    document["findings"][0].update(remediation_effort="m", blocked_external=True)
    document["findings"][1].update(remediation_effort="m", blocked_external=False)
    document["findings"].append(
        {
            **document["findings"][1],
            "id": "FIND-003",
            "remediation_effort": "blocked-external",
        }
    )
    del document["findings"][2]["blocked_external"]
    return encode(document)


def seed_current_finding_detail(store: Store) -> None:
    """Ingest the fixture both dialects' current_finding_detail tests assert on.

    Shared so a divergence between the SQLite and PostgreSQL views cannot
    hide behind two independently-authored setups, mirroring
    seed_findings_summary. Five findings cover every exposure class; one
    carries a cvss score, an explicit effective severity and a triage
    verdict, one is bare (untriaged, no disposition), and the rest pin the
    classification boundaries.
    """
    document = json.loads(sample("report")[0])
    document["findings"] = [
        {
            "id": "FIND-001",
            "title": "Open disposed finding",
            "severity": "high",
            "effective_severity": "critical",
            "description": "x" * 50,
            "cwes": ["CWE-79"],
            "locations": [{"path": "a/b.go"}],
            "remediation": "x" * 20,
            "fingerprint": "a" * 64,
            "validation_status": "confirmed",
            "category": "injection",
            "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
            "disposition": {
                "validity": "confirmed",
                "resolution": "fix_in_progress",
                "assurance": "execution_proven",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
            },
        },
        {
            "id": "FIND-002",
            "title": "Bare undisposed finding",
            "severity": "low",
            "description": "y" * 50,
            "cwes": ["CWE-200"],
            "locations": [{"path": "c/d.go"}],
            "remediation": "y" * 20,
        },
        {
            "id": "FIND-003",
            "title": "Refuted finding",
            "severity": "medium",
            "description": "z" * 50,
            "cwes": ["CWE-89"],
            "locations": [{"path": "e/f.go"}],
            "remediation": "z" * 20,
            "disposition": {
                "validity": "false_positive",
                "resolution": "open",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
            },
        },
        {
            "id": "FIND-004",
            "title": "Resolved finding",
            "severity": "high",
            "description": "w" * 50,
            "cwes": ["CWE-22"],
            "locations": [{"path": "g/h.go"}],
            "remediation": "w" * 20,
            "disposition": {
                "validity": "confirmed",
                "resolution": "resolved",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
            },
        },
        {
            "id": "FIND-005",
            "title": "Hardening finding",
            "severity": "low",
            "description": "v" * 50,
            "cwes": ["CWE-693"],
            "locations": [{"path": "i/j.go"}],
            "remediation": "v" * 20,
            "disposition": {
                "validity": "hardening",
                "resolution": "open",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
            },
        },
        {
            "id": "FIND-006",
            "title": "Accepted-risk finding",
            "severity": "medium",
            "description": "u" * 50,
            "cwes": ["CWE-200"],
            "locations": [{"path": "k/l.go"}],
            "remediation": "u" * 20,
            "disposition": {
                "validity": "confirmed",
                "resolution": "risk_accepted",
                "last_updated": "2026-01-02T00:00:00Z",
                "events": [],
            },
        },
    ]
    context = Binding(FINDINGS_SUMMARY_SCOPE, FINDINGS_SUMMARY_SUBJECT, FINDINGS_SUMMARY_RUN)
    store.ingest("report", encode(document), context)
    triage = {
        "triage_completed": "2026-01-03",
        "triage_context": {
            "environment": "Synthetic test environment",
            "votes_per_finding": 1,
            "repo": "repo",
            "harness_version": "0.1.0",
        },
        "summary": {
            "input_count": 2,
            "true_positives": 1,
            "hardening": 0,
            "false_positives": 1,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        },
        "findings": [
            {
                "id": "f101",
                "title": "Confirmed authorization issue",
                "orig_id": "FIND-001",
                "verdict": "true_positive",
                "severity": "critical",
                "rationale": "Confirmed with a second account.",
            },
            {
                "id": "f102",
                "title": "Refuted",
                "orig_id": "FIND-003",
                "verdict": "false_positive",
                "severity": "medium",
            },
        ],
    }
    store.ingest("triage", encode(triage), context)
    # Ownership rides the spine; without a registry the owner columns read
    # NULL and the listing loses its denominator context.
    store.ingest(
        "corpus-registry",
        encode(
            {
                "version": 1,
                "subjects": [
                    {
                        "subject_id": FINDINGS_SUMMARY_SUBJECT,
                        "tree": "findings",
                        "ownership": "owned",
                        "business_unit": "Test",
                        "repo_url": "https://example.test/repo",
                        "is_branch_audit": False,
                    }
                ],
            }
        ),
        Binding(scope_id=FINDINGS_SUMMARY_SCOPE),
    )


def current_finding_detail_rows(
    *,
    is_branch_audit: Any,
    render_cwes: Any,
) -> list[tuple[Any, ...]]:
    """Expected current_finding_detail rows for seed_current_finding_detail.

    `is_branch_audit` and `render_cwes` carry the two columns whose Python
    representation differs by dialect (bool vs int; decoded list vs JSON
    text); every other column is identical, so the expectation stays
    single-sourced the way FINDINGS_SUMMARY_ROWS is.
    """
    context = (FINDINGS_SUMMARY_SCOPE, FINDINGS_SUMMARY_SUBJECT, FINDINGS_SUMMARY_RUN)
    owner = ("owned", "Test", "findings", is_branch_audit)

    def row(
        finding_id: str,
        title: str,
        severity: str,
        fingerprint: str | None,
        validity: str | None,
        resolution: str | None,
        assurance: str | None,
        category: str | None,
        cwes: list[str],
        effective_severity: str | None,
        cvss_score: float | None,
        triage_verdict: str | None,
        triage_severity: str | None,
        exposure_class: str,
    ) -> tuple[Any, ...]:
        return (
            *context,
            finding_id,
            title,
            severity,
            fingerprint,
            validity,
            resolution,
            assurance,
            category,
            render_cwes(cwes),
            effective_severity,
            "code",
            *owner,
            cvss_score,
            triage_verdict,
            triage_severity,
            exposure_class,
        )

    return [
        row(
            "FIND-001", "Open disposed finding", "high", "a" * 64, "confirmed",
            "fix_in_progress", "execution_proven", "injection", ["CWE-79"], "critical",
            8.1, "true_positive", "critical", "open",
        ),
        row(
            "FIND-002", "Bare undisposed finding", "low", None, None, None, None,
            None, ["CWE-200"], None, None, None, None, "open",
        ),
        row(
            "FIND-003", "Refuted finding", "medium", None, "false_positive", "open",
            None, None, ["CWE-89"], None, None, "false_positive", "medium",
            "false_positive",
        ),
        row(
            "FIND-004", "Resolved finding", "high", None, "confirmed", "resolved",
            None, None, ["CWE-22"], None, None, None, None, "closed",
        ),
        row(
            "FIND-005", "Hardening finding", "low", None, "hardening", "open", None,
            None, ["CWE-693"], None, None, None, None, "hardening",
        ),
        row(
            "FIND-006", "Accepted-risk finding", "medium", None, "confirmed",
            "risk_accepted", None, None, ["CWE-200"], None, None, None, None, "closed",
        ),
    ]
