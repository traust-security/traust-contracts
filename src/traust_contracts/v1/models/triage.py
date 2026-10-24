"""TriageReport model — from triage.schema.json."""

from __future__ import annotations

from pydantic import Field

from traust_contracts.v1.enums import Severity, Verdict
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.models.report import SeverityCounts


class TriageContext(ContractModel):
    environment: str
    votes_per_finding: int
    repo: str
    harness_version: str
    mode: str | None = None
    threat_model: list[str] | str | None = None
    scoring: str | None = None
    noise_tolerance: str | None = None
    findings_path: str | None = None
    source_report: str | None = None
    rerun_of: str | None = None
    reemitted: str | None = None
    reemit_method: str | None = None


class TriageSummary(ContractModel):
    input_count: int
    true_positives: int
    hardening: int
    false_positives: int
    undetermined: int
    duplicates: int
    by_severity: SeverityCounts
    needs_manual_test: int = 0


class VoteBreakdown(ContractModel):
    true_positive: int
    hardening: int
    false_positive: int
    cannot_verify: int


class TriageFinding(ContractModel):
    id: str
    title: str
    verdict: Verdict
    orig_id: str | None = None
    source: str | None = None
    file: str | None = None
    line: int | None = None
    category: str | None = None
    claimed_severity: Severity | str | None = None
    verify_verdict: str | None = None
    confidence: float | None = None
    severity: Severity | None = None
    severity_label: str | None = None
    severity_alignment: str | float | None = None
    preconditions: list[str] = Field(default_factory=list)
    access_level: str | None = None
    threat_match: str | None = None
    rationale: str | None = None
    recommendation: str | None = None
    vote_breakdown: VoteBreakdown | None = None
    refute_reasons: list[str] = Field(default_factory=list)
    exclusion_rule: str | int | None = None
    first_links: list[str] = Field(default_factory=list)
    duplicate_of: str | None = None
    absorbed: list[str] = Field(default_factory=list)
    owner_hint: str | None = None
    component: str | None = None
    missing_fields: list[str] = Field(default_factory=list)


class TriageReport(ContractModel):
    """Output of the triage skill."""

    triage_completed: str
    triage_context: TriageContext
    summary: TriageSummary
    findings: list[TriageFinding] = Field(default_factory=list)
