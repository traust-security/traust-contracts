"""Report model — from report.schema.json (top-level)."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field, model_validator

from traust_contracts.v1.enums import RefKind, Severity
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.models.finding import DependencyProvenance, Finding
from traust_contracts.v1.timestamps import IsoTimestamp


class LocBreakdown(ContractModel):
    total: int
    by_language: dict[str, int] | None = None
    tool: str | None = None
    excludes: list[str] | None = None


class ReportMetadata(ContractModel):
    date: str
    scope: str
    repository: str | None = None
    commit: str | None = None
    ref: str | None = None
    ref_kind: RefKind | None = None
    framework: str | None = None
    auditor: str | None = None
    methodology: str | None = None
    loc_reviewed: int | str | None = None
    loc_breakdown: LocBreakdown | None = None
    tools: list[str] = Field(default_factory=list)
    additional: dict[str, Any] | None = None
    audit_profile: str | None = None


class SeverityCounts(ContractModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ExecutiveSummary(ContractModel):
    prose: str
    severity_counts: SeverityCounts
    key_risks: list[str] = Field(default_factory=list)
    positive_observations: list[str] = Field(default_factory=list)


class SeverityCriterion(ContractModel):
    level: Severity
    definition: str
    cvss_range: str | None = None


class SeverityCountEntry(ContractModel):
    severity: Severity
    count: int
    finding_ids: list[str] = Field(default_factory=list)


class RoadmapItem(ContractModel):
    explicit_null_fields = frozenset({"effort"})

    priority: str
    action: str
    addresses: list[str] = Field(default_factory=list)
    effort: str | None = None
    blocked_external: bool | None = Field(default=None, strict=True)


class ResolutionCounts(ContractModel):
    open: int = 0
    fix_in_progress: int = 0
    resolved: int = 0
    partially_resolved: int = 0
    risk_accepted: int = 0
    regression_introduced: int = 0


class ValidityCounts(ContractModel):
    confirmed: int = 0
    corrected: int = 0
    false_positive: int = 0
    not_verified: int = 0
    hardening: int = 0
    not_affected: int = 0
    true_positive: int = 0


class DispositionSummary(ContractModel):
    layer_ref: str
    generated_at: IsoTimestamp
    by_resolution: ResolutionCounts
    by_validity: ValidityCounts
    severity_overrides: list[dict[str, Any]] | None = None


class NegativeResult(ContractModel):
    check: str
    outcome: str
    detail: str | None = None


class ScannerCorrelation(ContractModel):
    """Scanner overlap/correlation section (schema-defined keys vary by report)."""

    model_config = ConfigDict(extra="allow")


class AsvsChapter(ContractModel):
    chapter: str
    area: str
    requirements_assessed: int | None = None
    violations: int | None = None
    highest_severity: Severity | None = None


class DependencyAuditEntry(ContractModel):
    package: str
    version: str
    status: str
    notes: str | None = None


class DependencyAudit(ContractModel):
    omit_unset_empty_fields = frozenset({"entries"})

    prose: str | None = None
    entries: list[DependencyAuditEntry] = Field(default_factory=list)


_ELIMINATING = frozenset({"version_not_in_range", "not_imported"})
_NEVER_ELIMINATED = frozenset({"affected", "likely_affected", "inconclusive", "not_observed"})


class NotAffectedEntry(ContractModel):
    """One scanner-matched advisory the audit eliminated as not affected, and why: by an
    impact-analysis row (out of range, not imported, or unreachable at symbol level) or by a
    vendor statement cited in `reference`. report.schema.json#/$defs/not_affected_entry."""

    dependency: DependencyProvenance
    rationale: str = Field(min_length=1)
    reference: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _eliminated_by_evidence(self) -> NotAffectedEntry:
        dep = self.dependency
        classification = None if dep.classification is None else str(dep.classification)
        by_impact = dep.impact_artifact is not None and (
            classification in _ELIMINATING
            or (classification == "not_observed" and dep.evidence_level == "symbol")
        )
        by_vendor = self.reference is not None and classification not in _NEVER_ELIMINATED
        if not (by_impact or by_vendor):
            raise ValueError(
                "a not_affected entry needs impact evidence (version_not_in_range, "
                "not_imported, or not_observed at evidence_level symbol, with impact_artifact) "
                "or a vendor reference with no affected classification"
            )
        return self


class PeachInterface(ContractModel):
    omit_unset_empty_fields = frozenset({"hardening_gaps", "finding_ids"})

    name: str
    complexity: str
    shared: bool
    boundary_type: str
    hardening_gaps: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    notes: str | None = None


class PeachIsolationReview(ContractModel):
    """PEACH tenant-isolation review; required for harness >= 0.15.0."""

    omit_unset_empty_fields = frozenset({"interfaces"})

    applicable: bool
    rationale: str | None = None
    interfaces: list[PeachInterface] = Field(default_factory=list)


class ReviewSurfaceEntry(ContractModel):
    """One review surface's outcome; conditional requirements stay schema-side."""

    omit_unset_empty_fields = frozenset({"finding_ids"})

    status: str
    finding_ids: list[str] = Field(default_factory=list)
    note: str | None = None


class Report(ContractModel):
    """Security audit/assessment report."""

    title: str
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    severity_criteria: list[SeverityCriterion] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    findings_summary: list[SeverityCountEntry] = Field(default_factory=list)
    remediation_roadmap: list[RoadmapItem] = Field(default_factory=list)
    footer: str | None = None
    disposition_summary: DispositionSummary | None = None
    negative_results: list[NegativeResult] = Field(default_factory=list)
    scanner_correlation: ScannerCorrelation | None = None
    asvs_coverage: list[AsvsChapter] | None = None
    dependency_audit: DependencyAudit | None = None
    not_affected: list[NotAffectedEntry] | None = None
    peach_isolation_review: PeachIsolationReview | None = None
    review_surface_coverage: dict[str, ReviewSurfaceEntry] | None = None
