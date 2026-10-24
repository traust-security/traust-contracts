"""Report model — from report.schema.json (top-level)."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from traust_contracts.v1.enums import RefKind, Severity
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.models.finding import Finding


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
    generated_at: str
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
