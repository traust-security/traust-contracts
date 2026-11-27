"""Report model — from report.schema.json (top-level)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import ConfigDict, Field, field_validator, model_validator

from traust_contracts.v1.enums import ComponentTargetStrategy, RefKind, Severity
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.models.finding import DependencyProvenance, Finding
from traust_contracts.v1.timestamps import IsoTimestamp


class LocBreakdown(ContractModel):
    total: int
    by_language: dict[str, int] | None = None
    tool: str | None = None
    excludes: list[str] | None = None


COMPONENT_PURL_PATTERN = (
    r"^pkg:[a-z][a-z0-9.+-]*/(@[^?#@/]+/)?([^?#@/]+/)*[^?#@/]+@[^?#@]+(\?[^#]*)?(#.*)?$"
)
COMPONENT_COMMIT_PATTERN = r"^([0-9a-f]{40}|[0-9a-f]{64})$"


class ComponentTargetProvenance(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Annotated[str, Field(min_length=1)]
    ref: Annotated[str, Field(min_length=1)]
    digest: Annotated[str, Field(min_length=1)]
    manifest_version: Annotated[str, Field(min_length=1)] | None = None

    @field_validator("manifest_version", mode="before")
    @classmethod
    def _reject_explicit_null_manifest_version(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("manifest_version must be a non-empty string when present, not null")
        return value


class ComponentTargetVerification(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    strategy: ComponentTargetStrategy
    manifest_paths: Annotated[tuple[Annotated[str, Field(min_length=1)], ...], Field(min_length=1)]
    provenance: ComponentTargetProvenance | None = None

    @field_validator("provenance", mode="before")
    @classmethod
    def _reject_explicit_null_provenance(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("provenance must be an object when present, not null")
        return value

    @model_validator(mode="after")
    def _check_provenance_strategy_consistency(self) -> ComponentTargetVerification:
        is_external = self.strategy == ComponentTargetStrategy.EXTERNAL_PROVENANCE
        has_provenance = self.provenance is not None
        if is_external and not has_provenance:
            raise ValueError(
                "verification.provenance is required when strategy is 'external_provenance'"
            )
        if not is_external and has_provenance:
            raise ValueError(
                f"verification.provenance must be omitted when strategy is '{self.strategy}'"
            )
        return self


class ComponentTarget(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    purl: Annotated[str, Field(pattern=COMPONENT_PURL_PATTERN)]
    repository: Annotated[str, Field(min_length=1)]
    commit: Annotated[str, Field(pattern=COMPONENT_COMMIT_PATTERN)]
    module_path: Annotated[str, Field(min_length=1)]
    release_ref: Annotated[str, Field(min_length=1)] | None = None
    verification: ComponentTargetVerification

    @field_validator("release_ref", mode="before")
    @classmethod
    def _reject_explicit_null_release_ref(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("release_ref must be a non-empty string when present, not null")
        return value


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
    target: ComponentTarget | None = None

    @field_validator("target", mode="before")
    @classmethod
    def _reject_explicit_null_target(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("metadata.target must be an object when present, not null")
        return value

    @model_validator(mode="after")
    def _check_target_consistency(self) -> ReportMetadata:
        if self.target is None:
            return self
        if (
            self.commit
            and self.commit.strip()
            and self.target.commit != self.commit.strip().lower()
        ):
            raise ValueError(
                f"metadata.target.commit ({self.target.commit}) does not match "
                f"metadata.commit ({self.commit})"
            )
        if (
            self.repository
            and self.repository.strip()
            and self.target.repository.strip().rstrip("/") != self.repository.strip().rstrip("/")
        ):
            raise ValueError(
                f"metadata.target.repository ({self.target.repository}) does not match "
                f"metadata.repository ({self.repository})"
            )
        return self


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
    impact-analysis row (out of range, or not imported) or by a vendor statement cited in
    `reference`. govulncheck's not_observed never eliminates (it is evidence for triage).
    report.schema.json#/$defs/not_affected_entry."""

    dependency: DependencyProvenance
    rationale: str = Field(min_length=1, pattern=r"\S")
    reference: str | None = Field(default=None, min_length=1, pattern=r"\S")

    @model_validator(mode="after")
    def _eliminated_by_evidence(self) -> NotAffectedEntry:
        dep = self.dependency
        classification = None if dep.classification is None else str(dep.classification)
        by_impact = bool(dep.impact_artifact and dep.impact_artifact.strip()) and (
            classification in _ELIMINATING
        )
        by_vendor = bool(self.reference and self.reference.strip()) and (
            classification not in _NEVER_ELIMINATED
        )
        if not (by_impact or by_vendor):
            raise ValueError(
                "a not_affected entry needs impact evidence (version_not_in_range or "
                "not_imported, with impact_artifact) or a vendor reference with no affected "
                "classification"
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
