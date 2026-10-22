"""Finding model — from report.schema.json#/$defs/finding."""

from __future__ import annotations

from pydantic import Field

from traust_contracts.v1.enums import Assurance, DispositionResolution, Severity, Validity
from traust_contracts.v1.models._base import ContractModel


class Location(ContractModel):
    path: str
    lines: str | None = None
    description: str | None = None


class EvidenceBlock(ContractModel):
    code: str
    language: str | None = None
    caption: str | None = None


class CVSS(ContractModel):
    score: float
    vector: str


class SeverityOverride(ContractModel):
    severity: Severity
    by: str
    at: str
    rationale: str | None = None


class Disposition(ContractModel):
    validity: Validity
    resolution: DispositionResolution
    last_updated: str
    events: list[str] = Field(default_factory=list)
    conflict: bool | None = None
    refuted_awaiting_signoff: bool | None = None
    assurance: Assurance | None = None
    fp_overridden: bool | None = None
    fp_reassertion_blocked: bool | None = None
    severity_override: SeverityOverride | None = None


class DependencyProvenance(ContractModel):
    """Supply-chain provenance for a dependency finding —
    report.schema.json#/$defs/finding/properties/dependency.

    Makes the finding SELF-DESCRIBING: `impact_artifact` is a pointer, not the
    source of truth, so a finding stays interpretable in object storage where
    the sibling artifact may not resolve by relative path. Also the join key
    for consumers that build their own database rather than reading the local
    SQLite projection.
    """

    advisory: str
    module: str
    ecosystem: str | None = None
    purl: str | None = None
    vulnerable_range: str | None = None
    fixed_version: str | None = None
    installed_version: str | None = None
    evidence_level: str | None = None
    classification: str | None = None
    impact_artifact: str | None = None


class Finding(ContractModel):
    """A security finding from an audit report."""

    id: str
    title: str
    severity: Severity
    cwes: list[str]
    locations: list[Location]
    description: str
    remediation: str
    asvs_references: list[str] = Field(default_factory=list)
    peach_references: list[str] = Field(default_factory=list)
    owasp_llm_references: list[str] = Field(default_factory=list)
    cvss: CVSS | None = None
    capec: list[str] = Field(default_factory=list)
    evidence: list[EvidenceBlock] = Field(default_factory=list)
    attack_pattern: str | None = None
    category: str | None = None
    validation_status: str | None = None
    source_findings: list[str] = Field(default_factory=list)
    origin: str | None = None
    pqc_classification: str | None = None
    remediation_effort: str | None = None
    blocked_external: bool | None = Field(default=None, strict=True)
    isolation_dimensions: list[str] = Field(default_factory=list)
    isolation_boundary: str | None = None
    disposition: Disposition | None = None
    fingerprint: str | None = None
    effective_severity: Severity | None = None
    passes: list[int] = Field(default_factory=list)
    dependency: DependencyProvenance | None = None
