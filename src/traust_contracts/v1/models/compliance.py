"""Compliance models — from compliance-scope.schema.json and compliance-assessment.schema.json."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from traust_contracts.v1.enums import ComplianceVerdict
from traust_contracts.v1.models._base import ContractModel


class ScopeRepoEdge(ContractModel):
    repo: str
    reason: str


class DeploymentEvidence(ContractModel):
    inventory: str
    service: str


class Boundary(ContractModel):
    frameworks: list[str]
    resolves_via: str
    declared_by: str
    declared_at: str
    product: str | None = None
    include: list[ScopeRepoEdge] = Field(default_factory=list)
    exclude: list[ScopeRepoEdge] = Field(default_factory=list)
    notes: str | None = None
    deployment_evidence: DeploymentEvidence | None = None


class ComplianceScope(ContractModel):
    """Compliance scope registry (compliance-scope.yaml)."""

    version: int
    updated: str
    boundaries: dict[str, Boundary] = Field(default_factory=dict)


class AssessmentEvidence(ContractModel):
    sha256: str
    kind: str
    locator: str
    excerpt: str | None = None


class Override(ContractModel):
    by: str
    date: str
    rationale: str
    overridden_check_verdict: ComplianceVerdict | str | None = None


class NPassAgreement(ContractModel):
    passes: int
    agreed: bool


class AssessmentResult(ContractModel):
    framework: str
    control_id: str
    classification: str
    verdict: ComplianceVerdict | str
    verdict_source: str
    title: str | None = None
    check_id: str | None = None
    reason: str | None = None
    narrative: str | None = None
    evidence: list[AssessmentEvidence] = Field(default_factory=list)
    override: Override | None = None
    n_pass_agreement: NPassAgreement | None = None


class CoverageEntry(ContractModel):
    total_in_scope: int
    deterministic: int
    evidence_review: int
    organizational: int
    satisfied: int
    not_satisfied: int
    not_applicable: int
    not_assessed: int


class AssessmentMetadata(ContractModel):
    artifact: str
    harness_version: str
    target: dict[str, Any]
    frameworks: list[dict[str, Any]]
    registry_hash: str
    generated_at: str
    org_parameters_hash: str | None = None
    collector_versions: dict[str, str] | None = None


class ComplianceAssessment(ContractModel):
    """Compliance assessment artifact."""

    metadata: AssessmentMetadata
    coverage: dict[str, CoverageEntry] = Field(default_factory=dict)
    results: list[AssessmentResult] = Field(default_factory=list)
