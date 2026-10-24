"""Validation model — from validation.schema.json."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from traust_contracts.v1.enums import EvidenceGrade
from traust_contracts.v1.models._base import ContractModel


class TargetFingerprint(ContractModel):
    adapter: str
    identity: str
    version: str | None = None
    digest: str | None = None
    details: dict[str, Any] | None = None


class ValidationMetadata(ContractModel):
    date: str
    harness_version: str
    scope_binding_mode: str
    target_fingerprint: list[TargetFingerprint] = Field(default_factory=list)
    scope_source: str | None = None
    engagement: str | None = None
    authorized_by: str | None = None
    expires: str | None = None
    approval: dict[str, Any] | None = None
    flags: list[str] = Field(default_factory=list)
    additional: dict[str, Any] | None = None


class SourceReport(ContractModel):
    kind: str
    path: str
    sha256: str | None = None


class ValidationSummary(ContractModel):
    by_verdict: dict[str, int]
    by_technique: dict[str, int]
    prose: str | None = None
    novel_count: int | None = None
    chain_count: int | None = None
    highest_impact_chain: str | None = None


class EvidenceArtifact(ContractModel):
    type: str
    path: str
    sha256: str | None = None
    caption: str | None = None


class StepResult(ContractModel):
    step_id: str
    adapter: str
    verb: str
    classification: str
    verdict: str
    finding_ref: str | None = None
    novel_ref: str | None = None
    target: dict[str, Any] | None = None
    expected: str | None = None
    observed: str | None = None
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    rollback_performed: bool | None = None
    rollback_output: str | None = None
    scope_reason: str | None = None
    duration_ms: int | None = None
    soundness_flag: str | None = None
    error: str | None = None


class ValidatedFinding(ContractModel):
    source_id: str
    source_report: str
    verdict: str
    technique: str
    title: str | None = None
    claimed_severity: str | None = None
    steps: list[StepResult] = Field(default_factory=list)
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    observed_impact: str | None = None
    deviation_from_claim: str | None = None
    rollback_performed: bool | None = None
    not_attempted_reason: str | None = None
    soundness_flag: str | None = None
    evidence_grade: EvidenceGrade | str | None = None
    grade_rationale: str | None = None


class AttackChain(ContractModel):
    chain_id: str
    name: str
    entry_point: str
    terminal_asset: str
    steps: list[StepResult]
    verdict: str
    mitre_attack_refs: list[str] = Field(default_factory=list)
    narrative: str | None = None


class Validation(ContractModel):
    """Live validation report."""

    title: str
    metadata: ValidationMetadata
    source_reports: list[SourceReport]
    summary: ValidationSummary
    validated_findings: list[ValidatedFinding] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    novel_findings: list[dict[str, Any]] = Field(default_factory=list)
    execution_log_ref: str = ""
    execution_log_sha256: str | None = None
    footer: str | None = None
