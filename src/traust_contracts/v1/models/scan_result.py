"""ScanResult model — from vuln-findings.schema.json."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from traust_contracts.v1.enums import Severity
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.models.finding import CVSS, DependencyProvenance


class ScanMetadata(ContractModel):
    repo: str
    repo_slug: str
    scanned_ref: str
    harness_version: str
    baseline: str | None = None
    baseline_findings: int = 0
    additional: dict[str, Any] | None = None


class ScanFinding(ContractModel):
    """A vuln-scan finding (unverified candidate)."""

    id: str
    file: str
    line: int | None
    category: str
    severity: Severity
    confidence: float
    title: str
    description: str
    recommendation: str
    scanner_ref: str | None = None
    cwe: str | None = None
    exploit_scenario: str | None = None
    confidence_reason: str | None = None
    cvss: CVSS | None = None
    dependency: DependencyProvenance | None = None


class KnownFinding(ContractModel):
    title: str
    matches_baseline_id: str


class ScanSummary(ContractModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    known: int
    low_confidence: int


class ScanResult(ContractModel):
    """Output of the vuln-scan skill."""

    target: str
    scanned_at: str
    focus_areas: list[str]
    metadata: ScanMetadata
    findings: list[ScanFinding] = Field(default_factory=list)
    known_findings: list[KnownFinding] = Field(default_factory=list)
    summary: ScanSummary | None = None
