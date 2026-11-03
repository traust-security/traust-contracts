"""ImpactAnalysis model — from impact-analysis.schema.json."""

from __future__ import annotations

from pydantic import Field

from traust_contracts.v1.enums import Classification
from traust_contracts.v1.models._base import ContractModel


class ImpactMetadata(ContractModel):
    cve: str
    module: str
    vulnerable_range: str
    harness_version: str
    generated_at: str
    tiers_executed: list[str]
    options: dict[str, bool]
    ecosystem: str | None = None
    fixed_version: str | None = None
    vulnerable_symbols: list[str] = Field(default_factory=list)
    vulnerable_packages: list[str] = Field(default_factory=list)
    feature_description: str | None = None
    advisory_sources: list[str] = Field(default_factory=list)
    portfolio_graph_db: str | None = None
    preparation_scope: dict | None = None


class ImpactSummary(ContractModel):
    repos_in_blast_radius: int
    version_in_range: int
    affected: int
    likely_affected: int
    not_observed: int
    version_not_in_range: int
    not_imported: int
    inconclusive: int
    product_surfaces: list[str] = Field(default_factory=list)


class RepoEvidence(ContractModel):
    l1_depends_on: bool | None = None
    l1_version_in_range: bool | None = None
    l4_package_imported: bool | None = None
    l4_packages_found: list[str] | None = None
    govulncheck: str | None = None
    govulncheck_trace: list[str] | None = None
    feature_pattern_matches: int | None = None
    binary_string_scan: str | None = None
    needs_manual_trace: bool | None = None
    notes: str | None = None
    manifest_scan: str | None = None
    manifest_version: str | None = None
    source_import_scan: str | None = None
    binary_linked_library: str | None = None
    evidence_level: str | None = None
    symbol_usage_scan: str | None = None
    binary_symbol_scan: str | None = None
    sbom_scan: str | None = None
    sbom_shipped_version: str | None = None


class RepoEntry(ContractModel):
    repo: str
    classification: Classification
    evidence: RepoEvidence
    products: list[str] = Field(default_factory=list)
    version: str | None = None
    direct: bool | None = None


class ImpactAnalysis(ContractModel):
    """CVE impact analysis report."""

    metadata: ImpactMetadata
    summary: ImpactSummary
    repos: list[RepoEntry] = Field(default_factory=list)
