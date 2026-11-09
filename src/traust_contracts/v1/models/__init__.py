"""Typed Pydantic models derived from contract JSON schemas."""

from traust_contracts.v1.models.adapter import AdapterMetadata, AdapterResult, AdapterSummary
from traust_contracts.v1.models.backport import (
    BackportMetadata,
    BackportReport,
    BackportStatus,
    BackportStopReason,
    BackportSummary,
    BranchResult,
    Check,
    CheckOutcome,
    SourceFix,
    VerificationHint,
    VerificationTarget,
)
from traust_contracts.v1.models.compliance import ComplianceAssessment, ComplianceScope
from traust_contracts.v1.models.finding import (
    CVSS,
    DependencyProvenance,
    Disposition,
    EvidenceBlock,
    Finding,
    Location,
    SeverityOverride,
)
from traust_contracts.v1.models.impact import ImpactAnalysis
from traust_contracts.v1.models.layer import (
    ExternalRef,
    Layer,
    LayerEvent,
    LayerMetadata,
    LayerRestatement,
    RestatementAuthority,
    ReviewItem,
)
from traust_contracts.v1.models.metrics import MetricsRecord
from traust_contracts.v1.models.refuted_register import RefutedEntry, RefutedRegister
from traust_contracts.v1.models.remediation import Remediation
from traust_contracts.v1.models.report import NegativeResult, Report
from traust_contracts.v1.models.scan_result import (
    ScanFinding,
    ScanMetadata,
    ScanResult,
    ScanSummary,
)
from traust_contracts.v1.models.triage import TriageReport
from traust_contracts.v1.models.validation import Validation
from traust_contracts.v1.models.verification import (
    Verification,
    VerificationMetadata,
    VerifiedFinding,
)

__all__ = [
    "CVSS",
    "AdapterMetadata",
    "AdapterResult",
    "AdapterSummary",
    "BackportMetadata",
    "BackportReport",
    "BackportStatus",
    "BackportStopReason",
    "BackportSummary",
    "BranchResult",
    "Check",
    "CheckOutcome",
    "ComplianceAssessment",
    "ComplianceScope",
    "DependencyProvenance",
    "Disposition",
    "EvidenceBlock",
    "ExternalRef",
    "Finding",
    "ImpactAnalysis",
    "Layer",
    "LayerEvent",
    "LayerMetadata",
    "LayerRestatement",
    "Location",
    "MetricsRecord",
    "NegativeResult",
    "RefutedEntry",
    "RefutedRegister",
    "Remediation",
    "Report",
    "RestatementAuthority",
    "ReviewItem",
    "ScanFinding",
    "ScanMetadata",
    "ScanResult",
    "ScanSummary",
    "SeverityOverride",
    "SourceFix",
    "TriageReport",
    "Validation",
    "Verification",
    "VerificationHint",
    "VerificationMetadata",
    "VerificationTarget",
    "VerifiedFinding",
]
