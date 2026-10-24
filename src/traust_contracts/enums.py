"""
Alias to the current data-contract major (v1).
Pin to traust_contracts.v1.enums directly if
you need the shape fixed regardless of what "current" means later.
"""

from traust_contracts.v1.enums import (
    Assurance,
    Classification,
    ComplianceVerdict,
    DispositionEmbargo,
    DispositionResolution,
    EvidenceGrade,
    FindingKind,
    LayerReviewQueueReason,
    QueueReason,
    RefKind,
    ReviewReason,
    Severity,
    TriageQueueReason,
    ValidationVerdict,
    Validity,
    Verdict,
)

__all__ = [
    "Assurance",
    "Classification",
    "ComplianceVerdict",
    "DispositionEmbargo",
    "DispositionResolution",
    "EvidenceGrade",
    "FindingKind",
    "LayerReviewQueueReason",
    "QueueReason",
    "RefKind",
    "ReviewReason",
    "Severity",
    "TriageQueueReason",
    "ValidationVerdict",
    "Validity",
    "Verdict",
]
