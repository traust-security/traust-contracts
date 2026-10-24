"""Shared enums derived from contract JSON schemas."""

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Validity(StrEnum):
    CONFIRMED = "confirmed"
    CORRECTED = "corrected"
    FALSE_POSITIVE = "false_positive"
    NOT_VERIFIED = "not_verified"
    HARDENING = "hardening"
    NOT_AFFECTED = "not_affected"
    TRUE_POSITIVE = "true_positive"


class FindingKind(StrEnum):
    """Finding classification, independent of validity."""

    VULNERABILITY = "vulnerability"
    WEAKNESS = "weakness"


class EvidenceGrade(StrEnum):
    """Explicit evidence strength, E0 strongest; no grade is inferred from provenance."""

    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"


class DispositionResolution(StrEnum):
    OPEN = "open"
    FIX_IN_PROGRESS = "fix_in_progress"
    RESOLVED = "resolved"
    PARTIALLY_RESOLVED = "partially_resolved"
    RISK_ACCEPTED = "risk_accepted"
    REGRESSION_INTRODUCED = "regression_introduced"


class DispositionEmbargo(StrEnum):
    REQUIRED = "required"
    ACTIVE = "active"
    NOT_REQUIRED = "not_required"
    UNCERTAIN = "uncertain"


class RestatementTarget(StrEnum):
    """Metadata an administrative restatement event may replace
    (layer.schema.json $defs/event_restatement). Event content is deliberately
    absent: events are immutable and are restated by appending a superseding
    determination."""

    CLAIM_HASHES = "claim_hashes"
    AUDIT_REPORT_SHA256 = "audit_report_sha256"
    ARTIFACT_DIGESTS = "artifact_digests"


#: Every restatement target is a signature-bound metadata field: a write that
#: changes one without a covering restatement event is the rewrite the mechanism
#: exists to prevent. finding_aliases is deliberately absent -- a rebaseline
#: event records a rename in the Merkle-covered event stream, so the metadata
#: table is a rebuildable projection rather than authority.
SIGNED_METADATA_TARGETS = frozenset(RestatementTarget)


class RestatementReason(StrEnum):
    DATA_ERROR = "data_error"
    SCHEMA_MIGRATION = "schema_migration"
    BASELINE_REWRITE = "baseline_rewrite"
    OPERATOR_ERROR = "operator_error"


class Assurance(StrEnum):
    EXECUTION_PROVEN = "execution_proven"
    HUMAN_REVIEWED = "human_reviewed"
    MACHINE_VERIFIED = "machine_verified"
    CLAIMED = "claimed"


class TriageQueueReason(StrEnum):
    """Forward vocabulary for triage/remediation queues (enums/v1/triage-queue-reason.json)."""

    NEW_DISCOVERY = "new_discovery"
    SEVERITY_UPGRADE = "severity_upgrade"
    REGRESSION_DETECTED = "regression_detected"
    EVIDENCE_AVAILABLE = "evidence_available"
    REMEDIATION_READY = "remediation_ready"
    REMEDIATION_DUE = "remediation_due"
    FALSE_POSITIVE_DISPUTE = "false_positive_dispute"
    SCOPE_CHANGE = "scope_change"
    REVALIDATION_REQUIRED = "revalidation_required"
    SLA_ESCALATION = "sla_escalation"
    MANUAL_QUEUE = "manual_queue"
    DEPENDENCY_UPDATE = "dependency_update"
    PATCH_AVAILABLE = "patch_available"
    ANALYST_REVIEW = "analyst_review"


# Backwards-compatible alias
QueueReason = TriageQueueReason


class LayerReviewQueueReason(StrEnum):
    """Layer disposition review queue reasons (layer.schema.json review_item.queue_reason)."""

    AMBIGUOUS_STATEMENT = "ambiguous_statement"
    UNVERIFIED_IDENTITY = "unverified_identity"
    INSUFFICIENT_AUTHORITY = "insufficient_authority"
    NO_FINDING_ID = "no_finding_id"
    UNDETERMINED_FINDING = "undetermined_finding"
    FP_AUDIT_VALVE = "fp_audit_valve"
    NEEDS_MANUAL_TEST = "needs_manual_test"
    STALE_BASELINE = "stale_baseline"
    REBASELINE_MAPPING = "rebaseline_mapping"
    REBASELINE_UNMATCHED = "rebaseline_unmatched"
    UNSOUND_REFUTATION = "unsound_refutation"
    WEAK_CONFIRMATION = "weak_confirmation"
    UNGRADED_CONFIRMATION = "ungraded_confirmation"
    SEVERITY_PROPOSAL = "severity_proposal"
    NEEDS_IDENTITY = "needs_identity"


class ReviewReason(StrEnum):
    """Merged review vocabulary; historical layer and triage codes retain their meanings."""

    AMBIGUOUS_STATEMENT = "ambiguous_statement"
    UNVERIFIED_IDENTITY = "unverified_identity"
    INSUFFICIENT_AUTHORITY = "insufficient_authority"
    NO_FINDING_ID = "no_finding_id"
    UNDETERMINED_FINDING = "undetermined_finding"
    FP_AUDIT_VALVE = "fp_audit_valve"
    NEEDS_MANUAL_TEST = "needs_manual_test"
    STALE_BASELINE = "stale_baseline"
    REBASELINE_MAPPING = "rebaseline_mapping"
    REBASELINE_UNMATCHED = "rebaseline_unmatched"
    UNSOUND_REFUTATION = "unsound_refutation"
    WEAK_CONFIRMATION = "weak_confirmation"
    UNGRADED_CONFIRMATION = "ungraded_confirmation"
    SEVERITY_PROPOSAL = "severity_proposal"
    NEEDS_IDENTITY = "needs_identity"
    NEW_DISCOVERY = "new_discovery"
    SEVERITY_UPGRADE = "severity_upgrade"
    REGRESSION_DETECTED = "regression_detected"
    EVIDENCE_AVAILABLE = "evidence_available"
    REMEDIATION_READY = "remediation_ready"
    REMEDIATION_DUE = "remediation_due"
    FALSE_POSITIVE_DISPUTE = "false_positive_dispute"
    SCOPE_CHANGE = "scope_change"
    REVALIDATION_REQUIRED = "revalidation_required"
    SLA_ESCALATION = "sla_escalation"
    MANUAL_QUEUE = "manual_queue"
    DEPENDENCY_UPDATE = "dependency_update"
    PATCH_AVAILABLE = "patch_available"
    ANALYST_REVIEW = "analyst_review"


class RefKind(StrEnum):
    BRANCH = "branch"
    TAG = "tag"
    DEFAULT = "default"
    STREAM = "stream"


class Verdict(StrEnum):
    """Triage/verification finding verdict."""

    TRUE_POSITIVE = "true_positive"
    HARDENING = "hardening"
    UNDETERMINED = "undetermined"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class ValidationVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    BLOCKED_BY_SCOPE = "blocked_by_scope"
    NOT_ATTEMPTED = "not_attempted"


class ComplianceVerdict(StrEnum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class Classification(StrEnum):
    """Impact analysis repo classification."""

    AFFECTED = "affected"
    LIKELY_AFFECTED = "likely_affected"
    NOT_OBSERVED = "not_observed"
    VERSION_NOT_IN_RANGE = "version_not_in_range"
    NOT_IMPORTED = "not_imported"
    INCONCLUSIVE = "inconclusive"


class SourceType(StrEnum):
    """Event source type (layer.schema.json source_type)."""

    MR_COMMENT = "mr_comment"
    COMMIT = "commit"
    JIRA = "jira"
    INTERACTIVE = "interactive"
    VALIDATION_REPORT = "validation_report"
    VERIFICATION_REPORT = "verification_report"
    TRIAGE_REPORT = "triage_report"
    IMPACT_REPORT = "impact_report"
    VULN_SCAN_REPORT = "vuln_scan_report"
    FUZZ_REPORT = "fuzz_report"
    # Neither of these is an evidence class; both carry an empty disposition.
    # They were in the schema enum and missing here, so typed code could not
    # name the two source types that the precedence engine must NOT weigh.
    REBASELINE = "rebaseline"
    RESTATEMENT = "restatement"


class ActorKind(StrEnum):
    """Actor type for disposition events (layer.schema.json actor.kind)."""

    HUMAN = "human"
    MACHINE = "machine"


class EventValidity(StrEnum):
    """Layer-event validity, retaining historical correction and hardening values.
    Distinct from Validity, which includes audit-stage NOT_VERIFIED."""

    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CORRECTED = "corrected"
    HARDENING = "hardening"
    NOT_AFFECTED = "not_affected"
