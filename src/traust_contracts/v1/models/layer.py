"""Layer disposition ledger — from layer.schema.json."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from traust_contracts.v1.enums import (
    DispositionEmbargo,
    DispositionResolution,
    EvidenceGrade,
    RestatementReason,
    RestatementTarget,
    ReviewReason,
    Severity,
    Validity,
)
from traust_contracts.v1.models._base import ContractModel
from traust_contracts.v1.timestamps import IsoTimestamp


class LayerActor(ContractModel):
    kind: str
    identity: str | None = None
    ldap_verified: bool | None = None
    identity_verified: bool | None = None
    identity_provider: str | None = None
    identity_issuer: str | None = None
    identity_subject: str | None = None
    employee_status: str | None = None
    display_name: str | None = None


class LayerSource(ContractModel):
    type: str
    ref: str
    actor: LayerActor


class LayerDisposition(ContractModel):
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    severity: Severity | None = None
    embargo: DispositionEmbargo | None = None


class ExternalRef(ContractModel):
    """An identifier this finding was escalated to or reconciled against in
    an external system — layer.schema.json layer_metadata.external_refs.

    PROVENANCE ONLY, and DERIVED. Lives in layer metadata beside
    finding_aliases rather than in the Merkle-signed event chain: it is
    recomputable from the advisory feed, it asserts nothing about validity,
    resolution or severity, and a reconciler re-run must not perturb a
    signed ledger.
    """

    system: str
    id: str
    url: str | None = None
    confidence: str | None = None
    matched_on: str | None = None
    stamped_at: str | None = None


class RestatementAuthority(ContractModel):
    ticket: str
    approved_by: str | None = None


class LayerRestatement(ContractModel):
    """Administrative restatement block — layer.schema.json $defs/event_restatement.

    Declared on the model, not only in the schema: ``ContractModel`` ignores
    unknown keys, so a block that exists only in JSON is silently dropped by any
    ``from_dict``/``to_dict`` round-trip. ``alias`` and ``finding`` were declared
    in the schema and omitted here, and that is exactly how they became
    unwritable through the typed path.
    """

    target: RestatementTarget
    reason: RestatementReason
    after: Any
    authority: RestatementAuthority
    before: Any = None
    schema_from: str | None = None
    schema_to: str | None = None


class LayerEvent(ContractModel):
    # Timestamps are validated here rather than left to the schema: jsonschema
    # asserts `format: date-time` only when the optional rfc3339-validator
    # package is present, so as bare `str` these were never checked anywhere.
    event_id: str
    finding_ref: str
    recorded_at: IsoTimestamp
    source: LayerSource
    disposition: LayerDisposition
    rationale: str
    occurred_at: IsoTimestamp | None = None
    harness_version: str | None = None
    auto_accept_tier: bool | None = None
    evidence_grade: EvidenceGrade | str | None = None
    # Stamped by the ledger write path. Declared here as well as in the schema
    # because ContractModel ignores unknown keys: without these fields a
    # from_dict/to_dict round-trip silently drops the identity stamp.
    fingerprint: str | None = None
    fingerprint_algo: str | None = None
    alias: dict[str, Any] | None = None
    finding: dict[str, Any] | None = None
    restatement: LayerRestatement | None = None


class ReviewItem(ContractModel):
    """A queued statement in the layer artifact, not the core review-item row."""

    queued_at: IsoTimestamp
    source_ref: str = Field(min_length=1)
    quote: str = Field(min_length=1)
    author: str = Field(min_length=1)
    status: str
    submitted_by: LayerActor | None = None
    suggested_finding_ref: str | None = None
    suggested_disposition: LayerDisposition | None = None
    queue_reason: ReviewReason | None = None
    resolution_note: str | None = None


class LayerMetadata(ContractModel):
    audit_report: str
    repository: str
    created: str
    harness_version: str
    audit_commit: str | None = None
    audit_report_sha256: str | None = None
    audit_report_ref: str | None = None
    updated: str | None = None
    claim_hashes: dict[str, str] = Field(default_factory=dict)
    finding_aliases: dict[str, Any] = Field(default_factory=dict)
    external_refs: dict[str, list[ExternalRef]] = Field(default_factory=dict)
    merkle_root: str | None = None
    merkle_epoch: int | None = None
    merkle_size: int | None = None


class Layer(ContractModel):
    """Findings disposition layer ledger."""

    metadata: LayerMetadata
    events: list[LayerEvent] = Field(default_factory=list)
    needs_review: list[ReviewItem] = Field(default_factory=list)
