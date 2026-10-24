"""Typed model for the integrity-bound refuted finding register."""

from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field

from traust_contracts.v1.enums import Severity
from traust_contracts.v1.models._base import ContractModel


class RefutedEntry(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_ref: str
    title: str
    refute_reasons: list[str]
    tier: str
    evidence_refs: list[str]
    asserted_at: datetime
    asserted_by: str
    note: str
    triage_id: str | None = None
    source: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=0)
    category: str | None = None
    claimed_severity: Severity | str | None = None
    exclusion_rule: str | int | None = None


class RefutedRegister(ContractModel):
    """Refutations emitted by triage and validation producers."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    source: str
    generated_at: datetime
    entries: list[RefutedEntry]
    sources: list[str] | None = None
