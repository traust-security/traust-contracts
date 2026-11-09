"""Backport report model — from backport-report.schema.json."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import Any, Self

from pydantic import ConfigDict, Field, model_validator

from traust_contracts.v1.models._base import ContractModel


class BackportStatus(StrEnum):
    """Outcome of one target branch, not a pipeline mechanic."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class BackportStopReason(StrEnum):
    """Why a run stopped before producing a backport on a branch."""

    PIPELINE_STOP = "pipeline_stop"
    PIPELINE_ESCALATION = "pipeline_escalation"
    WORKTREE_ERROR = "worktree_error"
    TIMEOUT = "timeout"
    ERROR = "error"


class CheckOutcome(StrEnum):
    """Shares the vocabulary of remediation.check.outcome."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


class BackportMetadata(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    date: str
    harness_version: str
    repository: str
    logical_product: str | None = None
    language: str | None = None
    operator: str | None = None
    #: Open on purpose: producer run records the contract does not declare yet.
    additional: dict[str, Any] | None = None


class SourceFix(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    commit: str
    branch: str
    fork_url: str | None = None
    remediation_path: str | None = None
    finding_refs: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)


class Check(ContractModel):
    """A build or test run recorded as evidence. Never an instruction."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str
    outcome: CheckOutcome
    command: str | None = None
    duration_seconds: float | None = None
    log_path: str | None = None
    summary: str | None = None


class BranchResult(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    branch: str
    status: BackportStatus
    stop_reason: BackportStopReason | None = None
    phase_reached: str | None = None
    checks: list[Check] = Field(default_factory=list)
    cost_usd: float | None = None
    duration_seconds: float | None = None
    tokens_used: int | None = None
    has_patch: bool | None = None
    patch_path: str | None = None
    patch_sha256: str | None = None
    patch_files_changed: int | None = None
    backport_commit: str | None = None
    backport_branch: str | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _status_carries_its_evidence(self) -> Self:
        """Mirror the schema's if/then rules.

        JSON Schema can enforce the same document shape; the model repeats it
        so a constructed model cannot serialize into a schema-invalid report.
        """
        if self.status is BackportStatus.SUCCEEDED:
            missing = []
            if self.has_patch is not True:
                missing.append("has_patch: true")
            if not self.patch_sha256:
                missing.append("patch_sha256")
            if not (self.backport_commit or self.backport_branch):
                missing.append("backport_commit or backport_branch")
            if missing:
                raise ValueError(f"succeeded branch {self.branch!r} is missing {missing}")
        if self.status is BackportStatus.FAILED and self.stop_reason is None:
            raise ValueError(f"failed branch {self.branch!r} needs a stop_reason")
        return self


class VerificationTarget(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    target_branch: str
    backport_commit: str | None = None
    backport_branch: str | None = None


class VerificationHint(ContractModel):
    """Inputs for verify-remediation. Inputs only: no command line."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    original_audit_report: str | None = None
    repository: str | None = None
    #: None rather than [] so `to_dict()` drops an empty list the schema rejects.
    branches: list[VerificationTarget] | None = None


class BackportSummary(ContractModel):
    """Counts derived from target_branches; never independently authored."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    total: int = Field(ge=1)
    succeeded: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(default=0, ge=0)
    total_cost_usd: float | None = None
    total_duration_seconds: float | None = None


class BackportReport(ContractModel):
    """A fix propagated across release branches, one entry per branch."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    title: str
    metadata: BackportMetadata
    source_fix: SourceFix
    target_branches: list[BranchResult]
    summary: BackportSummary
    notes: str | None = None
    verification_hint: VerificationHint | None = None
    footer: str | None = None

    @model_validator(mode="after")
    def _summary_is_derived_from_branches(self) -> Self:
        """The arithmetic JSON Schema cannot express.

        A report whose summary disagrees with its own branches is the shape a
        producer bug or a tampered artifact takes, and it validates. Readers
        must recompute; this makes the model refuse to carry the lie.
        """
        counted = Counter(branch.status for branch in self.target_branches)
        branches = Counter(branch.branch for branch in self.target_branches)
        duplicated = sorted(name for name, runs in branches.items() if runs > 1)
        if duplicated:
            raise ValueError(f"target_branches repeats a branch: {duplicated}")
        expected = {
            "total": len(self.target_branches),
            "succeeded": counted[BackportStatus.SUCCEEDED],
            "failed": counted[BackportStatus.FAILED],
            "skipped": counted[BackportStatus.SKIPPED],
        }
        actual = {name: getattr(self.summary, name) for name in expected}
        mismatched = {
            name: {"declared": actual[name], "branches": expected[name]}
            for name in expected
            if actual[name] != expected[name]
        }
        if mismatched:
            raise ValueError(f"summary disagrees with target_branches: {mismatched}")
        if self.verification_hint and self.verification_hint.branches:
            by_branch = {entry.branch: entry for entry in self.target_branches}
            stray = [
                target.target_branch
                for target in self.verification_hint.branches
                if target.target_branch not in by_branch
                or by_branch[target.target_branch].status is not BackportStatus.SUCCEEDED
            ]
            if stray:
                raise ValueError(f"verification_hint names branches that did not succeed: {stray}")
        return self
