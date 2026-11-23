"""Backport report model — from backport-report.schema.json."""

from __future__ import annotations

import re
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Self

from pydantic import AfterValidator, ConfigDict, Field, field_validator, model_validator

from traust_contracts.v1.models._base import ContractModel

_GIT_REF = r"^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}$"
_REPO_URL = r"^(https://|ssh://)"
_SHORT_SHA = r"^[0-9a-f]{7,40}$"
_FULL_SHA = r"^[0-9a-f]{40}$"
_CWE = r"^CWE-\d{1,5}$"
_SHA256 = r"^[a-f0-9]{64}$"
_HARNESS_VERSION = r"^\d+\.\d+\.\d+(-[0-9a-f]{7,40})?$"
_TITLE = re.compile(r"(backport|remediat|patch|fix)", re.I)


def _relative_path(value: str) -> str:
    """Mirror the schema's relative_path: never absolute, never traversal.

    Rejects a leading '/', a backslash (a Windows separator in a POSIX reader),
    a drive letter, and any '..' component.
    """
    if value.startswith("/") or "\\" in value:
        raise ValueError("path must be workspace-relative (no leading / or backslash)")
    if len(value) > 1 and value[1] == ":" and value[0].isalpha():
        raise ValueError("path must not be drive-qualified")
    if ".." in Path(value).parts:
        raise ValueError("path must not contain '..'")
    return value


RelativePath = Annotated[str, AfterValidator(_relative_path)]


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
    harness_version: str = Field(pattern=_HARNESS_VERSION)
    repository: str = Field(pattern=_REPO_URL)
    logical_product: str | None = None
    language: str | None = None
    operator: str | None = None
    #: Open on purpose: producer run records the contract does not declare yet.
    additional: dict[str, Any] | None = None


class SourceFix(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    commit: str = Field(pattern=_SHORT_SHA)
    branch: str = Field(pattern=_GIT_REF)
    fork_url: str | None = Field(default=None, pattern=_REPO_URL)
    remediation_path: RelativePath | None = None
    finding_refs: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)

    @field_validator("cwes")
    @classmethod
    def _cwes_are_ids(cls, values: list[str]) -> list[str]:
        bad = [v for v in values if not re.fullmatch(_CWE, v)]
        if bad:
            raise ValueError(f"cwes must be CWE-NNN: {bad}")
        return values


class Check(ContractModel):
    """A build or test run recorded as evidence. Never an instruction."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str
    outcome: CheckOutcome
    command: str | None = None
    duration_seconds: float | None = None
    log_path: RelativePath | None = None
    summary: str | None = None


class BranchResult(ContractModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    branch: str = Field(pattern=_GIT_REF)
    status: BackportStatus
    stop_reason: BackportStopReason | None = None
    phase_reached: str | None = None
    checks: list[Check] = Field(default_factory=list)
    cost_usd: float | None = None
    duration_seconds: float | None = None
    tokens_used: int | None = None
    has_patch: bool | None = None
    patch_path: RelativePath | None = None
    patch_sha256: str | None = Field(default=None, pattern=_SHA256)
    patch_files_changed: int | None = None
    backport_commit: str | None = Field(default=None, pattern=_FULL_SHA)
    backport_branch: str | None = Field(default=None, pattern=_GIT_REF)
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

    target_branch: str = Field(pattern=_GIT_REF)
    backport_commit: str | None = Field(default=None, pattern=_FULL_SHA)
    backport_branch: str | None = Field(default=None, pattern=_GIT_REF)


class VerificationHint(ContractModel):
    """Inputs for verify-remediation. Inputs only: no command line."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    original_audit_report: RelativePath | None = None
    repository: str | None = Field(default=None, pattern=_REPO_URL)
    #: None rather than [] so `to_dict()` drops an empty list the schema rejects;
    #: an explicitly supplied list must have an item (schema minItems: 1).
    branches: list[VerificationTarget] | None = Field(default=None, min_length=1)


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

    title: str = Field(min_length=5)
    metadata: BackportMetadata
    source_fix: SourceFix
    target_branches: list[BranchResult]
    summary: BackportSummary
    notes: str | None = None
    verification_hint: VerificationHint | None = None
    footer: str | None = None

    @field_validator("title")
    @classmethod
    def _title_names_the_artifact(cls, value: str) -> str:
        if not _TITLE.search(value):
            raise ValueError("title must name the artifact (backport/remediat/patch/fix)")
        return value

    def to_dict(self) -> dict[str, Any]:
        """Re-check the cross-field invariants before serializing.

        Mutating ``target_branches`` in place or assigning a nested summary
        field validates the child model, not this one, so the after-validator
        does not run again. Serialization is the last point where a stale
        summary or a duplicated branch can still be caught.
        """
        self._summary_is_derived_from_branches()
        return super().to_dict()

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
            stray: list[str] = []
            unidentified: list[str] = []
            mismatched: list[str] = []
            for target in self.verification_hint.branches:
                row = by_branch.get(target.target_branch)
                if row is None or row.status is not BackportStatus.SUCCEEDED:
                    stray.append(target.target_branch)
                    continue
                if not (target.backport_commit or target.backport_branch):
                    unidentified.append(target.target_branch)
                    continue
                if target.backport_commit and target.backport_commit != row.backport_commit:
                    mismatched.append(
                        f"{target.target_branch}: hint {target.backport_commit} "
                        f"!= landed {row.backport_commit}"
                    )
                elif target.backport_branch and target.backport_branch != row.backport_branch:
                    mismatched.append(
                        f"{target.target_branch}: hint {target.backport_branch} "
                        f"!= landed {row.backport_branch}"
                    )
            if stray:
                raise ValueError(f"verification_hint names branches that did not succeed: {stray}")
            if unidentified:
                raise ValueError(
                    "verification_hint must identify the backport it verifies "
                    f"(backport_commit or backport_branch): {unidentified}"
                )
            if mismatched:
                raise ValueError(
                    f"verification_hint disagrees with the landed backport: {mismatched}"
                )
        return self
