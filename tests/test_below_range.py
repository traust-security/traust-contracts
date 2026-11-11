"""below-range-packets and below-range-verdicts: a commit's below-range evidence and its review."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

SCHEMAS = Path(__file__).parents[1] / "artifacts_schema/v1"
SHA = "a" * 64
GAP: dict[str, Any] = {
    "reason": "source_unavailable",
    "case": "lib@1.0.0--GHSA-aaaa-bbbb-cccc",
    "ecosystem": None,
    "package": None,
    "version": None,
    "detail": "ServiceError: 404",
    "tried": [],
}
PACKET: dict[str, Any] = {
    "case": "example@1.2.0--GHSA-xxxx-yyyy-zzzz",
    "candidate": {
        "ecosystem": "pypi",
        "package": "example",
        "version": "1.2.0",
        "advisory": "GHSA-xxxx-yyyy-zzzz",
        "kind": "below_range",
        "stated_start": "2.0.0",
        "major_distance": 1,
        "aliases": ["CVE-2026-0001"],
    },
    "advisory": {
        "identifier": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2026-0001"],
        "summary": "Path traversal in example",
        "details": "Versions 2.0.0 and later ...",
        "affected": {
            "ecosystem": "pypi",
            "name": "example",
            "spans": [{"introduced": "2.0.0", "fixed": "2.4.1", "last_affected": None}],
            "versions": [],
            "imports": [],
            "symbols": [],
        },
    },
    "fix": {
        "chosen": {
            "url": "https://github.com/example/example/commit/0123456789abcdef",
            "rank": 0,
            "error": None,
            "commits": [{"sha": "0123456789abcdef", "subject": "Reject .. in archive names"}],
            "files": 1,
            "files_in_installed_tree": 1,
            "names_advisory": True,
            "only_adds_code": False,
            "release_commit": False,
            "commit_date": "2026-09-01T00:00:00+00:00",
        },
        "alternatives": [],
        "fixed_releases": [{"version": "2.4.1", "published": None}],
    },
    "installed_source": {
        "url": "https://files.pythonhosted.org/packages/example-1.2.0.tar.gz",
        "sha256": SHA,
        "files": 40,
        "root": "_sources/example@1.2.0--GHSA-xxxx-yyyy-zzzz",
        "declared_by": None,
    },
    "hunk_presence": [
        {
            "patch_path": "example/archive.py",
            "installed_path": "example/archive.py",
            "hunks": [
                {"removed_lines": 2, "removed_present": 2, "added_lines": 3, "added_present": 0}
            ],
        }
    ],
    "dependency_sources": [],
    "dependency_gaps": [],
    "patch": "From 0123 Mon Sep 17 00:00:00 2001\n",
}
PACKETS: dict[str, Any] = {
    "artifact": "below-range-packets",
    "repository_ref_id": "6f1c1e2a-0000-4000-8000-000000000001",
    "installed_exact": 12,
    "skipped_installs": {"version:npm": 2},
    "candidates": 2,
    "packets": [PACKET],
    "coverage_gaps": [GAP],
    "status": "complete",
}
UNSURE = "undetermined"
REVIEW = {"model": "claude-opus-5-5", "verdict": "applicable", "evidence": "example/archive.py:41"}
VERDICTS: dict[str, Any] = {
    "artifact": "below-range-verdicts",
    "packets_assessment_id": "6f1c1e2a-0000-4000-8000-000000000002",
    "cases": [
        {
            "case": PACKET["case"],
            "reviews": [REVIEW, {**REVIEW, "model": "claude-sonnet-5-5", "verdict": UNSURE}],
            "judge": {
                "model": "claude-opus-5-5",
                "verdict": "applicable",
                "ruling": "the unpatched join is at example/archive.py:41",
            },
            "verdict": "applicable",
        }
    ],
    "coverage_gaps": [GAP],
}


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


@pytest.mark.parametrize(
    ("name", "doc"), [("below-range-packets", PACKETS), ("below-range-verdicts", VERDICTS)]
)
def test_a_complete_document_validates(name: str, doc: dict[str, Any]) -> None:
    _validator(name).validate(doc)


def test_an_empty_commit_is_a_document() -> None:
    empty = {**PACKETS, "candidates": 0, "packets": [], "coverage_gaps": [], "skipped_installs": {}}
    _validator("below-range-packets").validate(empty)
    _validator("below-range-verdicts").validate({**VERDICTS, "cases": [], "coverage_gaps": []})


def _set(doc: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    changed = deepcopy(doc)
    *parents, last = path.split(".")
    node: Any = changed
    for key in parents:
        node = node[int(key)] if key.isdigit() else node[key]
    if value is ...:
        del node[last]
    else:
        node[last] = value
    return changed


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("source_tree", "/tmp/x"),  # trees are working data, never stored
        ("packets.0.patch", ...),
        ("packets.0.installed_source.sha256", "not-a-digest"),
        ("packets.0.case", "../escape"),
        ("packets.0.candidate.kind", "above_range"),
        ("packets.0.candidate.ecosystem", "cobol"),
        ("coverage_gaps.0.reason", "skipped"),
        ("status", "partial"),
        ("artifact", "below-range"),
    ],
)
def test_malformed_packets_fail(path: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        _validator("below-range-packets").validate(_set(PACKETS, path, value))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("cases.0.reviews", [REVIEW]),  # two blind reviews, not one
        ("cases.0.reviews", [REVIEW, REVIEW, REVIEW]),
        ("cases.0.verdict", "likely"),
        ("cases.0.reviews.0.evidence", ""),
        ("cases.0.judge.ruling", ...),
        ("cases.0.approved_by", "someone"),  # no human queue (D4)
        ("coverage_gaps", ...),
        ("packets_assessment_id", "not-a-uuid"),
    ],
)
def test_malformed_verdicts_fail(path: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        _validator("below-range-verdicts").validate(_set(VERDICTS, path, value))
