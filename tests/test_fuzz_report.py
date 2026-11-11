"""The fuzz report: the document a `fuzz` assessment holds.

Shape derived from the retired create-fuzzing scripts (emit_fuzz_events.py,
build_fuzz_rollup.py) and their targets.json manifest: target and harnesses,
crashers with reproducer digests, measured coverage and unfuzzed surfaces.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/fuzz-report.schema.json"

REPORT: dict[str, Any] = {
    "artifact": "fuzz-report",
    "target": {
        "id": "example-operator",
        "language": "go",
        "module": "example.test/operator",
        "harnesses": [
            {
                "name": "FuzzParseRange",
                "engine": "go_native",
                "path": "api/v1/helper_fuzz_test.go",
                "package": "./api/v1",
                "duration_seconds": 900,
                "execs": 4_812_330,
                "corpus_entries": 211,
                "outcome": "crashed",
            },
            {
                "name": "FuzzRenderTemplate",
                "engine": "go_native",
                "path": "pkg/render/render_fuzz_test.go",
                "duration_seconds": 900,
                "execs": None,
                "outcome": "clean",
            },
        ],
    },
    "crashers": [
        {
            "id": "FuzzParseRange-001",
            "harness": "FuzzParseRange",
            "title": "parseRange indexes the split result without a length check",
            "signature": {"crash_class": "index_out_of_range", "stack_hash": "d8f26ecffa44a0c1"},
            "reproducer": {
                "sha256": "a" * 64,
                "path": "api/v1/testdata/fuzz/FuzzParseRange/d8f26ecffa44a0c1",
            },
            "sanitizer": None,
            "cwes": ["CWE-129"],
            "severity_proposal": "medium",
            "cvss": {"score": 4.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H"},
            "location": {"path": "api/v1/helper.go", "lines": "550"},
        },
        {
            "id": "FuzzParseRange-002",
            "harness": "FuzzParseRange",
            "title": "Path validator accepts a bare parent reference",
            "signature": {"crash_class": "invariant_violation", "stack_hash": None},
            "reproducer": {"sha256": "b" * 64, "uri": "s3://example-bucket/fuzz/b"},
            "sanitizer": None,
            "cwes": [],
            "severity_proposal": "low",
            "finding_id": "00000000-0000-4000-8000-000000000001",
        },
    ],
    "coverage": {"tool": "go cover", "lines_covered": 812, "lines_total": 1540},
    "gaps": [
        {"surface": "pkg/dns", "reason": "fuzzed_upstream", "note": "OSS-Fuzz target exists"},
        {"surface": "FuzzLoadConfig", "reason": "harness_defect", "harness": "FuzzLoadConfig"},
    ],
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def test_report_with_crashers_coverage_and_gaps(validator: Draft202012Validator) -> None:
    validator.validate(REPORT)


def test_clean_run_records_no_crasher_and_unmeasured_coverage(
    validator: Draft202012Validator,
) -> None:
    clean = deepcopy(REPORT)
    clean["crashers"], clean["gaps"], clean["coverage"] = [], [], None
    clean["target"]["harnesses"][0]["outcome"] = "clean"
    validator.validate(clean)


def _set(document: dict[str, Any], path: tuple[str | int, ...], value: object) -> None:
    node: Any = document
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("artifact",), "fuzz-rollup"),
        (("repository",), "https://example.test/repo"),
        (("target", "harnesses"), []),
        (("target", "harnesses", 0, "engine"), "go test -fuzz"),
        (("target", "harnesses", 0, "outcome"), "noop"),
        (("target", "harnesses", 0, "execs"), -1),
        (("target", "harnesses", 0, "duration_seconds"), None),
        (("crashers", 0, "signature", "crash_class"), "segfault"),
        (("crashers", 0, "signature", "stack_hash"), "not-a-hash"),
        (("crashers", 0, "reproducer", "sha256"), "short"),
        (("crashers", 0, "reproducer", "inline"), "AAAA"),
        (("crashers", 0, "sanitizer"), "asan"),
        (("crashers", 0, "cwes"), ["129"]),
        (("crashers", 0, "severity_proposal"), "moderate"),
        (("crashers", 0, "finding_id"), "FIND-001"),
        (("crashers", 0, "method"), "static scout"),
        (("coverage", "lines_total"), -5),
        (("gaps", 0, "reason"), "skipped"),
    ],
)
def test_rejects_unknown_or_malformed_fields(
    validator: Draft202012Validator, path: tuple[str | int, ...], value: object
) -> None:
    document = deepcopy(REPORT)
    _set(document, path, value)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("target",),
        ("crashers",),
        ("coverage",),
        ("gaps",),
        ("target", "harnesses", 0, "execs"),
        ("crashers", 0, "reproducer"),
        ("crashers", 0, "reproducer", "sha256"),
        ("crashers", 0, "signature", "stack_hash"),
        ("crashers", 0, "sanitizer"),
        ("crashers", 0, "severity_proposal"),
        ("gaps", 0, "reason"),
    ],
)
def test_requires_evidence_fields(
    validator: Draft202012Validator, path: tuple[str | int, ...]
) -> None:
    document = deepcopy(REPORT)
    node: Any = document
    for part in path[:-1]:
        node = node[part]
    del node[path[-1]]
    with pytest.raises(ValidationError):
        validator.validate(document)
