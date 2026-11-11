from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1] / "artifacts_schema/v1"
ORDER = "00000000-0000-4000-8000-000000000001"
TASK = {
    "schema_version": "1",
    "run_id": ORDER,
    "skill": "dependency-watch",
    "mode": "below-range",
    "args": [],
    "models": {"reviewer_a": "review-model", "reviewer_b": "review-model", "judge": "judge-model"},
    "input": ["input/below-range.json", "input/case/fix.patch"],
    "output": {"path": "output/verdicts.json", "schema": "below-range-verdicts"},
}
ENTRY = {
    "skill": "dependency-watch",
    "mode": "below-range",
    "executor_session": "executor-1",
    "models": TASK["models"],
    "task_sha256": "a" * 64,
    "inputs": [{"path": "input/below-range.json", "bytes": 12, "sha256": "b" * 64}],
    "output": {"path": "output/verdicts.json", "sha256": "c" * 64, "artifact_id": ORDER},
}


def validate(name: str, doc: dict) -> None:
    schemas = [json.loads(p.read_text()) for p in ROOT.glob("*.schema.json")]
    registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas)
    schema = json.loads((ROOT / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(doc)


@pytest.mark.parametrize("run_id", [ORDER, None])
def test_ordered_and_manual_tasks_validate(run_id: str | None) -> None:
    validate("session-task", {**TASK, "run_id": run_id})


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../outside",
        "input/../../outside",
        "C:/file",
        "input\\file",
        "input/./file",
        "input//file",
        "input/\nfile",
        "input/file\n",
        "input/file\x00",
        "input/",
        "",
    ],
)
def test_task_paths_cannot_escape_the_task(path: str) -> None:
    with pytest.raises(ValidationError):
        validate("session-task", {**TASK, "input": [path]})


@pytest.mark.parametrize(
    "path",
    ["output/verdicts.json\n", "output/../verdicts.json", "/output/verdicts.json", "output/"],
)
def test_output_paths_are_regular_task_relative_names(path: str) -> None:
    with pytest.raises(ValidationError):
        validate(
            "session-task", {**TASK, "output": {"path": path, "schema": "below-range-verdicts"}}
        )


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "manual"},
        {"schema_version": "2"},
        {"models": {}},
        {"models": {"reviewer_a\n": "review-model"}},
        {"skill": "dependency-watch\n"},
        {"mode": "below-range\n"},
        {"input": ["input/a", "input/a"]},
        {"output": {"path": "input/verdicts.json", "schema": "below-range-verdicts"}},
    ],
)
def test_malformed_tasks_are_rejected(change: dict) -> None:
    with pytest.raises(ValidationError):
        validate("session-task", {**TASK, **change})


def test_results_keep_measured_usage_on_failure() -> None:
    validate(
        "session-result",
        {
            "session": "executor-1",
            "error": "executor exited 1",
            "usage": [
                {
                    "provider": "anthropic",
                    "model": "review-model",
                    "occurred_at": "2026-10-30T12:00:00Z",
                    "tokens_in": 5,
                    "tokens_out": 3,
                }
            ],
        },
    )


@pytest.mark.parametrize("counter", ["tokens_in", "tokens_out", "cache_read", "cache_creation"])
def test_negative_measured_counters_are_rejected(counter: str) -> None:
    usage = {
        "provider": "anthropic",
        "model": "review-model",
        "occurred_at": "2026-10-30T12:00:00Z",
        "tokens_in": 5,
        "tokens_out": 3,
    }
    validate("session-result", {"session": "executor-1", "usage": [usage], "error": None})
    with pytest.raises(ValidationError):
        validate(
            "session-result",
            {"session": "executor-1", "usage": [{**usage, counter: -1}], "error": None},
        )


def test_manifest_records_success_failure_and_multiple_sessions() -> None:
    failed = copy.deepcopy(ENTRY)
    failed["executor_session"] = None
    failed["output"].update(sha256=None, artifact_id=None)
    invalid = copy.deepcopy(ENTRY)
    invalid["executor_session"] = "executor-invalid"
    invalid["output"]["artifact_id"] = None
    validate("run-manifest", {"artifact": "run-manifest", "sessions": [ENTRY, failed, invalid]})
    validate("run-manifest", {"artifact": "run-manifest"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_sha256", "bad"),
        ("task_sha256", "a" * 64 + "\n"),
        ("inputs", [{"path": "input/a", "bytes": 0, "sha256": "a" * 64 + "\n"}]),
        (
            "output",
            {"path": "output/verdicts.json", "sha256": "a" * 64 + "\n", "artifact_id": ORDER},
        ),
        ("inputs", [{"path": "../secret", "bytes": 0, "sha256": "a" * 64}]),
        ("output", {"path": "output/verdicts.json", "sha256": None, "artifact_id": ORDER}),
    ],
)
def test_invalid_audit_entries_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        validate(
            "run-manifest", {"artifact": "run-manifest", "sessions": [{**ENTRY, field: value}]}
        )
