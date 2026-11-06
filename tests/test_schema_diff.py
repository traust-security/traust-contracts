from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("schema_diff", ROOT / "ci/schema_diff.py")
schema_diff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(schema_diff)


@pytest.fixture(autouse=True)
def isolated_git_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.mark.parametrize("namespace", ["artifacts_schema", "config", "views_schema"])
@pytest.mark.parametrize(
    ("change", "witness"),
    [
        ("removed_property", "validity"),
        ("newly_required", "validity"),
        ("removed_reason", "area_reported"),
    ],
)
def test_change_reports_include_each_contract_namespace_against_its_git_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    namespace: str,
    change: str,
    witness: str,
) -> None:
    git(tmp_path, "init", "--quiet")
    path = tmp_path / namespace / "v1/critical-misses.schema.json"
    path.parent.mkdir(parents=True)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "reason": {"enum": ["missed", "area_reported"]},
            "validity": {"type": ["string", "null"]},
        },
        "required": ["reason"],
    }
    path.write_text(json.dumps(schema))
    git(tmp_path, "add", ".")
    git(
        tmp_path,
        "-c",
        "user.name=Schema fixture",
        "-c",
        "user.email=schema@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture base",
    )
    base = git(tmp_path, "rev-parse", "HEAD")
    if change == "removed_property":
        del schema["properties"]["validity"]
    elif change == "newly_required":
        schema["required"].append("validity")
    else:
        schema["properties"]["reason"]["enum"].remove("area_reported")
    path.write_text(json.dumps(schema))
    monkeypatch.setattr(schema_diff, "ROOT", tmp_path)
    assert schema_diff.main([base]) == 0
    relative = path.relative_to(tmp_path).as_posix()
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith(relative + " ") and witness in line for line in lines)


def test_hook_context_cannot_redirect_fixture_commits(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    outer.mkdir()
    git(outer, "init", "--quiet")
    (outer / "marker.txt").write_text("outer evidence")
    git(outer, "add", ".")
    git(
        outer,
        "-c",
        "user.name=Schema fixture",
        "-c",
        "user.email=schema@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture marker",
    )
    before = git(outer, "rev-parse", "HEAD")
    environment = {
        **os.environ,
        "GIT_DIR": str(outer / ".git"),
        "GIT_WORK_TREE": str(outer),
        "GIT_INDEX_FILE": str(outer / ".git/index"),
    }
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            str(Path(__file__).resolve()),
            "-q",
            "-k",
            "views_schema and removed_property",
        ),
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert git(outer, "rev-parse", "HEAD") == before
    assert git(outer, "status", "--porcelain") == ""
