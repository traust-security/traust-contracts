import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "artifacts_schema" / "v1"
SBOM_ID = "64342675-b69c-4f85-8cb5-b18e4afca97b"
ASSESSMENT_ID = "ce3f40d5-e00e-407d-8c04-02db7d70fe84"


def _validator() -> Draft202012Validator:
    resources = {}
    for path in SCHEMA_DIR.glob("*.schema.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        resources[doc.get("$id", path.name)] = Resource.from_contents(doc)
        resources[path.name] = Resource.from_contents(doc)
    schema = json.loads((SCHEMA_DIR / "manifest-coverage.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        registry=Registry().with_resources(resources.items()),
        format_checker=FormatChecker(),
    )


def _doc(unresolved: dict[str, dict[str, str]] | None = None) -> dict:
    return {
        "artifact": "manifest-coverage",
        "tool": {"name": "syft", "version": "1.51.1"},
        "sbom_id": SBOM_ID,
        "assessment_id": ASSESSMENT_ID,
        "unresolved": {} if unresolved is None else unresolved,
    }


def _validate_cli(tmp_path: Path, raw: str) -> subprocess.CompletedProcess[str]:
    artifact = tmp_path / "coverage.json"
    artifact.write_text(raw, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "validate.py"),
            "--schema",
            "manifest-coverage",
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "unresolved",
    [
        {},
        {
            "pypi": {"pyproject.toml": "no-lockfile", "requirements.txt": "unpinned"},
            "nuget": {"src/App/App.csproj": "no-lockfile"},
        },
        {
            "pypi": {"shared/manifest": "unpinned"},
            "nuget": {"shared/manifest": "no-lockfile"},
        },
    ],
)
def test_bound_complete_and_multi_ecosystem_reads_validate(
    tmp_path: Path, unresolved: dict[str, dict[str, str]]
) -> None:
    doc = _doc(unresolved)
    _validator().validate(doc)
    result = _validate_cli(tmp_path, json.dumps(doc))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("field", ["artifact", "tool", "sbom_id", "assessment_id", "unresolved"])
def test_missing_required_fields_are_rejected(tmp_path: Path, field: str) -> None:
    doc = _doc()
    del doc[field]
    assert not _validator().is_valid(doc)
    result = _validate_cli(tmp_path, json.dumps(doc))
    assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.parametrize("field", ["sbom_id", "assessment_id"])
@pytest.mark.parametrize("value", [None, "", "not-a-uuid", "a" * 64, 7, [], {}])
def test_bindings_must_be_native_uuids(tmp_path: Path, field: str, value: object) -> None:
    doc = _doc()
    doc[field] = value
    assert not _validator().is_valid(doc)
    result = _validate_cli(tmp_path, json.dumps(doc))
    assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/abs/pyproject.toml",
        "../pyproject.toml",
        "./pyproject.toml",
        "src/../pyproject.toml",
        "src/./pyproject.toml",
        ".",
        "..",
        "src/.",
        "src/..",
        "src//pyproject.toml",
        "pyproject.toml/",
        r"src\pyproject.toml",
        "C:/pyproject.toml",
        "C:pyproject.toml",
        "src/\0pyproject.toml",
    ],
)
def test_manifest_paths_must_be_canonical_repository_relative_paths(path: str) -> None:
    assert not _validator().is_valid(_doc({"pypi": {path: "no-lockfile"}}))


@pytest.mark.parametrize(
    "unresolved",
    [
        None,
        [],
        [
            {"ecosystem": "pypi", "path": "pyproject.toml", "reason": "no-lockfile"},
            {"ecosystem": "pypi", "path": "pyproject.toml", "reason": "no-lockfile"},
        ],
        {"pip": {"pyproject.toml": "no-lockfile"}},
        {"pypi": {}},
        {"pypi": []},
        {"pypi": "pyproject.toml"},
        {"pypi": {"pyproject.toml": "unknown"}},
        {"pypi": {"pyproject.toml": None}},
        {"pypi": {"pyproject.toml": []}},
        {"pypi": {"pyproject.toml": {"reason": "no-lockfile"}}},
    ],
)
def test_malformed_unresolved_values_are_rejected(unresolved: object) -> None:
    doc = _doc()
    doc["unresolved"] = unresolved
    assert not _validator().is_valid(doc)


@pytest.mark.parametrize("reason", ["no-lockfile", "unpinned"])
@pytest.mark.parametrize("duplicate_level", ["path", "ecosystem", "escaped-path"])
def test_cli_rejects_identical_and_conflicting_raw_manifest_keys(
    tmp_path: Path, reason: str, duplicate_level: str
) -> None:
    # Keep repeated members in raw JSON: constructing a dict would erase the defect.
    if duplicate_level == "ecosystem":
        unresolved = (
            '{"pypi": {"pyproject.toml": "no-lockfile"}, '
            f'"pypi": {{"pyproject.toml": "{reason}"}}}}'
        )
        duplicate_key = "pypi"
    else:
        second_key = (
            r"pyproject\u002etoml" if duplicate_level == "escaped-path" else "pyproject.toml"
        )
        unresolved = f'{{"pypi": {{"pyproject.toml": "no-lockfile", "{second_key}": "{reason}"}}}}'
        duplicate_key = "pyproject.toml"
    raw = (
        '{"artifact": "manifest-coverage", "tool": {"name": "syft", "version": "1.51.1"}, '
        f'"sbom_id": "{SBOM_ID}", "assessment_id": "{ASSESSMENT_ID}", '
        f'"unresolved": {unresolved}}}'
    )
    result = _validate_cli(tmp_path, raw)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "JSON parse error" in result.stdout
    assert "duplicate JSON member" in result.stdout
    assert duplicate_key in result.stdout
