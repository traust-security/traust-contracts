import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).parent.parent / "artifacts_schema" / "v1"


def _validator() -> Draft202012Validator:
    resources = {}
    for path in SCHEMA_DIR.glob("*.schema.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        resources[doc.get("$id", path.name)] = Resource.from_contents(doc)
        resources[path.name] = Resource.from_contents(doc)
    schema = json.loads((SCHEMA_DIR / "manifest-coverage.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=Registry().with_resources(resources.items()))


def _doc(*unresolved: dict) -> dict:
    return {
        "artifact": "manifest-coverage",
        "tool": {"name": "syft", "version": "1.51.1"},
        "unresolved": list(unresolved),
    }


def test_a_complete_read_and_one_with_unresolved_manifests_validate() -> None:
    validator = _validator()
    validator.validate(_doc())
    validator.validate(
        _doc(
            {"ecosystem": "pypi", "path": "pyproject.toml", "reason": "no-lockfile"},
            {"ecosystem": "nuget", "path": "src/App/App.csproj", "reason": "no-lockfile"},
        )
    )


@pytest.mark.parametrize(
    "manifest",
    [
        {"ecosystem": "pip", "path": "pyproject.toml", "reason": "no-lockfile"},
        {"ecosystem": "pypi", "path": "/abs/pyproject.toml", "reason": "no-lockfile"},
        {"ecosystem": "pypi", "path": "../pyproject.toml", "reason": "no-lockfile"},
        {"ecosystem": "pypi", "path": "pyproject.toml", "reason": "unknown"},
        {"ecosystem": "pypi", "path": "pyproject.toml"},
        {"ecosystem": "pypi", "path": "pyproject.toml", "reason": "no-lockfile", "extra": 1},
    ],
)
def test_a_malformed_manifest_entry_is_rejected(manifest: dict) -> None:
    assert not _validator().is_valid(_doc(manifest))


def test_the_document_names_its_tool() -> None:
    doc = _doc()
    del doc["tool"]
    assert not _validator().is_valid(doc)
