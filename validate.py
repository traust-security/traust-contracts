#!/usr/bin/env python3
"""
Structural validator for traust-contracts artifacts.

Usage:
    python validate.py --schema <name> FILE...
    python validate.py --list

Exits 0 if all artifacts valid, 1 if any fail.
"""

import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

SCHEMA_DIR = Path(__file__).parent / "artifacts_schema" / "v1"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON members before decoding can discard their evidence."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def build_registry() -> Registry:
    """Build $ref registry across all schemas for cross-file references."""
    resources = {}
    for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        resource = Resource.from_contents(doc)
        # Register by both $id and filename for compatibility
        if "$id" in doc:
            resources[doc["$id"]] = resource
        resources[sf.name] = resource

    return Registry(resources=resources)


# Userinfo in any authority (`scheme://…@`, protocol-relative `//…@`) and a bare
# `user:password@` (scp-style or unprefixed).
_USERINFO = re.compile(r"(//)[^/?#\s@]*@|(?<![\w.+-])[^\s'\"/@:]+:[^\s/@]+@")


def _scrub(text: str) -> str:
    """Text for validation output, with any URL's userinfo removed.

    jsonschema's messages quote rejected values, property names and whole
    objects; a clone URL with credentials (`https://user:secret@host/…`) can
    sit anywhere in them and must not reach validation output.
    """
    return _USERINFO.sub(lambda m: (m.group(1) or "") + "<credentials>@", text)


def _describe(error) -> str:
    """The failure from the schema's side, never quoting the rejected value.

    jsonschema's message starts with the instance's repr, and an artifact value
    (a clone URL with a password, an unexpected property name) is untrusted. The
    keyword and what the schema expected identify the failure without it.
    """
    expected = error.validator_value
    if error.validator in {"additionalProperties", "unevaluatedProperties"}:
        return f"fails {error.validator}: unexpected propert(ies) not allowed"
    if error.validator in {"required", "dependentRequired"}:
        return error.message  # names the schema's property, not an artifact value
    if isinstance(expected, dict | list) and error.validator not in {"enum", "type"}:
        return f"fails {error.validator}"
    return f"fails {error.validator}: expected {expected!r}"


def validate_artifact(schema_name: str, artifact_path: Path) -> bool:
    """Validate artifact against a schema basename and optional JSON Pointer fragment."""
    basename, separator, fragment = schema_name.partition("#")
    schema_file = SCHEMA_DIR / f"{basename}.schema.json"
    if not schema_file.exists():
        print(f"{artifact_path}: schema not found: {basename}.schema.json")
        return False

    try:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        artifact = json.loads(
            artifact_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except ValueError as e:
        print(_scrub(f"{artifact_path}: JSON parse error: {e}"))
        return False

    registry = build_registry()
    if separator:
        reference = schema["$id"] + "#" + fragment
        try:
            registry.resolver().lookup(reference)
        except Unresolvable as error:
            print(f"{artifact_path}: invalid schema selector {schema_name!r}: {error}")
            return False
        schema = {"$schema": schema["$schema"], "$ref": reference}
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())

    valid = True
    for error in validator.iter_errors(artifact):
        valid = False
        path_str = (
            ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "<root>"
        )
        print(_scrub(f"{artifact_path}: {path_str}: {_describe(error)}"))

    # Content gates are whole-document cross-field rules. A JSON Pointer
    # fragment selects a sub-schema (a bare `#` selects the whole document),
    # so gates run only when no fragment narrowed the selection.
    whole_document = fragment == ""
    return valid and (not whole_document or _content_gates(basename, artifact, artifact_path))


def _content_gates(basename: str, artifact: dict, artifact_path: Path) -> bool:
    """Cross-field content gates the JSON Schema drafts cannot express.

    The README documents these as "the content gate": structural validation
    alone lets inconsistent facts through, so the CLI enforces them here.
    """
    valid = True
    if basename == "fuzz-campaign":
        for i, pattern in enumerate(artifact.get("patterns", [])):
            tested, vulnerable = pattern.get("tested"), pattern.get("vulnerable")
            if isinstance(tested, int) and isinstance(vulnerable, int) and vulnerable > tested:
                valid = False
                print(
                    f"{artifact_path}: patterns[{i}]: vulnerable ({vulnerable}) "
                    f"exceeds tested ({tested})"
                )
    if basename == "backport-report":
        # JSON Schema cannot express the arithmetic or per-property
        # uniqueness, and a report whose summary disagrees with its own
        # branches is what a producer bug or a tampered artifact looks like.
        branches = artifact.get("target_branches") or []
        summary = artifact.get("summary") or {}
        counts = {"succeeded": 0, "failed": 0, "skipped": 0}
        seen: dict[str, int] = {}
        for entry in branches:
            name = entry.get("branch")
            seen[name] = seen.get(name, 0) + 1
            if entry.get("status") in counts:
                counts[entry["status"]] += 1
        expected = {"total": len(branches), **counts}
        # `skipped` is optional in the schema (a report with none omits it);
        # treat an absent value as zero, like the model does.
        declared = {key: summary.get(key, 0) for key in expected}
        wrong = {
            key: {"declared": declared[key], "branches": value}
            for key, value in expected.items()
            if declared[key] != value
        }
        if wrong:
            valid = False
            print(f"{artifact_path}: summary disagrees with target_branches: {wrong}")
        duplicated = sorted(name for name, runs in seen.items() if runs > 1)
        if duplicated:
            valid = False
            print(f"{artifact_path}: target_branches repeats a branch: {duplicated}")
        # The verification hint is a pre-filled input for verify-remediation: it
        # must point at a backport this report says landed, in its own repository.
        hint = artifact.get("verification_hint") or {}
        rows = {entry.get("branch"): entry for entry in branches}
        for target in hint.get("branches") or []:
            name = target.get("target_branch")
            row = rows.get(name)
            if row is None or row.get("status") != "succeeded":
                valid = False
                print(f"{artifact_path}: verification_hint names a non-succeeded branch: {name}")
                continue
            if not (target.get("backport_commit") or target.get("backport_branch")):
                valid = False
                print(
                    f"{artifact_path}: verification_hint must identify the backport it "
                    f"verifies (backport_commit or backport_branch): {name}"
                )
                continue
            if target.get("backport_commit") and target["backport_commit"] != row.get(
                "backport_commit"
            ):
                valid = False
                print(f"{artifact_path}: verification_hint commit disagrees with {name}'s row")
            if target.get("backport_branch") and target["backport_branch"] != row.get(
                "backport_branch"
            ):
                valid = False
                print(f"{artifact_path}: verification_hint branch disagrees with {name}'s row")
        repository = hint.get("repository")
        allowed = {
            (artifact.get("metadata") or {}).get("repository"),
            (artifact.get("source_fix") or {}).get("fork_url"),
        } - {None}
        if repository is not None and repository not in allowed:
            valid = False
            print(
                f"{artifact_path}: verification_hint.repository is neither "
                "metadata.repository nor source_fix.fork_url"
            )
    if basename == "repo-liveness":
        for key, entry in artifact.get("repositories", {}).items():
            if entry.get("repository_id") != key:
                valid = False
                print(
                    f"{artifact_path}: repositories[{key}]: repository_id "
                    f"({entry.get('repository_id')}) does not match its map key"
                )
    return valid


def list_schemas():
    """Print available schemas."""
    schemas = sorted(sf.stem for sf in SCHEMA_DIR.glob("*.schema.json"))
    print(f"\nAvailable schemas ({len(schemas)}):\n")
    for schema in schemas:
        print(f"  {schema}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate.py --schema <name> FILE...")
        print("       python validate.py --list")
        sys.exit(1)

    if sys.argv[1] == "--list":
        list_schemas()
        return 0

    if sys.argv[1] == "--schema":
        if len(sys.argv) < 4:
            print("Usage: python validate.py --schema <name> FILE...")
            sys.exit(1)

        schema_name = sys.argv[2]
        artifact_paths = [Path(p) for p in sys.argv[3:]]

        all_valid = True
        for artifact_path in artifact_paths:
            if not artifact_path.exists():
                print(f"{artifact_path}: file not found")
                all_valid = False
            elif not validate_artifact(schema_name, artifact_path):
                all_valid = False

        sys.exit(0 if all_valid else 1)

    else:
        print(f"Unknown option: {sys.argv[1]}")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
