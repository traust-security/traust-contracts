#!/usr/bin/env python3
"""
Structural validator for traust-contracts artifacts.

Usage:
    python validate.py --schema <name> FILE...
    python validate.py --list

Exits 0 if all artifacts valid, 1 if any fail.
"""

import json
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
        print(f"{artifact_path}: JSON parse error: {e}")
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
        print(f"{artifact_path}: {path_str}: {error.message}")

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
