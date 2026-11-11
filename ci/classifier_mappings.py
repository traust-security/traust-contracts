#!/usr/bin/env python3
"""Validate field-specific historical mappings and account for typed inventory values.

This is an offline audit, not a runtime normalizer. Registry files own the
vocabulary; aliases only project explicitly reviewed historical observations.
Coverage may contain private inventory examples and must stay with its source.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS_PATH = ROOT / "mappings" / "v1" / "classifiers.json"
ENUMS_DIR = ROOT / "enums" / "v1"
ALIAS_STATUSES = frozenset({"mapped", "mapped_unknown", "non_evidence_operation", "unmapped"})
FIELD_STATUSES = frozenset({"unmapped", "observational", "open_label", "provenance"})
STATUSES = tuple(sorted(ALIAS_STATUSES | FIELD_STATUSES | {"observed_absence"}))


class MappingError(ValueError):
    """An invalid mapping, registry or typed inventory cannot support coverage."""


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MappingError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str):
    raise MappingError(f"not a finite JSON value: {value}")


def typed_key(value) -> tuple:
    """An exact, sortable JSON identity, including nested type distinctions."""
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int:
        return ("integer", value)
    if type(value) is float:
        if not math.isfinite(value):
            raise MappingError("raw values must be finite JSON values")
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, list):
        return ("array", tuple(typed_key(item) for item in value))
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ("object", tuple((key, typed_key(value[key])) for key in sorted(value)))
    raise MappingError("raw values must be JSON values with string object keys")


def _load(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_invalid_constant
        )
    except (ValueError, UnicodeError) as error:
        raise MappingError(f"{path}: {error}") from error
    if not isinstance(document, dict):
        raise MappingError(f"{path}: expected a JSON object")
    typed_key(document)
    return document, hashlib.sha256(raw).hexdigest()


def _nonempty_string(value, location: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise MappingError(f"{location}: expected a nonempty string")


def _field_name(value) -> None:
    _nonempty_string(value, "field name")
    parts = value.split("|")
    if len(parts) != 2 or any(not part or part != part.strip() for part in parts):
        raise MappingError(f"invalid field name {value!r}: expected artifact-type|inventory.field")


def _target(target, registry: dict[str, dict], *, nullable: bool, blocking: bool) -> None:
    if not isinstance(target, dict):
        raise MappingError("target must be an object")
    if set(target) == {"field", "value"}:
        if blocking and target["field"] == "blocked_external" and target["value"] is True:
            return
        raise MappingError("field targets may only explicitly set blocked_external to true")
    if set(target) != {"enum", "value"}:
        raise MappingError("enum target must contain exactly enum and value")
    name, value = target["enum"], target["value"]
    if not isinstance(name, str) or name not in registry:
        raise MappingError(f"target refers to unknown enum {name!r}")
    if value is None:
        if nullable:
            return
        raise MappingError("null enum targets require an explicit mapped_unknown alias")
    entry = registry[name]
    if not isinstance(value, str) or value not in entry["values"]:
        raise MappingError(f"target {name}.{value!r} is not a registry value")
    if value in entry.get("deprecated", {}):
        raise MappingError(f"target {name}.{value!r} is deprecated")


def validate_registry(registry: dict[str, dict]) -> None:
    """Check the current values and direct replacements used by this audit."""
    if not isinstance(registry, dict) or not registry:
        raise MappingError("registry must contain at least one named enum")
    for name, entry in registry.items():
        _nonempty_string(name, "enum name")
        if not isinstance(entry, dict) or entry.get("name") != name:
            raise MappingError(f"registry entry {name!r} must have the matching name")
        values = entry.get("values")
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) for value in values)
            or len(set(values)) != len(values)
        ):
            raise MappingError(f"{name}: values must be a nonempty list of unique strings")
        if not isinstance(entry.get("deprecated", {}), dict):
            raise MappingError(f"{name}: deprecated must be an object")
    for name, entry in registry.items():
        for value, spec in entry.get("deprecated", {}).items():
            if not isinstance(value, str) or not isinstance(spec, dict):
                raise MappingError(f"{name}: deprecated entries must be named objects")
            replacements = spec.get("replaced_by")
            if not isinstance(replacements, list):
                raise MappingError(f"{name}.{value}: replaced_by must be a list")
            retired = spec.get("retired", False)
            if type(retired) is not bool or (value in entry["values"]) == retired:
                raise MappingError(f"{name}.{value}: inconsistent retired flag and values")
            seen = set()
            for target in replacements:
                _target(target, registry, nullable=False, blocking=False)
                if target["enum"] in seen:
                    raise MappingError(f"{name}.{value}: duplicate replacement enum")
                seen.add(target["enum"])


def load_registry(directory: Path = ENUMS_DIR) -> tuple[dict[str, dict], dict[str, str]]:
    registry = {}
    hashes = {}
    for path in sorted(directory.glob("*.json")):
        entry, digest = _load(path)
        name = entry.get("name")
        _nonempty_string(name, f"{path}: enum name")
        if name in registry:
            raise MappingError(f"duplicate registry name {name!r}")
        registry[name] = entry
        hashes[path.name] = digest
    validate_registry(registry)
    return registry, hashes


def validate_mappings(mappings: dict, registry: dict[str, dict]) -> None:
    """Reject ambiguous aliases and targets outside the current registry."""
    validate_registry(registry)
    if not isinstance(mappings, dict) or set(mappings) != {"version", "fields"}:
        raise MappingError("mappings must contain exactly version and fields")
    if type(mappings["version"]) is not int or mappings["version"] != 1:
        raise MappingError("mapping version must be 1")
    if not isinstance(mappings["fields"], dict):
        raise MappingError("mapping fields must be an object")
    for field, binding in mappings["fields"].items():
        _field_name(field)
        if not isinstance(binding, dict):
            raise MappingError(f"{field}: binding must be an object")
        if "enum" not in binding:
            if set(binding) != {"status", "reason"}:
                raise MappingError(f"{field}: status binding requires exactly status and reason")
            if not isinstance(binding["status"], str) or binding["status"] not in FIELD_STATUSES:
                raise MappingError(f"{field}: unsupported field status")
            _nonempty_string(binding["reason"], f"{field}: reason")
            continue
        if set(binding) - {"enum", "nullable", "aliases"} or "aliases" not in binding:
            raise MappingError(
                f"{field}: enum binding requires enum, aliases and optional nullable"
            )
        name = binding["enum"]
        if not isinstance(name, str) or name not in registry:
            raise MappingError(f"{field}: unknown bound enum {name!r}")
        if type(binding.get("nullable", False)) is not bool:
            raise MappingError(f"{field}: nullable must be a boolean")
        if not isinstance(binding["aliases"], list):
            raise MappingError(f"{field}: aliases must be a list")
        seen = set()
        for alias in binding["aliases"]:
            if not isinstance(alias, dict) or set(alias) != {"raw", "targets", "status", "reason"}:
                raise MappingError(f"{field}: alias requires raw, targets, status and reason")
            key = typed_key(alias["raw"])
            if key in seen:
                raise MappingError(f"{field}: duplicate typed alias raw value")
            seen.add(key)
            status = alias["status"]
            if not isinstance(status, str) or status not in ALIAS_STATUSES:
                raise MappingError(f"{field}: unsupported alias status")
            _nonempty_string(alias["reason"], f"{field}: alias reason")
            targets = alias["targets"]
            if not isinstance(targets, list):
                raise MappingError(f"{field}: alias targets must be a list")
            if status in {"non_evidence_operation", "unmapped"}:
                if targets:
                    raise MappingError(f"{field}: {status} aliases cannot supply targets")
                continue
            if not targets:
                raise MappingError(f"{field}: mapped aliases require targets")
            dimensions = set()
            has_null = False
            for target in targets:
                _target(target, registry, nullable=status == "mapped_unknown", blocking=True)
                dimension = (
                    ("enum", target["enum"]) if "enum" in target else ("field", target["field"])
                )
                if dimension in dimensions:
                    raise MappingError(f"{field}: duplicate alias target dimension")
                dimensions.add(dimension)
                has_null |= "enum" in target and target["value"] is None
            if status == "mapped_unknown" and not has_null:
                raise MappingError(f"{field}: mapped_unknown requires a null enum target")


def _result(status: str, reason: str, targets: list[dict] | None = None) -> dict:
    return {"status": status, "reason": reason, "targets": copy.deepcopy(targets or [])}


def classify(raw, binding: dict | None, registry: dict[str, dict]) -> dict:
    """Classify one observation using an already validated field binding."""
    if binding is None:
        return _result("unmapped", "No field-specific binding is declared.")
    if "enum" not in binding:
        return _result(binding["status"], binding["reason"])
    key = typed_key(raw)
    for alias in binding["aliases"]:
        if typed_key(alias["raw"]) == key:
            return _result(alias["status"], alias["reason"], alias["targets"])
    if raw is None and binding.get("nullable", False):
        return _result(
            "observed_absence",
            "Observed null/absence; inventory nullability is not schema or write acceptance.",
        )
    name = binding["enum"]
    entry = registry[name]
    if isinstance(raw, str):
        deprecated = entry.get("deprecated", {})
        if raw in deprecated:
            targets = deprecated[raw]["replaced_by"]
            if targets:
                return _result("mapped", "Declared registry replacement.", targets)
            return _result("unmapped", "Deprecated registry value has no declared replacement.")
        if raw in entry["values"]:
            return _result(
                "mapped", "Exact current registry value.", [{"enum": name, "value": raw}]
            )
    return _result("unmapped", "No exact typed alias or current registry value applies.")


def _summary() -> dict:
    return {
        "observed_total": 0,
        "accounted_total": 0,
        "unmapped_total": 0,
        "unmapped_records": 0,
        "status_counts": dict.fromkeys(STATUSES, 0),
        "record_counts": dict.fromkeys(STATUSES, 0),
    }


def _account(summary: dict, status: str, count: int) -> None:
    summary["observed_total"] += count
    summary["accounted_total"] += count
    summary["status_counts"][status] += count
    summary["record_counts"][status] += 1
    if status == "unmapped":
        summary["unmapped_total"] += count
        summary["unmapped_records"] += 1


def coverage(inventory: dict, mappings: dict, registry: dict[str, dict]) -> dict:
    """Account for every typed raw entry without consulting legacy string counts."""
    validate_mappings(mappings, registry)
    if not isinstance(inventory, dict) or not isinstance(inventory.get("fields"), dict):
        raise MappingError("inventory must contain a fields object")
    report = {
        "version": 1,
        "inventory": {
            key: copy.deepcopy(inventory[key])
            for key in ("files", "unreadable", "provenance")
            if key in inventory
        },
        "fields": {},
        "totals": _summary(),
    }
    for field in sorted(inventory["fields"]):
        _field_name(field)
        observed = inventory["fields"][field]
        if not isinstance(observed, dict) or not isinstance(observed.get("raw_values"), list):
            raise MappingError(f"{field}: missing typed inventory raw_values list")
        if "total" in observed and (type(observed["total"]) is not int or observed["total"] < 0):
            raise MappingError(f"{field}: total must be a nonnegative integer, not a boolean")
        records = []
        summary = _summary()
        for observation in observed["raw_values"]:
            if (
                not isinstance(observation, dict)
                or not {"raw", "count"} <= set(observation)
                or set(observation) - {"raw", "count", "example"}
            ):
                raise MappingError(f"{field}: raw entry requires raw, count and optional example")
            count = observation["count"]
            if type(count) is not int or count <= 0:
                raise MappingError(f"{field}: count must be a positive integer, not a boolean")
            if "example" in observation and not isinstance(observation["example"], str):
                raise MappingError(f"{field}: example must be a string path")
            typed_key(observation["raw"])
            result = classify(observation["raw"], mappings["fields"].get(field), registry)
            records.append({**copy.deepcopy(observation), **result})
            _account(summary, result["status"], count)
            _account(report["totals"], result["status"], count)
        if "total" in observed and observed["total"] != summary["accounted_total"]:
            raise MappingError(f"{field}: typed observations do not cover the declared total")
        records.sort(
            key=lambda record: (
                typed_key(record["raw"]),
                record["count"],
                record.get("example", ""),
            )
        )
        report["fields"][field] = {**summary, "records": records}
    return report


def build_report(
    inventory_path: Path,
    mappings_path: Path = MAPPINGS_PATH,
    enums_dir: Path = ENUMS_DIR,
) -> dict:
    inventory, source_hash = _load(inventory_path)
    mappings, mapping_hash = _load(mappings_path)
    registry, registry_hashes = load_registry(enums_dir)
    report = coverage(inventory, mappings, registry)
    registry_content = json.dumps(registry_hashes, sort_keys=True, separators=(",", ":"))
    report["sha256"] = {
        "source": source_hash,
        "mappings": mapping_hash,
        "registry": hashlib.sha256(registry_content.encode("utf-8")).hexdigest(),
        "registry_files": registry_hashes,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--mappings", type=Path, default=MAPPINGS_PATH)
    parser.add_argument("--enums", type=Path, default=ENUMS_DIR)
    parser.add_argument("--check", action="store_true", help="exit 1 if any raw record is unmapped")
    args = parser.parse_args(argv)
    try:
        sources = [args.inventory, args.mappings, *args.enums.glob("*.json")]
        output = args.out.resolve()
        if any(
            output == path.resolve() or (output.exists() and output.samefile(path))
            for path in sources
        ):
            raise MappingError("coverage output must not overwrite an input artifact")
        report = build_report(args.inventory, args.mappings, args.enums)
        args.out.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except (MappingError, OSError, UnicodeError) as error:
        print(f"classifier-mappings: {error}", file=sys.stderr)
        return 2
    return int(args.check and report["totals"]["unmapped_records"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
