"""Schema and enum path resolution from installed package data."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

_PKG = "traust_contracts"


def package_root() -> Path:
    """Root of the installed traust-contracts package data."""
    root = Path(importlib.resources.files(_PKG))
    if (root / "artifacts_schema").is_dir():
        return root
    # Editable dev checkout: repo root is three levels above this file
    return Path(__file__).resolve().parents[2]


def schema_dir(version: str = "v1") -> Path:
    return package_root() / "artifacts_schema" / version


def config_schema_dir(version: str = "v1") -> Path:
    """Directory of config-file schemas (config/<version>).

    Config schemas are versioned independently of the artifact schemas in
    artifacts_schema/<version>, so a config-shape change does not move the
    data major.
    """
    return package_root() / "config" / version


def config_schema_path(name: str, version: str = "v1") -> Path:
    """Resolve a config schema by basename (e.g. traust or feeds)."""
    if not name.endswith(".schema.json"):
        name = f"{name}.schema.json"
    p = config_schema_dir(version) / name
    if not p.is_file():
        raise FileNotFoundError(f"no such config schema: {p}")
    return p


def enum_dir(version: str = "v1") -> Path:
    return package_root() / "enums" / version


def schema_path(name: str, version: str = "v1") -> Path:
    """Resolve a schema file by basename (e.g. report.schema.json)."""
    if not name.endswith(".schema.json"):
        name = f"{name}.schema.json"
    p = schema_dir(version) / name
    if not p.is_file():
        raise FileNotFoundError(f"no such schema: {p}")
    return p


def enum_path(name: str, version: str = "v1") -> Path:
    if not name.endswith(".json"):
        name = f"{name}.json"
    p = enum_dir(version) / name
    if not p.is_file():
        raise FileNotFoundError(f"no such enum: {p}")
    return p


def db_dir(version: str = "v1") -> Path:
    """Root of the database contract: one version, three namespaces."""
    return package_root() / "db" / version


def storage_dir(version: str = "v1") -> Path:
    """Directory containing the authored storage (traust namespace) SQL."""
    return db_dir(version) / "traust"


def ops_dir(version: str = "v1") -> Path:
    """Directory containing the authored ops (traust_ops namespace) SQL."""
    return db_dir(version) / "traust_ops"


def ledger_dir(version: str = "v1") -> Path:
    """Directory containing the authored ledger (traust_ledger) SQL."""
    return db_dir(version) / "traust_ledger"
