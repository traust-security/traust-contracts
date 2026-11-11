"""Config contract + canonical loader for the AI security harness.

Contracts owns the *universals* of configuration: what files live in the
config home (``traust.yaml`` and ``model-registry.yaml``), their shapes
(``config/v1/*.schema.json``), where they live (``$TRAUST_CONFIG_HOME``), and
the readiness audit. traust-core's ``Config`` is the typed reader of
``traust.yaml``; product data (tool pins, safe-exec profiles, feeds) ships with
traust and is validated against its ``config/v1`` schema where it is read.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from pydantic import BaseModel, ConfigDict

from traust_contracts.paths import config_schema_path

# --- resolution universals ----------------------------------------------------

#: Environment variable naming the one config root every consumer reads from.
TRAUST_CONFIG_HOME_ENV = "TRAUST_CONFIG_HOME"
#: Documented default, created by ``scripts/install_traust`` for adopters.
TRAUST_CONFIG_HOME_DEFAULT = Path.home() / ".traust" / "config"


class DeploymentConfigMissing(FileNotFoundError):
    """A required config file (or the config home itself) could not be resolved.

    Raised instead of silently falling back to a template or an empty default:
    a harness that runs on placeholder data reports numbers about nobody's
    estate and calls them real.
    """


def deployment_config_dir() -> Path | None:
    """The one config home, or ``None`` when there is none.

    ``$TRAUST_CONFIG_HOME`` when set; else the documented default
    ``~/.traust/config`` if it exists. One variable, one answer — no workspace
    scanning, no marker files, no second root in any code tree.
    """
    val = os.environ.get(TRAUST_CONFIG_HOME_ENV)
    if val:
        return Path(val).expanduser()
    if TRAUST_CONFIG_HOME_DEFAULT.is_dir():
        return TRAUST_CONFIG_HOME_DEFAULT
    return None


# --- completeness audit (doctor / CI) -----------------------------------------
# The loader parses any schema-valid file; completeness checks report what the
# operator still needs.

_CORE_LOCATION_FIELDS = (
    "workspace",
    "analysis_results",
    "progress_tracker",
)


def config_completeness_audit(
    *,
    config_home: Path | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` for a config home: ``traust.yaml`` and
    ``model-registry.yaml``. Errors block a production-ready deployment; warnings
    flag values the operator may still want to set."""
    warnings: list[str] = []
    try:
        ctx = load_context(config_home=config_home)
    except DeploymentConfigMissing as exc:
        return [str(exc)], warnings

    if ctx.traust is None:
        return [], [
            "traust.yaml: absent — zero-config local defaults (SQLite under ~/.traust); "
            "copy traust.example.yaml to set locations and the ledger key"
        ]
    locations = ctx.traust.locations or Locations()
    warnings += [
        f"traust.yaml: locations.{field} unset"
        for field in _CORE_LOCATION_FIELDS
        if not getattr(locations, field)
    ]
    if not (ctx.traust.ledger or {}).get("public_key_path"):
        warnings.append(
            "traust.yaml: ledger.public_key_path unset — layer signatures are not verified"
        )
    return [], warnings


# --- typed sections -----------------------------------------------------------
# Permissive by design: the authoritative shape check is the JSON schema applied
# at load time; these models give typed access to the top-level keys and keep
# everything else via pydantic's extra="allow".


class _Section(BaseModel):
    model_config = ConfigDict(extra="allow")

    #: sha256[:12] of the source file this section was parsed from, set by the
    #: loader. Provenance for stamps/ledger rows without the core touching a file.
    source_sha: str | None = None


class LongPromptPricing(_Section):
    """Prices for a request whose prompt is over ``above_tokens``.

    The prompt counts input, cache reads and cache writes. Over the threshold
    these prices replace the base prices for every token of the request.
    """

    above_tokens: int
    price_per_mtok_in: float
    price_per_mtok_out: float


class ModelSpec(_Section):
    """One concrete model: its tier class and (optional) list prices."""

    tier: str
    batch_eligible: bool = False
    price_per_mtok_in: float | None = None
    price_per_mtok_out: float | None = None
    #: cache-hit price as a fraction of the input price; None means 0.1
    cache_read_multiplier: float | None = None
    long_prompt: LongPromptPricing | None = None


class ProviderSpec(_Section):
    models: dict[str, ModelSpec]
    #: free-form: a structured block in some estates, a prose note in others.
    data_handling: Any = None


class RoleSpec(_Section):
    """A routing role: the tier floor and the approved models at/above it."""

    floor: str
    approved: list[str] = []
    candidates: list[str] = []


class ModelRegistry(_Section):
    version: Any
    #: tier class name -> metadata (ordering is by _TIER_ORDER in the consumer).
    tiers: dict[str, Any]
    providers: dict[str, ProviderSpec]
    roles: dict[str, RoleSpec]
    updated: Any = None
    escalation: dict[str, Any] | None = None

    def all_models(self) -> dict[str, ModelSpec]:
        """Every model across providers, keyed by id (ids are unique)."""
        return {mid: m for p in self.providers.values() for mid, m in p.models.items()}


class Locations(_Section):
    """``traust.yaml`` ``locations:``: where traust reads and writes runtime data.
    Every field is a local path or a location URI; no environment overrides."""

    workspace: str | None = None
    analysis_results: str | None = None
    portfolio_graph: str | None = None
    progress_tracker: str | None = None
    rule_drafts: str | None = None
    feeds_cache: str | None = None
    gitleaks_config: str | None = None
    opengrep_rules: str | None = None
    product_definitions: str | None = None
    sarif_tool_uri: str | None = None
    mirror_cache: str | None = None


class TraustConfig(_Section):
    """``traust.yaml``: the schema is the shape check; traust-core's ``Config`` reads the rest."""

    locations: Locations | None = None
    ledger: dict[str, Any] | None = None


# --- the manifest: the single source of truth for "what config exists" --------


@dataclass(frozen=True)
class ConfigFile:
    """One config file's universal facts."""

    name: str  # filename in the config home
    section: str  # attribute name on HarnessContext
    required: bool
    schema: str  # config schema basename
    model: type[_Section]


MANIFEST: tuple[ConfigFile, ...] = (
    ConfigFile("traust.yaml", "traust", False, "traust", TraustConfig),
    ConfigFile("model-registry.yaml", "model_registry", True, "model-registry", ModelRegistry),
)


# --- the full context ---------------------------------------------------------


class HarnessContext(BaseModel):
    """Every resolved config file, loaded once at an entry point by :func:`load_context`."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    config_home: Path
    model_registry: ModelRegistry
    #: None: no traust.yaml, so traust-core's zero-config defaults.
    traust: TraustConfig | None = None


# --- the canonical loader -----------------------------------------------------


def _example_name(name: str) -> str:
    stem, dot, ext = name.rpartition(".")
    return f"{stem}.example.{ext}" if dot else f"{name}.example"


def _missing(home: Path, name: str, why: str) -> DeploymentConfigMissing:
    return DeploymentConfigMissing(
        f"required config file {name!r} {why} in {home}. Copy "
        f"config/{_example_name(name)} there as {name!r} and fill it in, or run "
        f"scripts/install_traust."
    )


_LOCATION_PATH_FIELDS = (
    "workspace",
    "analysis_results",
    "portfolio_graph",
    "progress_tracker",
    "rule_drafts",
    "feeds_cache",
    "gitleaks_config",
    "opengrep_rules",
    "mirror_cache",
)


def _resolve_location_path(home: Path, value: str | None) -> str | None:
    """Resolve a local path relative to the config home; leave URIs untouched."""
    if not value or "://" in value:
        return value
    p = Path(value)
    if p.is_absolute():
        return value
    return str((home / p).resolve())


def _normalize_locations(home: Path, section: Locations) -> Locations:
    """Make relative ``locations`` paths absolute against ``config_home``."""
    updates = {
        field: _resolve_location_path(home, getattr(section, field))
        for field in _LOCATION_PATH_FIELDS
        if getattr(section, field) is not None
    }
    return section.model_copy(update=updates) if updates else section


def _load_one(home: Path, entry: ConfigFile) -> Any | None:
    path = home / entry.name
    if not path.is_file():
        if entry.required:
            raise _missing(home, entry.name, "not found")
        return None

    raw = path.read_bytes()
    data = yaml.safe_load(raw.decode("utf-8")) if raw.strip() else {}
    schema = json.loads(config_schema_path(entry.schema).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(data)

    section = entry.model.model_validate(data)
    section.source_sha = hashlib.sha256(raw).hexdigest()[:12]
    if isinstance(section, TraustConfig) and section.locations is not None:
        section.locations = _normalize_locations(home, section.locations)
    return section


def load_context(*, config_home: Path | None = None) -> HarnessContext:
    """Resolve the one config home and load every file into a HarnessContext.

    Required-and-absent raises :class:`DeploymentConfigMissing` naming the file
    and the fix; optional-and-absent becomes ``None``. Each file is validated
    against its ``config/v1`` schema. Use :func:`config_completeness_audit` to
    see what still needs operator input.
    """
    home = Path(config_home) if config_home is not None else deployment_config_dir()
    if home is None:
        raise DeploymentConfigMissing(
            f"no config home: set ${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust "
            f"(default {TRAUST_CONFIG_HOME_DEFAULT})."
        )
    home = Path(home)

    values: dict[str, Any] = {"config_home": home}
    for entry in MANIFEST:
        values[entry.section] = _load_one(home, entry)
    return HarnessContext.model_validate(values)


# --- narrow single-file access ------------------------------------------------
# For feature-gated deep consumers: load ONE file without requiring the whole
# estate context (a narrow feature must not break because an unrelated required
# file is absent or malformed). Entry points should prefer load_context().

_BY_NAME = {e.name: e for e in MANIFEST}
_BY_SECTION = {e.section: e for e in MANIFEST}


def load_section(
    name: str, *, config_home: Path | None = None, required: bool | None = None
) -> Any | None:
    """Load one config file, schema-validated and typed, by filename or section.

    ``required`` overrides the manifest default — e.g. a consumer that degrades
    gracefully passes ``required=False`` to get ``None`` instead of an error when
    a manifest-required file is absent. Returns the typed section, or ``None``
    when optional-and-absent.
    """
    entry = _BY_NAME.get(name) or _BY_SECTION.get(name)
    if entry is None:
        raise KeyError(f"unknown config file {name!r}")
    if required is not None and required != entry.required:
        entry = replace(entry, required=required)
    home = Path(config_home) if config_home is not None else deployment_config_dir()
    if home is None:
        if entry.required:
            raise DeploymentConfigMissing(
                f"required config file {entry.name!r}: no config home — set "
                f"${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust."
            )
        return None
    return _load_one(Path(home), entry)


def config_path(name: str) -> Path:
    """Resolve a REQUIRED config file path from the one config home.

    Raises :class:`DeploymentConfigMissing` when the home is unset or the file
    is absent. For raw-path needs (keys); prefer :func:`load_section` for typed
    config or :func:`load_context` at entry points.
    """
    dep = deployment_config_dir()
    if dep is not None and (dep / name).is_file():
        return dep / name
    where = (
        str(dep)
        if dep is not None
        else f"<${TRAUST_CONFIG_HOME_ENV} unset and {TRAUST_CONFIG_HOME_DEFAULT} absent>"
    )
    raise DeploymentConfigMissing(
        f"required config file {name!r} not found in {where}. Copy "
        f"config/{_example_name(name)} there as {name!r} and fill it in, or run "
        f"scripts/install_traust."
    )


def optional_config_path(name: str) -> Path | None:
    """Resolve a feature-gated OPTIONAL config file path, or ``None`` when absent."""
    dep = deployment_config_dir()
    if dep is not None and (dep / name).is_file():
        return dep / name
    return None
