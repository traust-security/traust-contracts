"""Config resolution and load_context behavior."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from traust_contracts.config import (
    MANIFEST,
    TRAUST_CONFIG_HOME_ENV,
    DeploymentConfigMissing,
    config_path,
    deployment_config_dir,
    load_context,
    load_section,
    optional_config_path,
)


def _write_minimal_config(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "model-registry.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "updated": "2026-01-01",
                "tiers": {"standard": {"description": "Synthetic test tier"}},
                "providers": {
                    "fixture": {
                        "data_handling": "synthetic",
                        "models": {"fixture-model": {"tier": "standard", "batch_eligible": False}},
                    }
                },
                "roles": {
                    "review": {
                        "floor": "standard",
                        "approved": ["fixture-model"],
                        "candidates": [],
                        "ledger_validity_writer": False,
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def test_manifest_covers_harness_context_sections():
    manifest_sections = {entry.section for entry in MANIFEST}
    required = {"traust", "model_registry"}
    assert manifest_sections == required


def test_deployment_config_dir_honors_env(tmp_path, monkeypatch):
    home = tmp_path / "cfg"
    home.mkdir()
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    assert deployment_config_dir() == home


def test_load_context_resolves_relative_locations(tmp_path):
    home = tmp_path / "cfg"
    ws = tmp_path / "workspace"
    ar = tmp_path / "analysis-results"
    ws.mkdir()
    ar.mkdir()
    _write_minimal_config(home)
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "locations": {
                    "workspace": "../workspace",
                    "analysis_results": "../analysis-results",
                }
            }
        ),
        encoding="utf-8",
    )
    ctx = load_context(config_home=home)
    assert ctx.traust.locations is not None
    assert ctx.traust.locations.workspace == str(ws.resolve())
    assert ctx.traust.locations.analysis_results == str(ar.resolve())


def test_config_path_and_optional(tmp_path, monkeypatch):
    home = tmp_path / "cfg"
    _write_minimal_config(home)
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    with pytest.raises(DeploymentConfigMissing, match=r"absent-required\.yaml"):
        config_path("absent-required.yaml")
    (home / "feeds.yaml").write_text("sources: {}\n", encoding="utf-8")
    assert config_path("feeds.yaml") == home / "feeds.yaml"
    assert optional_config_path("unused.yaml") is None
    (home / "unused.yaml").write_text("x: 1\n", encoding="utf-8")
    assert optional_config_path("unused.yaml") == home / "unused.yaml"


def test_load_section_locations_normalizes(tmp_path):
    home = tmp_path / "cfg"
    ws = tmp_path / "workspace"
    ws.mkdir()
    _write_minimal_config(home)
    (home / "traust.yaml").write_text(
        yaml.safe_dump({"locations": {"workspace": "../workspace"}}),
        encoding="utf-8",
    )
    loc = load_section("traust.yaml", config_home=home).locations
    assert loc.workspace == str(ws.resolve())


def test_config_path_fails_when_home_unset(monkeypatch):
    monkeypatch.setattr("traust_contracts.config.deployment_config_dir", lambda: None)
    with pytest.raises(DeploymentConfigMissing, match=r"feeds.yaml"):
        config_path("feeds.yaml")
