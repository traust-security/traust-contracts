"""traust.yaml: one schema for everything an adopter sets, and the audit over it."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from traust_contracts.config import (
    MANIFEST,
    DeploymentConfigMissing,
    config_completeness_audit,
    load_context,
    load_section,
)
from traust_contracts.paths import config_schema_dir, config_schema_path

REGISTRY = {
    "version": 1,
    "updated": "2026-10-28",
    "tiers": {"haiku-class": {"description": "h"}},
    "providers": {
        "anthropic": {
            "data_handling": "test",
            "models": {"m": {"tier": "haiku-class", "batch_eligible": True}},
        }
    },
    "roles": {
        "r": {
            "floor": "haiku-class",
            "approved": ["m"],
            "candidates": [],
            "ledger_validity_writer": False,
        }
    },
}

# The plan's example traust.yaml, with core's names for remediation and campaign.
EXAMPLE = {
    "database": {
        "url": "postgresql+psycopg://traust@db.example.invalid/traust",
        "password_env": "TRAUST_DB_PASSWORD",
    },
    "artifacts": {"path": "artifacts"},
    "identity": {"trust_local": True, "admins": ["alice@example.com"]},
    "ledger": {"key_path": "keys/ledger.pem", "public_key_path": "keys/ledger.pub"},
    "budgets": [{"lane": "diff-scan", "monthly_usd": "200", "enforcement": "enforced"}],
    "forge_hosts": {"github.com": "github", "gitlab.example.invalid": "gitlab"},
    "forge_tokens": {"github.com": "GITHUB_TOKEN"},
    "locations": {
        "workspace": "~/work/traust",
        "analysis_results": "/srv/ar",
        "progress_tracker": "/srv/pt",
        "mirror_cache": "/srv/mirrors",
    },
    "feeds": {"osv_access": "air-gapped"},
    "execution": {"sandbox": "podman"},
    "remediation": {
        "fork_org": "my-org-security-mirrors",
        "private_forge_hosts": ["gitlab.example.invalid"],
    },
    "campaign": {"tracking_reference": "SEC-2026-Q4", "display_name": "Q4"},
    "overrides": {"rule_pack_allowlist": "./rule-pack-allowlist.yaml"},
    "process": {"timeout_seconds": 600},
}


def _validate(document: object) -> None:
    schema = json.loads(config_schema_path("traust").read_text())
    jsonschema.Draft202012Validator(schema).validate(document)


def _home(tmp_path: Path, traust: dict | str | None = None) -> Path:
    (tmp_path / "model-registry.yaml").write_text(yaml.safe_dump(REGISTRY))
    if traust is not None:
        text = traust if isinstance(traust, str) else yaml.safe_dump(traust)
        (tmp_path / "traust.yaml").write_text(text)
    return tmp_path


def test_the_config_home_holds_traust_yaml_and_the_model_registry() -> None:
    assert [(e.name, e.required) for e in MANIFEST] == [
        ("traust.yaml", False),
        ("model-registry.yaml", True),
    ]


@pytest.mark.parametrize(
    "name",
    ["corpus-config", "storage", "ledger", "budget-policy", "rpm-distgit-watch", "locations"],
)
def test_retired_schemas_are_gone(name: str) -> None:
    assert not (config_schema_dir() / f"{name}.schema.json").exists()
    with pytest.raises(FileNotFoundError):
        config_schema_path(name)


@pytest.mark.parametrize("document", [{}, EXAMPLE], ids=["empty", "example"])
def test_the_schema_accepts(document: dict) -> None:
    _validate(document)


@pytest.mark.parametrize(
    "artifacts",
    [
        {"path": "artifacts"},
        {"s3": {"bucket": "test-artifacts"}},
        {"s3": {"bucket": "test-artifacts", "prefix": "deploy-a", "region": "us-east-1"}},
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "https://rgw.example.com"}},
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "http://[::1]:9000"}},
        {
            "s3": {
                "bucket": "test-artifacts",
                "endpoint_url": "http://localhost:9000",
                "access_key_env": "TEST_ACCESS_KEY",
                "secret_key_env": "TEST_SECRET_KEY",
            }
        },
    ],
)
def test_artifact_storage_config_is_selectable(artifacts: dict) -> None:
    _validate({"artifacts": artifacts})


@pytest.mark.parametrize(
    "artifacts",
    [
        {"path": "local", "s3": {"bucket": "test-artifacts"}},
        {"s3": {}},
        {"s3": {"bucket": ""}},
        {"s3": {"bucket": "test-artifacts", "secret_access_key": "secret"}},
        {"s3": {"bucket": "test-artifacts", "access_key_env": "NOT_PAIRED"}},
        {"s3": {"bucket": "test-artifacts", "secret_key_env": "NOT_PAIRED"}},
        {"s3": {"bucket": "test-artifacts", "access_key_env": "1BAD", "secret_key_env": "OK"}},
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "ftp://invalid"}},
        {
            "s3": {
                "bucket": "test-artifacts",
                "endpoint_url": "https://user:password@rgw.example.com",
            }
        },
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "http://bad host"}},
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "http://bad..host"}},
        {"s3": {"bucket": "test-artifacts", "endpoint_url": "http://localhost:notaport"}},
    ],
)
def test_artifact_storage_config_rejects_invalid_or_ambiguous_values(artifacts: dict) -> None:
    with pytest.raises(jsonschema.ValidationError):
        _validate({"artifacts": artifacts})


@pytest.mark.parametrize("outputs", [["stderr"], ["file"], ["stderr", "file"]])
def test_logging_outputs_are_selectable(outputs: list[str]) -> None:
    _validate({"logging": {"outputs": outputs}})


@pytest.mark.parametrize("outputs", [[], ["stdout"], ["stderr", "stderr"]])
def test_logging_outputs_are_nonempty_known_and_unique(outputs: list[str]) -> None:
    with pytest.raises(jsonschema.ValidationError):
        _validate({"logging": {"outputs": outputs}})


@pytest.mark.parametrize(
    "document",
    [
        {"storage": {"dsn": "sqlite://"}},
        {"database": {"password": "secret"}},
        {"forge_tokens": {"github.com": "ghp_not-an-env-name!"}},
        {"forge_tokens": {"github.com": 5}},
        {"database": {"password_env": "1BAD"}},
        {"feeds": {"osv_access": "disabled"}},
        {"feeds": {"endpoints": {}}},
        {"execution": {"sandbox": "docker"}},
        {"budgets": [{"lane": "x", "monthly_usd": "1", "enforcement": "withhold"}]},
        {"budgets": [{"lane": "x", "monthly_usd": "1"}]},
        {"remediation": {"fix_branch_prefix": "a/b"}},
        {"remediation": {"patch_prefix": "patch prefix"}},
        {"overrides": {"model_registry": "./m.yaml"}},
        {"overrides": {"external_tools": "./tools.yaml"}},
        {"overrides": {"safe_exec_profiles": "./profiles.yaml"}},
        {"overrides": {"feeds": "./feeds.yaml"}},
        {"identity": {"login": {"issuer": "https://i.example.invalid"}}},
        [],
    ],
    ids=[
        "retired-section",
        "inline-secret",
        "token-not-env-name",
        "token-not-string",
        "env-name-leading-digit",
        "osv-access",
        "feeds-endpoints-are-shipped",
        "sandbox",
        "budget-enforcement",
        "budget-missing-enforcement",
        "fix-branch-prefix",
        "patch-prefix",
        "override-unknown-file",
        "tool-pins-are-not-configurable",
        "safe-exec-is-not-configurable",
        "feeds-registry-is-not-configurable",
        "login-without-client",
        "not-a-mapping",
    ],
)
def test_the_schema_rejects(document: object) -> None:
    with pytest.raises(jsonschema.ValidationError):
        _validate(document)


def test_locations_keep_unknown_keys_as_before() -> None:
    _validate({"locations": {"workspace": "/w", "something_else": 3}})


def test_an_absent_traust_yaml_is_zero_config(tmp_path: Path) -> None:
    ctx = load_context(config_home=_home(tmp_path))
    assert ctx.traust is None
    assert config_completeness_audit(config_home=tmp_path) == (
        [],
        [
            "traust.yaml: absent — zero-config local defaults (SQLite under ~/.traust); "
            "copy traust.example.yaml to set locations and the ledger key"
        ],
    )


def test_an_empty_traust_yaml_loads_as_no_settings(tmp_path: Path) -> None:
    section = load_section("traust.yaml", config_home=_home(tmp_path, ""))
    assert section.locations is None and section.source_sha


def test_relative_locations_resolve_against_the_home(tmp_path: Path) -> None:
    home = _home(
        tmp_path,
        {
            "locations": {
                "workspace": "ws",
                "analysis_results": "s3://b/ar",
                "mirror_cache": "mirrors",
            }
        },
    )
    locations = load_context(config_home=home).traust.locations
    assert locations.workspace == str((home / "ws").resolve())
    assert locations.analysis_results == "s3://b/ar"
    assert locations.mirror_cache == str((home / "mirrors").resolve())


def test_the_audit_of_a_filled_traust_yaml_is_clean(tmp_path: Path) -> None:
    assert config_completeness_audit(config_home=_home(tmp_path, EXAMPLE)) == ([], [])


def test_the_audit_names_unset_locations_and_the_ledger_key(tmp_path: Path) -> None:
    home = _home(tmp_path, {"locations": {"workspace": "/w"}, "ledger": {"key_path": "/k"}})
    assert config_completeness_audit(config_home=home) == (
        [],
        [
            "traust.yaml: locations.analysis_results unset",
            "traust.yaml: locations.progress_tracker unset",
            "traust.yaml: ledger.public_key_path unset — layer signatures are not verified",
        ],
    )


def test_the_audit_without_a_model_registry_is_one_error(tmp_path: Path) -> None:
    (tmp_path / "traust.yaml").write_text(yaml.safe_dump(EXAMPLE))
    errors, warnings = config_completeness_audit(config_home=tmp_path)
    assert len(errors) == 1 and "'model-registry.yaml' not found" in errors[0]
    assert warnings == []


def test_a_malformed_traust_yaml_fails_the_audit(tmp_path: Path) -> None:
    with pytest.raises(jsonschema.ValidationError):
        config_completeness_audit(config_home=_home(tmp_path, {"locations": {"workspace": 5}}))


def test_retired_files_in_the_home_are_not_read(tmp_path: Path) -> None:
    home = _home(tmp_path, EXAMPLE)
    for name in ("corpus-config.yaml", "storage.yaml", "ledger.yaml", "locations.yaml"):
        (home / name).write_text("not: [valid\n")
    assert config_completeness_audit(config_home=home) == ([], [])
    with pytest.raises(KeyError):
        load_section("storage", config_home=home)
    with pytest.raises(DeploymentConfigMissing):
        load_section("traust", config_home=tmp_path / "nowhere", required=True)
