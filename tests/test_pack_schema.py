from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = Path(__file__).parents[1] / "config/v1/pack.schema.json"

SECURITY = {
    "pack": "security",
    "budget": "scanning",
    "approvers": ["security-operators"],
    "route_on": "repo_state",
    "assets": {
        "feeds_cache": {
            "run": ["python3", "-m", "traust.cli", "feeds", "fetch", "--feed", "all"],
            "trigger": {"every": "24h"},
            "freshness": {"warn": "36h", "fail": "48h"},
            "runner": {"labels": ["egress:public"]},
        },
        "repo_state": {
            "partitions": "dynamic:repo",
            "trigger": {"every": "24h"},
            "params": {"repo_url": "HttpsRepoUrl"},
            "admission": {"quota": {"key": "forge:{host}", "per_hour": 500}},
            "runner": {"labels": ["forge:{host}"]},
        },
        "diff_scan": {
            "partitions": "dynamic:repo",
            "deps": ["repo_state"],
            "trigger": {"lanes": ["diff-scan", "diff-scan-quarterly"]},
            "run": ["/vuln-scan", "--diff", "--", "{repo_url}"],
            "params": {"repo_url": "HttpsRepoUrl", "sha": "GitSha"},
            "admission": {
                "approval": "operator",
                "estimate_usd": "2.50",
                "pacing": {"per_tick": 10},
            },
            "model": {"role": "deep-audit"},
            "runner": {"labels": ["sandbox:agentic"]},
            "writes": ["ledger"],
            "riders": ["threat_model_pr"],
            "outcomes": ["succeeded", "degraded", "refused"],
        },
    },
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _with(asset: str, **fields: Any) -> dict[str, Any]:
    pack = json.loads(json.dumps(SECURITY))
    pack["assets"][asset] |= fields
    return pack


def test_the_design_security_pack_validates(validator: Draft202012Validator) -> None:
    validator.validate(SECURITY)


def test_an_asset_with_no_trigger_is_materialized_by_hand(validator: Draft202012Validator) -> None:
    validator.validate({"pack": "p", "assets": {"census": {"run": ["/census"]}}})


@pytest.mark.parametrize(
    "fields",
    [
        {"trigger": {"every": "24h", "lanes": ["diff-scan"]}},
        {"trigger": {"every": "24h", "on_cron": "0 5 * * *"}},
        {"trigger": {"on_cron": "0 5 * *"}},
        {"trigger": {"every": "1w"}},
        {"trigger": {"every": "0h"}},
        {"partitions": "dynamic:cve"},
        {"admission": {"pacing": {"per_tick": 0}}},
        {"admission": {"quota": {"key": "forge:{host}"}}},
        {"admission": {"estimate_usd": "-1"}},
        {"freshnes": {"fail": "48h"}},
        {"run": []},
    ],
    ids=[
        "every and lanes",
        "every and cron",
        "cron with four fields",
        "unknown unit",
        "zero duration",
        "unknown partitioning",
        "zero pacing",
        "quota without a rate",
        "negative estimate",
        "misspelt key",
        "empty argv",
    ],
)
def test_an_invalid_asset_is_rejected(
    validator: Draft202012Validator, fields: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(_with("repo_state", **fields))


@pytest.mark.parametrize(
    "pack",
    [{"pack": "p", "assets": {}}, {"assets": {"a": {}}}, {"pack": "p", "assets": {"Bad Name": {}}}],
    ids=["no assets", "no pack name", "bad asset name"],
)
def test_an_invalid_pack_is_rejected(validator: Draft202012Validator, pack: dict) -> None:
    with pytest.raises(ValidationError):
        validator.validate(pack)


def test_a_clock_time_job_is_a_cron_trigger(validator: Draft202012Validator) -> None:
    validator.validate(_with("feeds_cache", trigger={"on_cron": "0 7 * * 1"}))
    validator.validate(_with("feeds_cache", trigger={"on_cron": "*/15 0-6 1,15 * mon-fri"}))


def test_an_asset_declares_what_preflight_requires(validator: Draft202012Validator) -> None:
    validator.validate(
        _with(
            "diff_scan",
            requires={
                "tools": ["gitleaks", "opengrep"],
                "config": ["locations", "forge_tokens", "model-registry"],
                "facts": ["sla-policy", "product-definitions-map"],
                "feeds": ["osv", "deps_dev"],
                "secrets": ["GITHUB_TOKEN", "NVD_API_KEY"],
            },
        )
    )


def test_a_disabled_asset_needs_no_requirements(validator: Draft202012Validator) -> None:
    validator.validate(_with("diff_scan", enabled=False))
    validator.validate(_with("diff_scan", enabled=False, requires={"tools": ["gitleaks"]}))


@pytest.mark.parametrize(
    "fields",
    [
        {"enabled": True},
        {"requires": {}},
        {"requires": {"tools": []}},
        {"requires": {"skills": ["triage"]}},
        {"requires": {"config": ["storage"]}},
        {"requires": {"facts": ["org-chart"]}},
        {"requires": {"secrets": ["1BAD"]}},
        {"requires": {"tools": ["gitleaks", "gitleaks"]}},
    ],
    ids=[
        "enabled true",
        "empty requires",
        "empty requirement list",
        "unknown requirement kind",
        "retired config key",
        "unknown fact",
        "secret not an env name",
        "duplicate tool",
    ],
)
def test_an_invalid_requirement_is_rejected(
    validator: Draft202012Validator, fields: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate(_with("diff_scan", **fields))


def test_config_requirements_name_traust_yaml_keys() -> None:
    pack = json.loads(SCHEMA.read_text())
    traust = json.loads((SCHEMA.parent / "traust.schema.json").read_text())
    allowed = pack["$defs"]["asset"]["properties"]["requires"]["properties"]["config"]["items"][
        "enum"
    ]
    assert set(allowed) == set(traust["properties"]) | {"model-registry"}


def test_fact_requirements_name_core_recorded_facts() -> None:
    pack = json.loads(SCHEMA.read_text())
    allowed = pack["$defs"]["asset"]["properties"]["requires"]["properties"]["facts"]["items"][
        "enum"
    ]
    assert allowed == [
        "adr-registry",
        "benchmark-target",
        "org-parameters",
        "product-definitions-map",
        "sla-policy",
    ]
