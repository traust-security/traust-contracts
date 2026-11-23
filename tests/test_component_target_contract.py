"""Contract tests for component PURL monorepo audit metadata and enums."""

from __future__ import annotations

import copy
import json
from typing import Any

import jsonschema
import pydantic
import pytest

from traust_contracts.paths import enum_dir, schema_dir
from traust_contracts.v1.models import ComponentTarget, Report


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads((schema_dir() / name).read_text(encoding="utf-8"))


def _base_report() -> dict[str, Any]:
    return {
        "title": "Spring Beans Security Audit",
        "metadata": {
            "date": "2026-11-22",
            "scope": "Component PURL audit of spring-beans at v7.1.0",
            "repository": "https://github.com/spring-projects/spring-framework",
            "commit": "f2e4863de60e6a20e827a0aa3c524ffb3ae96ad4",
            "ref": "v7.1.0",
            "ref_kind": "tag",
            "audit_profile": "code",
        },
        "executive_summary": {
            "prose": "Focused security review of spring-beans in its pinned monorepo context.",
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": "critical", "definition": "Remote exploitation without auth."},
            {"level": "high", "definition": "High-impact privilege escalation or leak."},
            {"level": "medium", "definition": "Scoped security weakness under preconditions."},
            {"level": "low", "definition": "Defense-in-depth hardening gap."},
        ],
        "findings": [],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 0, "finding_ids": []},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "p3",
                "addresses": ["NONE"],
                "action": "No remediation required for clean fixture report.",
                "effort": "xs",
            }
        ],
    }


def _valid_target(strategy: str = "shared_release") -> dict[str, Any]:
    return {
        "purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
        "repository": "https://github.com/spring-projects/spring-framework",
        "commit": "f2e4863de60e6a20e827a0aa3c524ffb3ae96ad4",
        "module_path": "spring-beans",
        "release_ref": "v7.1.0",
        "verification": {
            "strategy": strategy,
            "manifest_paths": ["pom.xml", "spring-beans/pom.xml"],
        },
    }


@pytest.mark.parametrize("strategy", ["shared_release", "package_release", "workspace_package"])
def test_report_accepts_component_target_and_round_trips(strategy: str) -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    doc["metadata"]["target"] = _valid_target(strategy)
    jsonschema.validate(doc, schema)
    canonical_validator = jsonschema.Draft202012Validator(schema).evolve(
        schema={"$ref": "#/$defs/canonical_write"}
    )
    canonical_validator.validate(doc)
    parsed = Report.model_validate(doc)
    assert isinstance(parsed.metadata.target, ComponentTarget)
    assert parsed.metadata.target.verification.strategy == strategy


def test_report_without_target_stays_valid() -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    jsonschema.validate(doc, schema)
    assert Report.model_validate(doc).metadata.target is None


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:maven/org.springframework/spring-beans@7.1.0",
        "pkg:npm/%40earendil-works/pi-ai@1.6.0",
        "pkg:npm/@acme/cache-lib@1.2.0",
        "pkg:pypi/langchain-core@1.8.4?classifier=wheel#libs/core",
        "pkg:golang/github.com/org/repo@v1.2.3+build.1#sub/pkg",
    ],
)
def test_report_accepts_valid_versioned_purls(purl: str) -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    target = _valid_target()
    target["purl"] = purl
    doc["metadata"]["target"] = target
    jsonschema.validate(doc, schema)
    assert Report.model_validate(doc).metadata.target.purl == purl


@pytest.mark.parametrize(
    "patch",
    [
        {"purl": "pkg:maven/org.springframework/spring-beans"},
        {"purl": "pkg:npm/@acme/cache-lib"},
        {"purl": "pkg:npm/@acme/cache-lib?foo=bar@baz"},
        {"purl": "pkg:npm/@acme/cache-lib#sub@1"},
        {"purl": "pkg:npm/@acme@1.2.0"},
        {"purl": "pkg:maven/g/a?repository_url=https://u@host"},
        {"purl": "pkg:maven/g/a#dir@1"},
        {"purl": "pkg:1x/a@1"},
        {"repository": ""},
        {"commit": "f2e4863"},
        {"commit": "F2E4863DE60E6A20E827A0AA3C524FFB3AE96AD4"},
        {"module_path": ""},
        {"release_ref": ""},
        {"release_ref": None},
        {"verification": {"strategy": "dir_name_guess", "manifest_paths": ["pom.xml"]}},
        {"verification": {"strategy": "shared_release", "manifest_paths": []}},
        {"verification": {"strategy": "shared_release", "manifest_paths": [""]}},
        {
            "verification": {
                "strategy": "shared_release",
                "manifest_paths": ["pom.xml"],
                "extra_evidence": True,
            }
        },
        {"unexpected": True},
    ],
)
def test_report_rejects_invalid_component_target(patch: dict[str, Any]) -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    target = copy.deepcopy(_valid_target())
    target.update(patch)
    doc["metadata"]["target"] = target
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)
    with pytest.raises(pydantic.ValidationError):
        Report.model_validate(doc)


def test_report_rejects_explicit_null_target() -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    doc["metadata"]["target"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)
    with pytest.raises(pydantic.ValidationError):
        Report.model_validate(doc)


def test_component_target_omitted_release_ref_round_trips_and_is_immutable() -> None:
    schema = _load_schema("report.schema.json")
    doc = _base_report()
    target = _valid_target()
    target.pop("release_ref")
    doc["metadata"]["target"] = target
    jsonschema.validate(doc, schema)
    parsed = Report.model_validate(doc)
    assert parsed.metadata.target is not None
    assert parsed.metadata.target.release_ref is None
    assert isinstance(parsed.metadata.target.verification.manifest_paths, tuple)
    serialized = parsed.to_dict()
    assert "release_ref" not in serialized["metadata"]["target"]
    jsonschema.validate(serialized, schema)
    with pytest.raises(pydantic.ValidationError):
        parsed.metadata.target.repository = "https://github.com/other/repo"  # type: ignore[misc]
    with pytest.raises(pydantic.ValidationError):
        parsed.metadata.target.verification.manifest_paths = ("",)  # type: ignore[misc]
    assert not hasattr(parsed.metadata.target.verification.manifest_paths, "append")


def test_current_major_aliases_export_component_target_symbols() -> None:
    from traust_contracts.enums import ComponentTargetStrategy as AliasStrategy
    from traust_contracts.models import (
        ComponentTarget as AliasTarget,
    )
    from traust_contracts.models import (
        ComponentTargetVerification as AliasVerification,
    )
    from traust_contracts.v1.enums import ComponentTargetStrategy as V1Strategy
    from traust_contracts.v1.models import (
        ComponentTarget as V1Target,
    )
    from traust_contracts.v1.models import (
        ComponentTargetVerification as V1Verification,
    )

    assert AliasStrategy is V1Strategy
    assert AliasTarget is V1Target
    assert AliasVerification is V1Verification


@pytest.mark.parametrize(
    ("meta_patch", "match"),
    [
        ({"commit": "0" * 40}, "metadata.target.commit"),
        ({"repository": "https://github.com/other/repo"}, "metadata.target.repository"),
    ],
)
def test_report_model_rejects_target_metadata_mismatch(
    meta_patch: dict[str, Any], match: str
) -> None:
    doc = _base_report()
    doc["metadata"]["target"] = _valid_target()
    doc["metadata"].update(meta_patch)
    with pytest.raises(pydantic.ValidationError, match=match):
        Report.model_validate(doc)


def test_report_model_accepts_target_with_normalized_metadata() -> None:
    doc = _base_report()
    doc["metadata"]["target"] = _valid_target()
    doc["metadata"]["commit"] = doc["metadata"]["commit"].upper()
    doc["metadata"]["repository"] = doc["metadata"]["repository"] + "/"
    parsed = Report.model_validate(doc)
    assert parsed.metadata.target is not None
    assert parsed.metadata.target.commit == _valid_target()["commit"]


def test_run_order_reason_declares_unresolved_target() -> None:
    data = json.loads((enum_dir() / "run-order-reason.json").read_text(encoding="utf-8"))
    assert "unresolved-target" in data["values"]
    assert "unresolved-target" in data["definitions"]
