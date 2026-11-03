from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from test_contracts import build_registry

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def validator(name: str, fragment: str = "") -> Draft202012Validator:
    schema = json.loads((ROOT / "artifacts_schema/v1" / f"{name}.schema.json").read_text())
    target = {"$ref": schema["$id"] + fragment} if fragment else schema
    return Draft202012Validator(target, registry=build_registry(), format_checker=FormatChecker())


@pytest.mark.parametrize("section", ["packages", "interfaces"])
def test_recorded_measurement_can_be_explicitly_empty_without_inventing_other_facts(
    section: str,
) -> None:
    document = json.loads((FIXTURES / "code-facts-interfaces.json").read_text())
    other = "interfaces" if section == "packages" else "packages"
    document[other] = None
    gate = validator("code-facts")
    assert gate.is_valid(document)
    document[section] = None
    assert not gate.is_valid(document)


@pytest.mark.parametrize("path", ["../outside.go", "/outside.go", "C:/outside.go", "a\\b.go"])
def test_package_and_interface_locations_cannot_escape_the_recorded_ref(path: str) -> None:
    document = json.loads((FIXTURES / "code-facts-interfaces.json").read_text())
    gate = validator("code-facts")
    assert gate.is_valid(document)
    document["packages"]["imports"][0]["location"]["path"] = path
    assert not gate.is_valid(document)
    document = json.loads((FIXTURES / "code-facts-interfaces.json").read_text())
    document["interfaces"][0]["location"]["path"] = path
    assert not gate.is_valid(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "deleted-or-private"),
        ("observed_at", True),
        ("status_since", "2026-99-99"),
        ("canonical_url", "file:///tmp/repo"),
    ],
)
def test_liveness_keeps_unknown_distinct_and_refuses_unusable_observation_metadata(
    field, value
) -> None:
    document = json.loads((FIXTURES / "repo-liveness.json").read_text())
    gate = validator("repo-liveness")
    assert gate.is_valid(document)
    unknown = document["repositories"]["10000000-0000-4000-8000-000000000003"]
    assert unknown["status"] == "unknown" and unknown["unobserved"] == "no-credentials"
    unknown[field] = value
    assert not gate.is_valid(document)


@pytest.mark.parametrize(
    "tested,vulnerable,valid",
    [
        (True, True, True),
        (True, False, True),
        (True, None, True),
        (False, None, True),
        (False, True, False),
        (False, False, False),
    ],
)
def test_pattern_outcomes_require_tested_evidence_without_defaulting_unknown(
    tested, vulnerable, valid
) -> None:
    document = json.loads((FIXTURES / "fuzz-report-analysis.json").read_text())
    document["patterns"][0].update(tested=tested, vulnerable=vulnerable)
    assert validator("fuzz-report").is_valid(document) is valid


def test_campaign_reference_and_run_evidence_are_not_interchangeable() -> None:
    campaign = json.loads((FIXTURES / "fuzz-campaign.json").read_text())
    campaign["narrative"] = (
        "## Supplied analyst notes\n\nThe counts describe this campaign, not one run."
    )
    assert validator("fuzz-campaign").is_valid(campaign)
    assert not validator("fuzz-report").is_valid(campaign)
    del campaign["repositories"]
    assert not validator("fuzz-campaign").is_valid(campaign)


@pytest.mark.parametrize(
    "mutation", ["bad-digest", "no-members", "duplicate-member", "bad-ecosystem"]
)
def test_complete_impact_scope_requires_an_identifiable_nonempty_package_snapshot(
    mutation: str,
) -> None:
    scope = {
        "digest": "a" * 64,
        "members": [{"ecosystem": "go", "module": "example.test/lib", "version": "1.0.0"}],
    }
    gate = validator("impact-analysis", "#/$defs/metadata/properties/preparation_scope")
    assert gate.is_valid(scope)
    if mutation == "bad-digest":
        scope["digest"] = "not-a-content-digest"
    elif mutation == "no-members":
        scope["members"] = []
    elif mutation == "duplicate-member":
        scope["members"].append(deepcopy(scope["members"][0]))
    else:
        scope["members"][0]["ecosystem"] = "invented-ecosystem"
    assert not gate.is_valid(scope)


@pytest.mark.parametrize(
    "segment", [".", "..", "../outside", "two/segments", "x?query", "x#fragment", "", True]
)
def test_documentation_coordinates_are_explicit_safe_path_segments(segment: object) -> None:
    schema = json.loads((ROOT / "config/v1/traust.schema.json").read_text())
    gate = Draft202012Validator(schema, format_checker=FormatChecker())
    target = {"product_slug": "example-product", "version": "1.0", "guides": ["security_guide"]}
    document = {"compliance": {"docs_targets": {"10000000-0000-4000-8000-000000000001": target}}}
    assert gate.is_valid(document)
    target["product_slug"] = segment
    assert not gate.is_valid(document)
