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


def test_campaign_counts_content_gate_rejects_vulnerable_above_tested(
    tmp_path: Path,
) -> None:
    """The README's documented gate: vulnerable <= tested, enforced by validate.py."""
    import sys

    sys.path.insert(0, str(ROOT))
    from validate import validate_artifact

    document = json.loads((FIXTURES / "fuzz-campaign.json").read_text())
    document["patterns"][0].update(tested=0, vulnerable=1)
    bad = tmp_path / "bad-campaign.json"
    bad.write_text(json.dumps(document))
    assert not validate_artifact("fuzz-campaign", bad)

    document["patterns"][0].update(tested=2, vulnerable=1)
    good = tmp_path / "good-campaign.json"
    good.write_text(json.dumps(document))
    assert validate_artifact("fuzz-campaign", good)


def test_liveness_entry_must_carry_its_own_map_key(tmp_path: Path) -> None:
    """One repository's facts cannot sit under another repository's key."""
    import sys

    sys.path.insert(0, str(ROOT))
    from validate import validate_artifact

    document = json.loads((FIXTURES / "repo-liveness.json").read_text())
    first = next(iter(document["repositories"]))
    document["repositories"][first]["repository_id"] = "10000000-0000-4000-8000-0000000000ff"
    misplaced = tmp_path / "misplaced.json"
    misplaced.write_text(json.dumps(document))
    assert not validate_artifact("repo-liveness", misplaced)

    document["repositories"][first]["repository_id"] = first
    correct = tmp_path / "correct.json"
    correct.write_text(json.dumps(document))
    assert validate_artifact("repo-liveness", correct)


def test_liveness_snapshot_carries_a_generated_marker() -> None:
    """Consumers order snapshots by generated, observations by observed_at."""
    document = json.loads((FIXTURES / "repo-liveness.json").read_text())
    gate = validator("repo-liveness")
    assert gate.is_valid(document)
    del document["generated"]
    assert not gate.is_valid(document)


def test_code_facts_all_null_sections_record_nothing() -> None:
    """A document whose sections are all explicit nulls does not validate."""
    document = json.loads((FIXTURES / "code-facts-interfaces.json").read_text())
    gate = validator("code-facts")
    assert gate.is_valid(document)
    for section in ("symbols", "languages", "packages", "interfaces"):
        document[section] = None
    assert not gate.is_valid(document)


def test_impact_metadata_round_trips_the_complete_preparation_scope() -> None:
    """The SDK must not silently drop the complete-snapshot identity."""
    from traust_contracts.v1.models.impact import ImpactAnalysis

    scope = {
        "digest": "a" * 64,
        "members": [{"ecosystem": "go", "module": "example.test/lib", "version": "1.0.0"}],
    }
    document = {
        "metadata": {
            "cve": "CVE-2026-0001",
            "module": "example.test/lib",
            "vulnerable_range": "<1.0.1",
            "harness_version": "test",
            "generated_at": "2026-11-03T12:00:00Z",
            "tiers_executed": ["l1"],
            "options": {},
            "preparation_scope": scope,
            "portfolio_graph_version": "corp-portfolio@2026-11-01",
        },
        "summary": {
            "repos_in_blast_radius": 0,
            "version_in_range": 0,
            "affected": 0,
            "likely_affected": 0,
            "not_observed": 0,
            "version_not_in_range": 0,
            "not_imported": 0,
            "inconclusive": 0,
        },
    }
    round_tripped = ImpactAnalysis.from_dict(document).to_dict()["metadata"]
    assert round_tripped["preparation_scope"] == scope
    assert round_tripped["portfolio_graph_version"] == "corp-portfolio@2026-11-01"


@pytest.mark.parametrize("schema", ["fuzz-campaign", "repo-liveness"])
@pytest.mark.parametrize("document", [None, [], 1, "not an object", False])
def test_validator_rejects_invalid_root_shapes_without_crashing(
    schema: str, document: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from validate import validate_artifact

    artifact = tmp_path / "invalid.json"
    artifact.write_text(json.dumps(document))
    assert validate_artifact(schema, artifact) is False


@pytest.mark.parametrize(
    "schema, field, value",
    [
        ("fuzz-campaign", "patterns", None),
        ("fuzz-campaign", "patterns", [None]),
        ("fuzz-campaign", "patterns", ["not an object"]),
        ("fuzz-campaign", "patterns", {}),
        ("repo-liveness", "repositories", None),
        ("repo-liveness", "repositories", []),
        ("repo-liveness", "repositories", {"10000000-0000-4000-8000-000000000001": None}),
    ],
)
def test_validator_rejects_invalid_content_gate_shapes_without_crashing(
    schema: str, field: str, value: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from validate import validate_artifact

    document = json.loads((FIXTURES / f"{schema}.json").read_text())
    document[field] = value
    artifact = tmp_path / "invalid.json"
    artifact.write_text(json.dumps(document))
    assert validate_artifact(schema, artifact) is False


def test_validator_cli_reports_later_files_after_a_structurally_invalid_document(
    tmp_path: Path,
) -> None:
    import subprocess
    import sys

    first = tmp_path / "invalid-root.json"
    first.write_text("[]")
    second = tmp_path / "invalid-entry.json"
    document = json.loads((FIXTURES / "repo-liveness.json").read_text())
    key = next(iter(document["repositories"]))
    document["repositories"][key]["repository_id"] = "10000000-0000-4000-8000-0000000000ff"
    second.write_text(json.dumps(document))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "validate.py"),
            "--schema",
            "repo-liveness",
            str(first),
            str(second),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert str(first) in result.stdout
    assert str(second) in result.stdout
    assert "Traceback" not in result.stderr
