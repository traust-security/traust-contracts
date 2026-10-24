"""
Tests for traust-contracts schema integrity.

The golden-vector tests were removed with the suite on 2026-08-18. The recipe's
regression fixtures live in the ledger package, beside the implementation they
guard.
"""

import json
from pathlib import Path
from typing import ClassVar

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "artifacts_schema" / "v1"
CONFIG_SCHEMA_DIR = REPO_ROOT / "config" / "v1"
ENUMS_DIR = REPO_ROOT / "enums" / "v1"


def build_registry() -> Registry:
    """Build $ref registry across all schemas."""
    resources = {}
    for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        schema_id = doc.get("$id", sf.name)
        resources[schema_id] = Resource.from_contents(doc)
    return Registry(resources=resources)


def test_complete_synthetic_layer_document() -> None:
    """The portable schema validates a whole layer, not just isolated events."""
    from jsonschema import FormatChecker

    schema = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
    document = json.loads(
        (REPO_ROOT / "tests/fixtures/sample-findings-layer.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(document)
    assert len(document["events"]) == 2
    assert "\0" in document["events"][0]["rationale"]
    for field in ("metadata", "events", "needs_review"):
        with pytest.raises(ValidationError):
            validator.validate({key: value for key, value in document.items() if key != field})


class TestSchemas:
    """Schema parsing and validation tests."""

    def test_all_schemas_parse_json(self):
        """All schema files must be valid JSON."""
        schema_files = list(SCHEMA_DIR.glob("*.schema.json"))
        assert len(schema_files) == 34, f"Expected 34 data schemas, found {len(schema_files)}"

        config_schema_files = list(CONFIG_SCHEMA_DIR.glob("*.schema.json"))
        assert len(config_schema_files) == 15, (
            f"Expected 15 config schemas, found {len(config_schema_files)}"
        )

        for sf in [*schema_files, *config_schema_files]:
            with Path(sf).open() as f:
                try:
                    json.load(f)
                except json.JSONDecodeError as e:
                    pytest.fail(f"{sf.name}: invalid JSON: {e}")

    def test_all_schemas_are_valid_draft202012(self):
        """All schemas can be instantiated as Draft 2020-12 validators."""
        registry = build_registry()

        for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
            schema = json.loads(sf.read_text(encoding="utf-8"))
            try:
                # Verify the schema can be instantiated as a validator
                Draft202012Validator(schema, registry=registry)
            except Exception as e:
                pytest.fail(f"{sf.name}: failed to instantiate validator: {e}")

    def test_refs_resolve(self):
        """Cross-file $refs must resolve."""
        registry = build_registry()

        # Try to resolve a known cross-file ref as smoke test
        # (e.g., if report.schema.json has a $ref to another schema)
        report_schema = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
        validator = Draft202012Validator(report_schema, registry=registry)

        # Create a minimal valid report to trigger ref resolution
        minimal_report = {
            "title": "Security Assessment",
            "metadata": {"date": "2026-01-01", "scope": "test"},
            "executive_summary": "Test",
            "severity_criteria": [
                {"level": "critical", "description": "Test"},
                {"level": "high", "description": "Test"},
                {"level": "medium", "description": "Test"},
                {"level": "low", "description": "Test"},
            ],
            "findings": [],
            "findings_summary": [
                {"severity": "critical", "count": 0},
                {"severity": "high", "count": 0},
                {"severity": "medium", "count": 0},
                {"severity": "low", "count": 0},
            ],
            "remediation_roadmap": [{"phase": 1, "description": "Test"}],
        }

        # Should not raise during validation (refs should resolve)
        list(validator.iter_errors(minimal_report))


class TestEnums:
    """Enum vocabulary consistency tests."""

    def test_enums_directory_exists(self):
        """enums/ directory should exist."""
        assert ENUMS_DIR.exists(), f"Enums directory not found: {ENUMS_DIR}"

    def test_enum_files_parse(self):
        """All enum files must be valid JSON."""
        enum_files = list(ENUMS_DIR.glob("*.json"))
        assert len(enum_files) > 0, "No enum files found"

        for ef in enum_files:
            with Path(ef).open() as f:
                try:
                    json.load(f)
                except json.JSONDecodeError as e:
                    pytest.fail(f"{ef.name}: invalid JSON: {e}")

    def test_enum_values_in_source_schemas(self):
        """Each enum's values must appear verbatim in its source schema."""
        for ef in sorted(ENUMS_DIR.glob("*.json")):
            with Path(ef).open() as f:
                enum_def = json.load(f)

            source = enum_def.get("source_schema", "")
            if not source:
                continue
            parts = source.split("#")
            if len(parts) != 2:
                continue

            schema_name, json_path = parts
            schema_file = SCHEMA_DIR / schema_name
            if not schema_file.exists():
                continue

            with Path(schema_file).open() as f:
                schema = json.load(f)

            # Navigate to the enum definition
            obj = schema
            for segment in json_path.strip("/").split("/"):
                if segment.startswith("$"):
                    obj = obj.get(segment, {})
                elif segment in obj:
                    obj = obj[segment]
                else:
                    # Path not found, skip validation
                    break
            else:
                # Successfully navigated; check enum values
                if isinstance(obj, dict) and "enum" in obj:
                    # null marks a nullable field, not a vocabulary value; the
                    # registry records strings only (ci/enum_registry.py).
                    schema_values = {v for v in obj["enum"] if v is not None}
                    enum_values = set(enum_def.get("values", []))
                    assert enum_values == schema_values, (
                        f"{ef.name}: values mismatch with {schema_name}. "
                        f"Expected {schema_values}, got {enum_values}"
                    )

    def test_triage_verdict_matches_schema(self):
        enum_def = json.loads((ENUMS_DIR / "verdict.json").read_text(encoding="utf-8"))
        triage = json.loads((SCHEMA_DIR / "triage.schema.json").read_text(encoding="utf-8"))
        assert set(enum_def["values"]) == set(triage["$defs"]["verdict"]["enum"])

    def test_stamped_event_validates(self):
        """An event carrying its identity stamp must validate.

        $defs.event is additionalProperties: false, and the ledger write path
        (events.attach_identity) stamps fingerprint/fingerprint_algo
        onto every event it writes. Between 0.3.0 and 0.4.2 the schema did not
        declare either field, so every stamped layer file failed validation —
        49 files / 198 events in the test corpus before this was
        caught. Keep both fields declared.
        """
        layer = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
        event_schema = {**layer["$defs"]["event"], "$defs": layer["$defs"]}
        stamped = {
            "event_id": "a" * 64,
            "finding_ref": "FIND-001",
            "recorded_at": "2026-08-17T00:00:00+00:00",
            "source": {
                "type": "interactive",
                "ref": "interactive:2026-08-17:embargo:required",
                "actor": {"kind": "human", "identity": "analyst@example.com"},
            },
            "disposition": {"validity": "confirmed"},
            "rationale": "stamped by the ledger write path",
            "fingerprint": "b" * 64,
            "fingerprint_algo": "v1",
        }
        errors = list(Draft202012Validator(event_schema).iter_errors(stamped))
        assert not errors, [e.message for e in errors]


def test_every_findings_schema_declares_the_identity_fields():
    """A schema with findings and additionalProperties:false must declare
    both `fingerprint` and `fingerprint_algo`, or the stamped corpus it
    describes is invalid against it.

    This has now bitten twice. report.schema.json omitted fingerprint_algo
    while the producer emitted it, leaving thousands of audit reports invalid for
    16 days. cloud-config-findings-current.schema.json declared NEITHER, so
    stamping the policy findings turned nearly every valid report invalid in
    one command.
    """
    import json

    from traust_contracts.paths import schema_dir

    missing = []
    for path in sorted(schema_dir().glob("*.json")):
        document = json.loads(path.read_text())
        candidates = [
            (
                "properties.findings.items",
                document.get("properties", {}).get("findings", {}).get("items"),
            )
        ]
        candidates += [(f"$defs.{name}", node) for name, node in document.get("$defs", {}).items()]
        for where, node in candidates:
            if not isinstance(node, dict):
                continue
            properties = node.get("properties") or {}
            if "id" not in properties or "severity" not in properties:
                continue  # not a finding-shaped object
            if node.get("additionalProperties") is not False:
                continue
            for field in ("fingerprint", "fingerprint_algo"):
                if field not in properties:
                    missing.append(f"{path.name} {where}: {field}")
    assert not missing, (
        "finding-shaped objects missing an identity field; a stamped corpus "
        f"would be invalid against them: {missing}"
    )


def _canonical_write_validator(family: str, canonical: bool = False) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{family}.schema.json").read_text(encoding="utf-8"))
    if canonical:
        namespace = "definitions" if family == "pqc-decision-tree" else "$defs"
        schema = {"$ref": f"{schema['$id']}#/{namespace}/canonical_write"}
    return Draft202012Validator(schema, registry=build_registry())


def test_canonical_write_roadmap_separates_historical_text_from_canonical_writes():
    from storage_samples import sample

    document = json.loads(sample("report")[0])
    roadmap = document["remediation_roadmap"][0]
    roadmap.update(priority="owner sequencing note", effort="depends on provider response")
    reader = _canonical_write_validator("report")
    writer = _canonical_write_validator("report", canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)

    for priority in ("p0", "p1", "p2", "p3", "p4"):
        roadmap.update(priority=priority, effort="m", blocked_external=False)
        writer.validate(document)
    for size in ("xs", "s", "m", "l", "xl"):
        for blocked in (False, True):
            roadmap.update(effort=size, blocked_external=blocked)
            writer.validate(document)
    roadmap["priority"] = "p5"
    assert not writer.is_valid(document)
    roadmap["priority"] = "p2"
    roadmap["effort"] = "blocked-external"
    reader.validate(document)
    assert not writer.is_valid(document)
    roadmap["effort"] = "m"
    roadmap["blocked_external"] = "true"
    assert not writer.is_valid(document)


@pytest.mark.parametrize("family", ["pqc-blockers", "pqc-readiness"])
def test_canonical_write_open_historical_properties_are_not_retroactively_boolean(family):
    from storage_samples import sample

    document = json.loads(sample(family)[0])
    if family == "pqc-blockers":
        item = document["remediation_roadmap"][0]
        item.update(priority="p2", effort={"provider_note": "historical extra"})
    else:
        item = {"fact_ids": [], "primitive": "RSA", "disallowed_after": 2035}
        document["clock_items"] = [item]
    item["blocked_external"] = "historical provider note"
    reader = _canonical_write_validator(family)
    writer = _canonical_write_validator(family, canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    item["blocked_external"] = True
    item["effort" if family == "pqc-blockers" else "remediation_effort"] = "s"
    writer.validate(document)


def test_canonical_write_decision_classes_preserve_exact_history_and_size_requiredness():
    from storage_samples import sample

    document = json.loads(sample("pqc-decision-tree")[0])
    reader = _canonical_write_validator("pqc-decision-tree")
    writer = _canonical_write_validator("pqc-decision-tree", canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    legacy_classes = document["remediation_effort"]["classes"]
    document["remediation_effort"]["classes"] = ["xs", "s", "m", "l", "xl"]
    for rule in document["remediation_effort"]["rules"]:
        rule.update(effort="m", blocked_external=True)
    writer.validate(document)
    document["remediation_effort"]["classes"] += legacy_classes
    assert not reader.is_valid(document)
    document["remediation_effort"]["classes"] = ["xs", "s", "m", "l", "xl"]
    del document["remediation_effort"]["rules"][0]["effort"]
    assert not writer.is_valid(document)
    assert not reader.is_valid(document)


def test_canonical_write_mitigation_keeps_uppercase_history_and_requires_known_size():
    from storage_samples import sample

    document = json.loads(sample("threat-model")[0])
    item = {
        "mitigation": "Verify authorization",
        "threat_ids": ["T1"],
        "closes_class": "partial",
        "effort": "S",
        "blocked_external": True,
    }
    document["mitigations"] = [item]
    reader = _canonical_write_validator("threat-model")
    writer = _canonical_write_validator("threat-model", canonical=True)
    reader.validate(document)
    assert not writer.is_valid(document)
    item["effort"] = "s"
    writer.validate(document)
    del item["effort"]
    assert not writer.is_valid(document)
    assert not reader.is_valid(document)


class TestReportMetadataAdditional:
    """Declared run records under report metadata.additional (0.55.0).

    The object stays open: undeclared keys pass, declared keys must match.
    """

    @staticmethod
    def _validator():
        schema = json.loads((SCHEMA_DIR / "report.schema.json").read_text(encoding="utf-8"))
        return Draft202012Validator(schema["$defs"]["metadata"]["properties"]["additional"])

    VALID: ClassVar[dict] = {
        "harness_version": "0.17.0-abc1234",
        "deterministic_steps": {"opengrep": "ran", "gitleaks": "skipped: not on PATH"},
        "precision_gates": {
            "crit_high_evaluated": 2,
            "fired": [{"candidate": "X-001", "gate": "fp-precedent", "action": "downgraded"}],
        },
        "coverage_gaps": [
            {"tool": "route-guards", "system": "fastapi", "reason": "no enumerator"},
            {"tool": "config-matrix", "system": "toml", "reason": "no expander", "count": 3},
        ],
        "assertive_inference": {"languages": ["rust"], "trigger": "uncovered per opengrep"},
        "companion_lanes": ["cloud-config-audit"],
        "audit_passes": 1,
        "model_routing": {"role": "auditor", "model": "m", "registry_sha": "abc", "floor": "f"},
        "source_audit": "findings/p/r/r-security-audit.json",
        "degraded": False,
        "undeclared_extra": {"anything": [1, 2]},
    }

    def test_declared_shapes_validate(self):
        errors = list(self._validator().iter_errors(self.VALID))
        assert errors == [], [e.message for e in errors]

    def test_empty_fired_list_is_legitimate(self):
        doc = {"precision_gates": {"crit_high_evaluated": 0, "fired": []}}
        assert list(self._validator().iter_errors(doc)) == []

    @pytest.mark.parametrize(
        "doc",
        [
            {"deterministic_steps": {"opengrep": True}},
            {"precision_gates": {"fired": []}},
            {
                "precision_gates": {
                    "crit_high_evaluated": 1,
                    "fired": [{"candidate": "a", "gate": "g", "action": "dropped"}],
                }
            },
            {"coverage_gaps": [{"tool": "t", "system": "s"}]},
            {"assertive_inference": None},
            {"audit_passes": 0},
            {"model_routing": {"role": "r", "model": "m", "registry_sha": None}},
            {"degraded": "yes"},
        ],
    )
    def test_malformed_declared_fields_fail(self, doc):
        assert list(self._validator().iter_errors(doc)), doc


def _repo_state_validator() -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / "repo-state.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=build_registry())


def test_repo_state_records_an_observation_with_or_without_a_comparison() -> None:
    validator = _repo_state_validator()
    unchanged = {
        "observed_at": "2026-10-22T09:00:00Z",
        "status": "ok",
        "pushed_at": "2026-09-01T00:00:00Z",
    }
    validator.validate(unchanged)
    compared = {
        **unchanged,
        "comparison": {
            "ahead_by": 12,
            "truncated": False,
            "changed_lines": 340,
            "sensitive_changed": True,
            "sensitive_lines": 25,
            "deps_only": False,
        },
    }
    validator.validate(compared)
    validator.validate({"observed_at": "2026-10-22T09:00:00Z", "status": "no-pinned-sha"})
    validator.validate({**unchanged, "fork_of": "https://github.com/org/upstream"})


@pytest.mark.parametrize(
    "change",
    [
        {"status": "stale"},
        {"head_sha": "a" * 40},
        {"fork_of": "org/upstream"},
        {"comparison": {"ahead_by": 1}},
        {
            "comparison": {
                "ahead_by": -1,
                "truncated": False,
                "changed_lines": 0,
                "sensitive_changed": False,
                "sensitive_lines": 0,
                "deps_only": True,
            }
        },
    ],
    ids=[
        "unknown status",
        "fact owned by the ref row",
        "fork_of not a URL",
        "partial comparison",
        "negative count",
    ],
)
def test_repo_state_rejects_what_it_does_not_own(change: dict) -> None:
    document = {"observed_at": "2026-10-22T09:00:00Z", "status": "ok", **change}
    with pytest.raises(ValidationError):
        _repo_state_validator().validate(document)
