"""Offline classifier coverage uses exact typed observations, not coercion."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "classifier_mappings", ROOT / "ci" / "classifier_mappings.py"
)
classifier_mappings = importlib.util.module_from_spec(_spec)
sys.modules["classifier_mappings"] = classifier_mappings
_spec.loader.exec_module(classifier_mappings)


@pytest.fixture
def registry():
    return {
        "colour": {
            "name": "colour",
            "values": ["red", "blue", "crimson", "navy", "dropped"],
            "deprecated": {
                "crimson": {"replaced_by": [{"enum": "colour", "value": "red"}]},
                "navy": {
                    "replaced_by": [
                        {"enum": "colour", "value": "blue"},
                        {"enum": "shade", "value": "dark"},
                    ]
                },
                "dropped": {"replaced_by": []},
                "retired": {
                    "replaced_by": [{"enum": "colour", "value": "red"}],
                    "retired": True,
                },
            },
        },
        "shade": {"name": "shade", "values": ["dark", "light"]},
    }


def _alias(raw, value, *, status="mapped", enum="colour"):
    return {
        "raw": raw,
        "targets": [{"enum": enum, "value": value}],
        "status": status,
        "reason": "Explicit synthetic historical projection.",
    }


def _mappings(*aliases, nullable=False):
    return {
        "version": 1,
        "fields": {
            "sample|finding.colour": {
                "enum": "colour",
                "nullable": nullable,
                "aliases": list(aliases),
            }
        },
    }


def _inventory(*raw_values, field="sample|finding.colour"):
    return {"fields": {field: {"raw_values": [{"raw": raw, "count": 1} for raw in raw_values]}}}


def _records(report, field="sample|finding.colour"):
    return report["fields"][field]["records"]


def _by_raw(records, raw):
    key = classifier_mappings.typed_key(raw)
    return next(record for record in records if classifier_mappings.typed_key(record["raw"]) == key)


def test_typed_aliases_do_not_coerce_scalars_or_nested_values(registry):
    aliases = [
        _alias(False, "red"),
        _alias(0, "blue"),
        _alias(0.0, "red"),
        _alias("0", "blue"),
        _alias("null", "red"),
        _alias([False, {"key": 0}], "blue"),
        _alias([0, {"key": False}], "red"),
    ]
    raw = [False, 0, 0.0, "0", None, "null", [False, {"key": 0}], [0, {"key": False}], True]
    report = classifier_mappings.coverage(
        _inventory(*raw), _mappings(*aliases, nullable=True), registry
    )
    records = _records(report)
    assert len(records) == len(raw)
    for alias in aliases:
        assert _by_raw(records, alias["raw"])["targets"] == alias["targets"]
    assert _by_raw(records, None)["status"] == "observed_absence"
    assert _by_raw(records, None)["targets"] == []
    assert _by_raw(records, True)["status"] == "unmapped"


def test_null_requires_nullable_binding_and_literal_null_is_not_absence(registry):
    inventory = _inventory(None, "null")
    required = classifier_mappings.coverage(inventory, _mappings(), registry)
    nullable = classifier_mappings.coverage(inventory, _mappings(nullable=True), registry)
    assert [record["status"] for record in _records(required)] == ["unmapped", "unmapped"]
    assert _by_raw(_records(nullable), None)["status"] == "observed_absence"
    assert _by_raw(_records(nullable), "null")["status"] == "unmapped"


def test_registry_fallthrough_keeps_split_and_retired_replacements(registry):
    report = classifier_mappings.coverage(
        _inventory("red", "crimson", "navy", "dropped", "retired", "RED"),
        _mappings(),
        registry,
    )
    records = _records(report)
    assert _by_raw(records, "red")["targets"] == [{"enum": "colour", "value": "red"}]
    assert _by_raw(records, "crimson")["targets"] == [{"enum": "colour", "value": "red"}]
    assert _by_raw(records, "navy")["targets"] == [
        {"enum": "colour", "value": "blue"},
        {"enum": "shade", "value": "dark"},
    ]
    assert _by_raw(records, "retired")["status"] == "mapped"
    assert _by_raw(records, "dropped")["status"] == "unmapped"
    assert _by_raw(records, "dropped")["targets"] == []
    assert _by_raw(records, "RED")["status"] == "unmapped"


def test_aliases_precede_both_current_and_deprecated_registry_values(registry):
    operation = {
        "raw": "dropped",
        "targets": [],
        "status": "non_evidence_operation",
        "reason": "Operation.",
    }
    report = classifier_mappings.coverage(
        _inventory("red", "crimson", "dropped"),
        _mappings(_alias("red", "blue"), _alias("crimson", "blue"), operation),
        registry,
    )
    records = _records(report)
    assert _by_raw(records, "red")["targets"] == [{"enum": "colour", "value": "blue"}]
    assert _by_raw(records, "crimson")["targets"] == [{"enum": "colour", "value": "blue"}]
    assert _by_raw(records, "dropped")["status"] == "non_evidence_operation"
    assert _by_raw(records, "dropped")["targets"] == []


def test_full_field_coverage_counts_every_entry_and_ignores_old_string_counts(registry):
    mappings = _mappings()
    for status in ("unmapped", "observational", "open_label", "provenance"):
        mappings["fields"][f"sample|{status}"] = {"status": status, "reason": "Reviewed field."}
    inventory = {
        "files": 3,
        "unreadable": [],
        "fields": {
            "sample|finding.colour": {
                "values": {"red": 900},
                "total": 9,
                "raw_values": [
                    {"raw": "red", "count": 2, "example": "synthetic.json"},
                    {"raw": "blue", "count": 3},
                    {"raw": "absent", "count": 4},
                ],
            },
            "new-artifact|unbound.field": {"raw_values": [{"raw": False, "count": 5}]},
            **{
                f"sample|{status}": {"raw_values": [{"raw": "any", "count": 1}]}
                for status in ("unmapped", "observational", "open_label", "provenance")
            },
            "sample|empty": {"raw_values": []},
        },
    }
    original = copy.deepcopy((inventory, mappings, registry))
    report = classifier_mappings.coverage(inventory, mappings, registry)
    assert set(report["fields"]) == set(inventory["fields"])
    assert len(_records(report)) == 3
    assert _by_raw(_records(report), "red")["count"] == 2
    assert _by_raw(_records(report), "blue")["count"] == 3
    assert any(record.get("example") == "synthetic.json" for record in _records(report))
    assert report["totals"]["observed_total"] == 18
    assert report["totals"]["accounted_total"] == 18
    assert report["totals"]["unmapped_total"] == 10
    assert report["totals"]["unmapped_records"] == 3
    assert report["totals"]["status_counts"]["mapped"] == 5
    assert report["totals"]["record_counts"]["mapped"] == 2
    for field, summary in report["fields"].items():
        assert summary["observed_total"] == summary["accounted_total"]
        assert sum(summary["status_counts"].values()) == summary["observed_total"]
        assert sum(summary["record_counts"].values()) == len(summary["records"])
        if field == "new-artifact|unbound.field":
            assert summary["records"][0]["status"] == "unmapped"
    assert (inventory, mappings, registry) == original


def test_approved_size_projection_does_not_invent_size_or_blocking():
    inventory = _inventory(
        "xs",
        "XS",
        "trivial",
        "moderate",
        "significant",
        "blocked-external",
        "two days",
        None,
        field="findings-current|roadmap.effort",
    )
    report = classifier_mappings.coverage(
        inventory,
        json.loads(classifier_mappings.MAPPINGS_PATH.read_text()),
        classifier_mappings.load_registry()[0],
    )
    records = _records(report, "findings-current|roadmap.effort")
    for raw in ("xs", "XS"):
        assert _by_raw(records, raw)["targets"] == [{"enum": "effort", "value": "xs"}]
    for raw in ("trivial", "moderate", "significant"):
        result = _by_raw(records, raw)
        assert result["status"] == "mapped_unknown"
        assert result["targets"] == [{"enum": "effort", "value": None}]
    blocked = _by_raw(records, "blocked-external")
    assert blocked["status"] == "mapped_unknown"
    assert blocked["targets"] == [
        {"enum": "effort", "value": None},
        {"field": "blocked_external", "value": True},
    ]
    assert _by_raw(records, "two days")["status"] == "unmapped"
    assert _by_raw(records, None)["status"] == "observed_absence"
    assert _by_raw(records, None)["targets"] == []


def test_ambiguous_priorities_and_standard_grade_case_are_not_guessed():
    inventory = {
        "fields": {
            "findings-current|roadmap.priority": {
                "raw_values": [
                    {"raw": value, "count": 1}
                    for value in ("p0", "P0", "first", "urgent", "1", 1, "next week")
                ]
            },
            "synthetic|grade": {
                "raw_values": [
                    {"raw": value, "count": 1} for value in ("E0", "e0", "human", "strong")
                ]
            },
        }
    }
    mappings = json.loads(classifier_mappings.MAPPINGS_PATH.read_text())
    mappings["fields"]["synthetic|grade"] = {"enum": "evidence_grade", "aliases": []}
    report = classifier_mappings.coverage(
        inventory,
        mappings,
        classifier_mappings.load_registry()[0],
    )
    priority = _records(report, "findings-current|roadmap.priority")
    for raw in ("p0", "P0"):
        assert _by_raw(priority, raw)["targets"] == [{"enum": "roadmap_priority", "value": "p0"}]
    for raw in ("first", "urgent", "1", 1, "next week"):
        assert _by_raw(priority, raw)["status"] == "unmapped"
    grade = _records(report, "synthetic|grade")
    assert _by_raw(grade, "E0")["status"] == "mapped"
    for raw in ("e0", "human", "strong"):
        assert _by_raw(grade, raw)["status"] == "unmapped"


def test_historical_rejection_needs_per_item_closure_context():
    field = "findings-layer|needs_review.status"
    inventory = _inventory("rejected", "confirmed", "pending", field=field)
    inventory["fields"]["findings-layer|x.rejected*resolution_note"] = {
        "raw_values": [{"raw": "bulk-closed: administrative cleanup", "count": 1}]
    }
    report = classifier_mappings.coverage(
        inventory,
        json.loads(classifier_mappings.MAPPINGS_PATH.read_text()),
        classifier_mappings.load_registry()[0],
    )
    records = _records(report, field)
    assert _by_raw(records, "rejected")["status"] == "unmapped"
    assert _by_raw(records, "rejected")["targets"] == []
    assert _by_raw(records, "confirmed")["targets"] == [
        {"enum": "review_item_status", "value": "accepted"}
    ]
    assert _by_raw(records, "pending")["targets"] == [
        {"enum": "review_item_status", "value": "pending"}
    ]
    assert report["fields"][field]["unmapped_total"] == 1
    assert report["fields"][field]["status_counts"]["mapped"] == 2


@pytest.mark.parametrize("raw", ["red", False, 0, None, [False], {"a": 0, "b": False}])
def test_duplicate_typed_aliases_are_rejected(registry, raw):
    mappings = _mappings(_alias(raw, "red"), _alias(copy.deepcopy(raw), "blue"))
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.validate_mappings(mappings, registry)


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data.__setitem__("version", True),
        lambda data: data.__setitem__("unexpected", {}),
        lambda data: data.__setitem__("fields", []),
        lambda data: data["fields"].__setitem__("invalid-field", {"enum": "colour", "aliases": []}),
        lambda data: data["fields"]["sample|finding.colour"].__setitem__("enum", "unknown"),
        lambda data: data["fields"]["sample|finding.colour"].__setitem__("nullable", 1),
        lambda data: data["fields"]["sample|finding.colour"].__setitem__("aliases", {}),
        lambda data: data["fields"]["sample|finding.colour"].__setitem__("status", "mapped"),
        lambda data: data["fields"].__setitem__(
            "sample|other", {"status": "mapped", "reason": "No."}
        ),
        lambda data: data["fields"].__setitem__(
            "sample|other", {"status": "unmapped", "reason": ""}
        ),
    ],
)
def test_invalid_mapping_bindings_are_rejected(registry, change):
    mappings = _mappings()
    change(mappings)
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.validate_mappings(mappings, registry)


@pytest.mark.parametrize(
    "alias",
    [
        _alias("raw", "crimson"),
        _alias("raw", "not-a-value"),
        _alias("raw", "red", enum="unknown"),
        _alias("raw", None),
        _alias("raw", "red", status="mapped_unknown"),
        _alias("raw", "red", status="non_evidence_operation"),
        _alias("raw", "red", status="unmapped"),
        {"raw": "raw", "targets": [], "status": "mapped", "reason": "Empty."},
        {"raw": "raw", "targets": [], "status": "non_evidence_operation", "reason": ""},
        {
            "raw": "raw",
            "targets": [{"field": "blocked_external", "value": False}],
            "status": "mapped",
            "reason": "Cannot infer false blocking.",
        },
        {
            "raw": "raw",
            "targets": [{"field": "blocked_external", "value": 1}],
            "status": "mapped",
            "reason": "Boolean required.",
        },
        {
            "raw": "raw",
            "targets": [{"enum": "colour", "value": "red"}] * 2,
            "status": "mapped",
            "reason": "Duplicate target dimension.",
        },
    ],
)
def test_invalid_alias_targets_and_statuses_are_rejected(registry, alias):
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.validate_mappings(_mappings(alias), registry)


@pytest.mark.parametrize("count", [True, False, 0, -1, 1.5, "1", None])
def test_counts_require_positive_nonboolean_integers(registry, count):
    inventory = {
        "fields": {"sample|finding.colour": {"raw_values": [{"raw": "red", "count": count}]}}
    }
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.coverage(inventory, _mappings(), registry)


@pytest.mark.parametrize("total", [True, -1, 1.0, "1", 0, 2])
def test_declared_totals_cannot_hide_missing_or_invalid_observations(registry, total):
    inventory = _inventory("red")
    inventory["fields"]["sample|finding.colour"]["total"] = total
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.coverage(inventory, _mappings(), registry)


@pytest.mark.parametrize(
    "field",
    [
        {"values": {"null": 1, "false": 2}, "total": 3},
        {"raw_values": {}},
        {"raw_values": [{"count": 1}]},
        {"raw_values": [{"raw": "red"}]},
        {"raw_values": [{"raw": "red", "count": 1, "example": None}]},
        {"raw_values": [{"raw": float("inf"), "count": 1}]},
    ],
)
def test_missing_or_malformed_typed_inventory_is_rejected(registry, field):
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.coverage(
            {"fields": {"sample|finding.colour": field}}, _mappings(), registry
        )


def _write_json(path, document):
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _cli_files(tmp_path, registry, inventory=None):
    enums = tmp_path / "enums"
    enums.mkdir()
    for name, entry in registry.items():
        _write_json(enums / f"{name}.json", entry)
    source = _write_json(tmp_path / "inventory.json", inventory or _inventory("red", "missing"))
    mappings = _write_json(tmp_path / "mappings.json", _mappings())
    output = tmp_path / "coverage.json"
    args = [
        "--inventory",
        str(source),
        "--mappings",
        str(mappings),
        "--enums",
        str(enums),
        "--out",
        str(output),
    ]
    return args, source, mappings, enums, output


def test_cli_check_writes_complete_deterministic_coverage_and_content_hashes(tmp_path, registry):
    args, source, mappings, enums, output = _cli_files(tmp_path, registry)
    originals = {path: path.read_bytes() for path in (source, mappings, *enums.glob("*.json"))}
    assert classifier_mappings.main([*args, "--check"]) == 1
    first = output.read_bytes()
    report = json.loads(first)
    assert report["totals"]["observed_total"] == report["totals"]["accounted_total"] == 2
    assert report["totals"]["unmapped_total"] == 1
    assert report["sha256"]["source"] == hashlib.sha256(originals[source]).hexdigest()
    assert report["sha256"]["mappings"] == hashlib.sha256(originals[mappings]).hexdigest()
    for name, digest in report["sha256"]["registry_files"].items():
        assert digest == hashlib.sha256(originals[enums / name]).hexdigest()
    assert classifier_mappings.main([*args, "--check"]) == 1
    assert output.read_bytes() == first
    assert classifier_mappings.main(args) == 0
    assert output.read_bytes() == first
    assert all(path.read_bytes() == content for path, content in originals.items())


def test_coverage_is_stable_when_inventory_field_and_entry_order_changes(registry):
    inventory = _inventory("red", "navy", False, None, "red")
    inventory["fields"]["sample|other"] = {"raw_values": [{"raw": "any", "count": 3}]}
    reordered = copy.deepcopy(inventory)
    reordered["fields"] = dict(reversed(list(reordered["fields"].items())))
    for field in reordered["fields"].values():
        field["raw_values"].reverse()
    original = classifier_mappings.coverage(inventory, _mappings(), registry)
    assert classifier_mappings.coverage(reordered, _mappings(), registry) == original


def test_cli_check_succeeds_when_all_typed_entries_are_accounted_for(tmp_path, registry):
    args, _, _, _, output = _cli_files(tmp_path, registry, _inventory("red", "navy"))
    assert classifier_mappings.main([*args, "--check"]) == 0
    assert json.loads(output.read_text())["totals"]["unmapped_records"] == 0


@pytest.mark.parametrize("malformed", ["{", '{"fields": {}, "fields": {}}', '{"fields": NaN}'])
def test_cli_reports_malformed_json_as_exit_two(tmp_path, registry, malformed):
    args, source, _, _, output = _cli_files(tmp_path, registry)
    source.write_text(malformed, encoding="utf-8")
    assert classifier_mappings.main(args) == 2
    assert not output.exists()


def test_cli_rejects_values_only_inventory_without_writing_coverage(tmp_path, registry):
    args, source, _, _, output = _cli_files(tmp_path, registry)
    _write_json(source, {"fields": {"sample|finding.colour": {"values": {"red": 1}}}})
    assert classifier_mappings.main([*args, "--check"]) == 2
    assert not output.exists()


@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_cli_rejects_overwriting_input_artifacts(tmp_path, registry, alias):
    args, source, _, _, output = _cli_files(tmp_path, registry)
    original = source.read_bytes()
    if alias == "symlink":
        output.symlink_to(source)
    elif alias == "hardlink":
        output.hardlink_to(source)
    else:
        args[-1] = str(source)
    assert classifier_mappings.main(args) == 2
    assert source.read_bytes() == original


def test_registry_hash_changes_when_registry_content_changes(tmp_path, registry):
    _, source, mappings, enums, _ = _cli_files(tmp_path, registry)
    first = classifier_mappings.build_report(source, mappings, enums)
    registry["shade"]["description"] = "An explanatory edit still changes source content."
    _write_json(enums / "shade.json", registry["shade"])
    second = classifier_mappings.build_report(source, mappings, enums)
    assert first["sha256"]["registry"] != second["sha256"]["registry"]
    first_hash = first["sha256"]["registry_files"]["shade.json"]
    second_hash = second["sha256"]["registry_files"]["shade.json"]
    assert first_hash != second_hash


@pytest.mark.parametrize("case", ["unknown", "deprecated", "duplicate", "empty", "chain"])
def test_invalid_registry_replacements_fail_closed(registry, case):
    if case == "unknown":
        registry["colour"]["deprecated"]["crimson"]["replaced_by"][0]["enum"] = "unknown"
    elif case == "deprecated":
        registry["colour"]["deprecated"]["crimson"]["replaced_by"][0]["value"] = "navy"
    elif case == "duplicate":
        registry["colour"]["deprecated"]["navy"]["replaced_by"].append(
            {"enum": "colour", "value": "red"}
        )
    elif case == "empty":
        registry["shade"]["values"] = []
    else:
        registry["shade"]["deprecated"] = {
            "dark": {"replaced_by": [{"enum": "colour", "value": "red"}]}
        }
    with pytest.raises(classifier_mappings.MappingError):
        classifier_mappings.coverage(_inventory("red"), _mappings(), registry)


@pytest.mark.parametrize(
    "field",
    [
        "findings-current|finding.disposition.validity",
        "findings-current|finding.validation_status",
        "security-audit|finding.validation_status",
    ],
)
def test_historical_absence_and_correction_never_invent_a_validity_answer(field):
    report = classifier_mappings.coverage(
        _inventory("not_verified", "corrected", field=field),
        json.loads(classifier_mappings.MAPPINGS_PATH.read_text()),
        classifier_mappings.load_registry()[0],
    )
    records = _records(report, field)
    assert _by_raw(records, "not_verified")["status"] == "mapped_unknown"
    assert _by_raw(records, "not_verified")["targets"] == [{"enum": "validity", "value": None}]
    assert _by_raw(records, "corrected")["status"] == "non_evidence_operation"
    assert _by_raw(records, "corrected")["targets"] == []
