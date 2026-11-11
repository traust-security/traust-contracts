#!/usr/bin/env python3
"""Event-carried `alias` (B1a) and `finding` (B1) blocks.

Both exist because only baseline-writing audit skills may write an
audit baseline (events, not state).

**Why these tests exist at all.** P2 shipped the alias mechanism in the engine —
`events.aliases_from_events()` reads `event["alias"]` and
`build_cumulative` merges it over the legacy table — but never declared `alias`
on `$defs/event`, which sets `additionalProperties: false`. So every alias event
was schema-invalid, and the feature had never run: zero alias events existed in
the corpus, while many layers still used the table it was meant to replace. Engine
support without schema support produces code that reads what validation rejects.
These tests validate REAL events bearing both blocks so that cannot recur.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, ClassVar

import jsonschema
import pytest

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "artifacts_schema" / "v1"
LAYER_SCHEMA = json.loads((SCHEMA_DIR / "layer.schema.json").read_text())


def _event(**extra) -> dict:
    ev = {
        "event_id": "a" * 64,
        "finding_ref": "TEST_WIDGET-abcdef0-001",
        "recorded_at": "2026-08-17T10:00:00+00:00",
        "source": {
            "type": "vuln_scan_report",
            "ref": "test-widget-vuln-findings.json",
            "actor": {"kind": "machine", "identity": "vuln-scan/0.282.0"},
        },
        "disposition": {"resolution": "open"},
        "rationale": "Discovered by a between-audit sweep; enters at "
        "not_verified for downstream adjudication.",
    }
    ev.update(extra)
    return ev


def _errors(event: dict) -> list[str]:
    """Validate one event against $defs/event alone.

    The sub-schema carries only $defs + a $ref, never the layer's top-level
    properties/required — otherwise every event would also be asked for
    `metadata` and `events`.
    """
    sub = {
        "$schema": LAYER_SCHEMA.get("$schema"),
        "$defs": LAYER_SCHEMA["$defs"],
        "$ref": "#/$defs/event",
    }
    v = jsonschema.Draft202012Validator(sub)
    return [e.message for e in v.iter_errors(event)]


class TestSourceTypeVocabulary:
    def test_vuln_scan_report_is_a_source_type(self) -> None:
        enum = LAYER_SCHEMA["$defs"]["source_type"]["enum"]
        assert "vuln_scan_report" in enum

    def test_evidence_class_comment_names_it(self) -> None:
        # Evidence strength beats actor authority (tenet 4) — the class must be
        # documented or build_cumulative's precedence is undefined for it.
        assert "vuln_scan_report" in LAYER_SCHEMA["$defs"]["source_type"]["$comment"]


class TestAliasBlock:
    """B1a — P2's mechanism, now declarable."""

    def test_alias_event_validates(self) -> None:
        ev = _event(
            alias={"new_finding_ref": "TEST_WIDGET-9999999-004", "matched_by": "fingerprint"}
        )
        assert _errors(ev) == []

    def test_alias_rejects_unknown_key(self) -> None:
        ev = _event(alias={"new_finding_ref": "X-1", "matched_by": "manual", "smuggled": True})
        assert _errors(ev), "alias must not accept arbitrary keys"

    def test_alias_requires_successor_and_match_tier(self) -> None:
        assert _errors(_event(alias={"matched_by": "fingerprint"}))
        assert _errors(_event(alias={"new_finding_ref": "X-1"}))

    def test_alias_match_tiers_match_the_legacy_table(self) -> None:
        """The event form must not diverge from the table it supersedes."""
        table = LAYER_SCHEMA["$defs"]["layer_metadata"]["properties"]["finding_aliases"][
            "additionalProperties"
        ]["properties"]["matched_by"]["enum"]
        block = LAYER_SCHEMA["$defs"]["event_alias"]["properties"]["matched_by"]["enum"]
        assert sorted(block) == sorted(table)

    def test_engine_readable_fields_are_all_declared(self) -> None:
        """Every key aliases_from_events() consumes must be declarable.

        This is the exact assertion whose absence let P2 ship unusable.
        """
        consumed = {
            "new_finding_ref",
            "matched_by",
            "confirmed",
            "rejected",
            "similarity",
            "path_overlap",
            "from_report",
            "note",
        }
        declared = set(LAYER_SCHEMA["$defs"]["event_alias"]["properties"])
        assert consumed <= declared, consumed - declared


class TestFindingBlock:
    """B1 — a finding discovered between audits rides on the event."""

    CLAIM: ClassVar[dict[str, Any]] = {
        "id": "TEST_WIDGET-8ff0742-001",
        "title": "Unvalidated redirect in the callback handler",
        "severity": "medium",
        "cwes": ["CWE-601"],
        "locations": [{"path": "pkg/auth/callback.go", "lines": "88-94"}],
        "description": "The callback handler echoes the `next` parameter.",
        "remediation": "Allow-list redirect targets.",
    }

    def test_finding_carrying_event_validates(self) -> None:
        ev = _event(
            finding={
                **self.CLAIM,
                "validation_status": "not_verified",
                "origin": "vuln-scan",
                "source_findings": ["test-widget-vuln-findings.json#TW-001"],
            }
        )
        assert _errors(ev) == []

    @pytest.mark.parametrize("missing", sorted(CLAIM))
    def test_every_canonical_claim_field_is_required(self, missing) -> None:
        """The required set must equal what claim_hashes pins.

        If these drift apart, an event-carried claim cannot be pinned on the
        same terms as a baselined one and tamper-evidence has a hole.
        """
        claim = {k: v for k, v in self.CLAIM.items() if k != missing}
        assert _errors(_event(finding=claim)), f"{missing} should be required"

    def test_cwe_pattern_enforced(self) -> None:
        bad = {**self.CLAIM, "cwes": ["601"]}
        assert _errors(_event(finding=bad))

    def test_severity_vocabulary_matches_reports(self) -> None:
        report = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
        assert (
            LAYER_SCHEMA["$defs"]["event_finding"]["properties"]["severity"]["enum"]
            == report["$defs"]["severity_level"]["enum"]
        )

    def test_required_set_equals_report_finding_required(self) -> None:
        report = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
        assert sorted(LAYER_SCHEMA["$defs"]["event_finding"]["required"]) == sorted(
            report["$defs"]["finding"]["required"]
        )


class TestBackwardCompatibility:
    def test_plain_event_still_validates(self) -> None:
        """Neither block is required — all existing events must stay valid."""
        assert _errors(_event()) == []

    def test_both_blocks_together(self) -> None:
        ev = _event(
            alias={"new_finding_ref": "X-2", "matched_by": "manual"}, finding=TestFindingBlock.CLAIM
        )
        assert _errors(ev) == []

    def test_event_still_rejects_unknown_top_level_keys(self) -> None:
        assert _errors(_event(sneaky="value"))


class TestArrivalDisposition:
    """An arrival is not a determination — it is `resolution: open`.

    Confirmed against the corpus rather than invented: all existing
    impact_report events use exactly {"resolution": "open"}, as do all
    verification_report events. Resolution is the lifecycle axis, validity the
    truth axis — a newly discovered finding is
    OPEN with validity unstated. No new vocabulary is needed for B1.
    """

    def test_resolution_open_is_a_valid_arrival(self) -> None:
        ev = _event(disposition={"resolution": "open"}, finding=TestFindingBlock.CLAIM)
        assert _errors(ev) == []

    def test_scan_time_validity_is_not_expressible_as_not_verified(self) -> None:
        # 'not_verified' is a report-level validation_status, never an event
        # validity — the event vocabulary is confirmed/false_positive/
        # corrected/hardening. Nothing at scan time confirms.
        assert _errors(_event(disposition={"validity": "not_verified"}))

    def test_disposition_cannot_be_empty(self) -> None:
        # minProperties: 1 — an event always records something.
        assert _errors(_event(disposition={}))
