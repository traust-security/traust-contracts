#!/usr/bin/env python3
"""Administrative restatement events ($defs/event_restatement).

**Why this vocabulary exists.** Everything a layer asserts is either immutable
or unrecorded. Event payloads are append-only and the Merkle leaf binds their
full content, so a wrong field can only be superseded. The signature-bound
metadata digests (``claim_hashes``, ``audit_report_sha256``,
``artifact_digests``) are the opposite problem: mutable, with no record of the
prior value, who changed it, or why — so a legitimate re-audit and a tampering
rewrite look identical afterwards, and the only signal (a digest mismatch) had
to be adjudicated by a human every time.

These tests pin the block's shape and, more importantly, the two structural
invariants a consumer relies on: a restatement carries an EMPTY disposition (it
is not an evidence class), and ``restatement`` may not ride on any other source
type (so no ordinary event can smuggle one).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, ClassVar

import jsonschema
import pytest

from traust_contracts.v1.enums import RestatementReason, RestatementTarget, SourceType
from traust_contracts.v1.models.layer import LayerEvent

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "artifacts_schema" / "v1"
LAYER_SCHEMA = json.loads((SCHEMA_DIR / "layer.schema.json").read_text())

AUTHORITY: dict[str, Any] = {"ticket": "SEC-1234"}


def _errors(event: dict) -> list[str]:
    sub = {
        "$schema": LAYER_SCHEMA.get("$schema"),
        "$defs": LAYER_SCHEMA["$defs"],
        "$ref": "#/$defs/event",
    }
    return [e.message for e in jsonschema.Draft202012Validator(sub).iter_errors(event)]


def _restatement_event(**restatement) -> dict:
    block = {
        "target": "claim_hashes",
        "reason": "baseline_rewrite",
        "before": {"TEST_WIDGET-abcdef0-001": "a" * 64},
        "after": {"TEST_WIDGET-abcdef0-001": "b" * 64},
        "authority": AUTHORITY,
    }
    block.update(restatement)
    return {
        "event_id": "c" * 64,
        "finding_ref": "__layer__",
        "recorded_at": "2026-09-01T10:00:00+00:00",
        "source": {
            "type": "restatement",
            "ref": "restatement:2026-09-01:alice@example.com:9f3c1b2e77a1",
            "actor": {"kind": "human", "identity": "alice@example.com", "identity_verified": True},
        },
        "disposition": {},
        "rationale": "Baseline report reissued after the v1->v2 fingerprint re-stamp.",
        "restatement": block,
    }


class TestVocabulary:
    def test_restatement_is_a_source_type(self) -> None:
        assert "restatement" in LAYER_SCHEMA["$defs"]["source_type"]["enum"]

    def test_enum_and_schema_agree(self) -> None:
        declared = set(LAYER_SCHEMA["$defs"]["event_restatement"]["properties"]["target"]["enum"])
        assert {t.value for t in RestatementTarget} == declared
        declared = set(LAYER_SCHEMA["$defs"]["event_restatement"]["properties"]["reason"]["enum"])
        assert {r.value for r in RestatementReason} == declared

    def test_source_type_enum_covers_the_schema(self) -> None:
        """SourceType drifted: fuzz_report and rebaseline were in the schema and
        absent from the enum, so typed code could not name the source types the
        precedence engine must NOT weigh. Pin the two lists together."""
        assert {s.value for s in SourceType} == set(LAYER_SCHEMA["$defs"]["source_type"]["enum"])

    def test_non_evidence_status_is_documented(self) -> None:
        comment = LAYER_SCHEMA["$defs"]["source_type"]["$comment"]
        assert "restatement is NOT an evidence class" in comment


class TestStructure:
    def test_restatement_event_validates(self) -> None:
        assert _errors(_restatement_event()) == []

    def test_disposition_must_be_empty(self) -> None:
        """A restatement says data was wrong, not that a finding is real. If it
        could carry a disposition it would enter validity precedence, and an
        admin could adjudicate findings through the restatement path."""
        ev = _restatement_event()
        ev["disposition"] = {"validity": "false_positive"}
        assert _errors(ev)

    def test_ordinary_events_may_not_carry_a_restatement(self) -> None:
        ev = _restatement_event()
        ev["source"]["type"] = "interactive"
        ev["disposition"] = {"validity": "confirmed"}
        assert _errors(ev), "only source.type=restatement may carry a restatement block"

    def test_restatement_source_type_without_a_block_is_inert_not_invalid(self) -> None:
        """The converse of the smuggling rule is enforced by the ledger write
        path, not here. Expressing it needs a conditional ``required``, which
        the compatibility gate reads as a breaking change even though no
        artifact predating the ``restatement`` source type can trip it. Safe to
        leave to the writer: a restatement-typed event with no block carries an
        empty disposition, is not an evidence class, and gives a verifier
        nothing to apply."""
        ev = _restatement_event()
        del ev["restatement"]
        assert _errors(ev) == []

    def test_authority_ticket_is_required(self) -> None:
        assert _errors(_restatement_event(authority={}))
        assert _errors(_restatement_event(authority={"approved_by": "bob@example.com"}))

    def test_block_rejects_unknown_keys(self) -> None:
        assert _errors(_restatement_event(smuggled=True))

    @pytest.mark.parametrize("missing", ["target", "reason", "after", "authority"])
    def test_required_keys(self, missing: str) -> None:
        ev = _restatement_event()
        del ev["restatement"][missing]
        assert _errors(ev)

    def test_before_is_required(self) -> None:
        """A restatement asserts what it replaces. A field with no prior value
        is not restated at all — it is written through the ordinary path."""
        ev = _restatement_event(target="audit_report_sha256", after="d" * 64)
        del ev["restatement"]["before"]
        assert _errors(ev)

    def test_map_targets_take_a_delta_not_a_snapshot(self) -> None:
        """before/after carry only the changed entries, so an event's size
        tracks the change rather than the layer. Empty is meaningless."""
        assert _errors(_restatement_event(before={}, after={}))
        assert (
            _errors(_restatement_event(before={"FIND-1": "a" * 64}, after={"FIND-1": "b" * 64}))
            == []
        )


class TestTargetConstraints:
    def test_finding_aliases_is_not_a_target(self) -> None:
        """A rebaseline event already records a rename inside the Merkle tree,
        so metadata.finding_aliases is a rebuildable projection, not authority.
        Restating it would be a second mechanism for a solved problem."""
        targets = LAYER_SCHEMA["$defs"]["event_restatement"]["properties"]["target"]["enum"]
        assert "finding_aliases" not in targets
        assert _errors(_restatement_event(target="finding_aliases"))

    def test_event_content_is_not_a_target(self) -> None:
        """Events are immutable and are restated by appending a superseding
        determination, which latest-wins precedence already resolves. A
        read-time overlay would be a SECOND read-time transform competing with
        the v1->v2 normaliser, with no defined ordering between the two."""
        targets = LAYER_SCHEMA["$defs"]["event_restatement"]["properties"]["target"]["enum"]
        assert "event" not in targets
        assert _errors(_restatement_event(target="event"))

    def test_report_digest_target_takes_a_digest(self) -> None:
        assert _errors(_restatement_event(target="audit_report_sha256", after={"not": "a digest"}))
        assert _errors(_restatement_event(target="audit_report_sha256", after="nope"))
        ev = _restatement_event(target="audit_report_sha256", before="a" * 64, after="b" * 64)
        assert _errors(ev) == []

    def test_schema_migration_must_name_both_versions(self) -> None:
        assert _errors(_restatement_event(reason="schema_migration"))
        ev = _restatement_event(reason="schema_migration", schema_from="v1", schema_to="v2")
        assert _errors(ev) == []


class TestModelRoundTrip:
    """ContractModel ignores unknown keys, so a block declared only in the
    schema is silently dropped by from_dict/to_dict. That is precisely how
    `alias` and `finding` became unwritable through the typed path."""

    EVENT: ClassVar[dict[str, Any]] = _restatement_event()

    def test_round_trip_preserves_the_block(self) -> None:
        assert LayerEvent.from_dict(self.EVENT).to_dict() == self.EVENT

    def test_round_trip_preserves_alias_and_finding(self) -> None:
        ev = {
            "event_id": "a" * 64,
            "finding_ref": "TEST_WIDGET-abcdef0-001",
            "recorded_at": "2026-08-17T10:00:00+00:00",
            "source": {
                "type": "rebaseline",
                "ref": "rebaseline:2026-08-17",
                "actor": {"kind": "machine", "identity": "harness/0.1.0"},
            },
            "disposition": {},
            "rationale": "Finding renamed after the path canonicalisation change.",
            "alias": {"new_finding_ref": "TEST_WIDGET-abcdef0-002", "matched_by": "fingerprint"},
        }
        assert LayerEvent.from_dict(ev).to_dict() == ev

    def test_typed_access(self) -> None:
        event = LayerEvent.from_dict(self.EVENT)
        assert event.restatement is not None
        assert event.restatement.target is RestatementTarget.CLAIM_HASHES
        assert event.restatement.authority.ticket == "SEC-1234"
