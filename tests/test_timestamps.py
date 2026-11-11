"""traust_contracts.v1.timestamps — predicate, transform, and model gate."""

from __future__ import annotations

import contextlib

import pytest
from pydantic import ValidationError

from traust_contracts.v1.models.layer import LayerEvent, ReviewItem
from traust_contracts.v1.timestamps import TimestampError, is_rfc3339, to_rfc3339

RFC3339 = [
    "2026-06-24T09:15:00+00:00",
    "2026-06-24T09:15:00Z",
    "2026-06-24T09:15:00-04:00",
    "2026-06-24T09:15:00.123456+00:00",
]

# Real information, wrong shape.
BARE_DATES = ["2026-06-24", "2026-07-20"]

# Parseable by datetime.fromisoformat but not RFC 3339 — no offset stated.
NAIVE = ["2026-06-24T09:15:00", "2026-06-24T09:15:00.500"]

GARBAGE = [
    "TrueT00:00:00+00:00",
    "FalseT00:00:00+00:00",
    "2026-01-16T00:00:00ZT00:00:00+00:00",
    "T00:00:00+00:00",
    "banana",
    "",
    "2026-13-45T99:00:00+00:00",
]

NON_STRINGS = [True, False, None, 20260624, 2.5, [], {}]


class TestIsRfc3339:
    @pytest.mark.parametrize("value", RFC3339)
    def test_accepts(self, value: str) -> None:
        assert is_rfc3339(value)

    @pytest.mark.parametrize("value", BARE_DATES + NAIVE + GARBAGE + NON_STRINGS)
    def test_rejects(self, value: object) -> None:
        assert not is_rfc3339(value)


class TestToRfc3339:
    @pytest.mark.parametrize("value", RFC3339)
    def test_conforming_input_is_returned_byte_for_byte(self, value: str) -> None:
        """event_id and the Merkle leaf hash the serialized event."""
        assert to_rfc3339(value) == value

    @pytest.mark.parametrize("value", BARE_DATES)
    def test_bare_date_padded_to_midnight_utc(self, value: str) -> None:
        assert to_rfc3339(value) == f"{value}T00:00:00+00:00"

    def test_surrounding_whitespace_tolerated(self) -> None:
        assert to_rfc3339("  2026-06-24  ") == "2026-06-24T00:00:00+00:00"

    @pytest.mark.parametrize("value", NAIVE + GARBAGE)
    def test_unconvertible_strings_raise(self, value: str) -> None:
        with pytest.raises(TimestampError):
            to_rfc3339(value)

    @pytest.mark.parametrize("value", NON_STRINGS)
    def test_non_strings_raise_naming_the_type(self, value: object) -> None:
        with pytest.raises(TimestampError, match=type(value).__name__):
            to_rfc3339(value)

    @pytest.mark.parametrize("value", BARE_DATES + RFC3339)
    def test_idempotent(self, value: str) -> None:
        once = to_rfc3339(value)
        assert to_rfc3339(once) == once

    def test_output_is_always_conforming_or_raises(self) -> None:
        for value in RFC3339 + BARE_DATES + NAIVE + GARBAGE + NON_STRINGS:
            with contextlib.suppress(TimestampError):
                assert is_rfc3339(to_rfc3339(value)), value


def _event(**overrides: object) -> dict:
    return {
        "event_id": "a" * 64,
        "finding_ref": "FIND-001",
        "recorded_at": RFC3339[0],
        "rationale": "probe rationale long enough to be realistic",
        "source": {
            "type": "triage_report",
            "ref": "probe-triage.json",
            "actor": {"kind": "machine", "identity": "triage/0.1.0"},
        },
        "disposition": {},
        **overrides,
    }


def _review_item(queued_at: object) -> dict:
    return {
        "queued_at": queued_at,
        "source_ref": "probe-comment-001",
        "quote": "Please review the reported finding.",
        "author": "fixture-author",
        "queue_reason": "undetermined_finding",
        "status": "pending",
    }


class TestModelGate:
    @pytest.mark.parametrize("value", RFC3339)
    def test_accepts_rfc3339(self, value: str) -> None:
        assert LayerEvent.model_validate(_event(recorded_at=value)).recorded_at == value

    @pytest.mark.parametrize("value", BARE_DATES + NAIVE + GARBAGE + [True, None])
    def test_rejects_recorded_at(self, value: object) -> None:
        with pytest.raises(ValidationError):
            LayerEvent.model_validate(_event(recorded_at=value))

    @pytest.mark.parametrize("value", BARE_DATES + GARBAGE)
    def test_rejects_occurred_at(self, value: object) -> None:
        with pytest.raises(ValidationError):
            LayerEvent.model_validate(_event(occurred_at=value))

    def test_does_not_transform_a_bare_date(self) -> None:
        """Converting is the producer's job; the gate's job is to say no."""
        with pytest.raises(ValidationError):
            LayerEvent.model_validate(_event(recorded_at="2026-06-24"))

    def test_occurred_at_stays_optional(self) -> None:
        """The post-migration shape: dropped, not faked."""
        assert LayerEvent.model_validate(_event()).occurred_at is None

    @pytest.mark.parametrize("value", RFC3339)
    def test_serialization_is_byte_preserving(self, value: str) -> None:
        out = LayerEvent.model_validate(_event(recorded_at=value, occurred_at=value)).to_dict()
        assert out["recorded_at"] == value
        assert out["occurred_at"] == value

    def test_review_submitter_is_optional_and_preserved(self) -> None:
        data = _review_item(RFC3339[0])
        assert "submitted_by" not in ReviewItem.model_validate(data).to_dict()
        data["submitted_by"] = {"kind": "machine", "identity": "fixture-submitter"}
        assert ReviewItem.model_validate(data).to_dict()["submitted_by"] == data["submitted_by"]

    def test_review_item_queued_at_is_gated(self) -> None:
        assert ReviewItem.model_validate(_review_item(RFC3339[0])).queued_at == RFC3339[0]
        with pytest.raises(ValidationError):
            ReviewItem.model_validate(_review_item("TrueT00:00:00+00:00"))

    def test_error_names_the_field_value_and_expected_shape(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            LayerEvent.model_validate(_event(recorded_at="TrueT00:00:00+00:00"))
        message = str(excinfo.value)
        assert "recorded_at" in message
        assert "TrueT00:00:00+00:00" in message
        assert "RFC 3339" in message


def test_schema_date_time_format_is_asserted() -> None:
    """Guards the dependency: an unregistered format passes everything."""
    import jsonschema

    checker = jsonschema.FormatChecker()
    assert "date-time" in checker.checkers, "jsonschema[format-nongpl] missing"
    assert not checker.conforms("TrueT00:00:00+00:00", "date-time")
