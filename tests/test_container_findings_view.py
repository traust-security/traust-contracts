from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
VIEWS = ROOT / "views_schema/v1"
SCHEMA = VIEWS / "container-findings.schema.json"
RECORDS = VIEWS / "finding-records.schema.json"
F, R, A = (f"00000000-0000-4000-8000-00000000000{i}" for i in (1, 2, 3))
AT = "2026-11-16T00:00:00Z"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(json.loads(RECORDS.read_text()))
    resources = [
        (doc["$id"], Resource.from_contents(doc))
        for doc in (json.loads(p.read_text()) for p in sorted(VIEWS.glob("*.schema.json")))
    ]
    return Draft202012Validator(
        schema, registry=Registry().with_resources(resources), format_checker=FormatChecker()
    )


def _counts() -> dict[str, int]:
    return dict.fromkeys(("critical", "high", "medium", "low", "informational", "unrated"), 0)


def _occurrence() -> dict[str, Any]:
    return {
        "id": "00000000-0000-4000-8000-000000000004",
        "created_at": AT,
        "finding_id": F,
        "assessment_id": A,
        "severity": "high",
        "cvss_vector": None,
        "cvss_score": "7.5",
        "rule": "CVE-2026-0001",
    }


def _decision() -> dict[str, Any]:
    return {
        "id": "00000000-0000-4000-8000-000000000005",
        "created_at": AT,
        "finding_id": F,
        "assessment_id": None,
        "fixed_repository_ref_id": None,
        "repository_ref_id": None,
        "restates_id": None,
        "artifact_id": None,
        "statement_key": "stmt-1",
        "validity": "confirmed",
        "resolution": None,
        "evidence_grade": "E1",
        "reason": None,
        "severity": None,
        "source_channel": "interactive",
        "actor": "human:analyst@example.com",
        "rationale": "Reachable from the image entrypoint.",
        "ticket": None,
        "auto_accept_tier": False,
        "occurred_at": AT,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    tally = {
        "open": _counts() | {"high": 1},
        "hardening": 0,
        "resolved": 0,
        "risk_accepted": 0,
        "false_positive": 0,
        "execution_proven": 0,
        "unverified": 0,
        "decided": 1,
        "remediated": _counts(),
        "tracked": 0,
    }
    return {
        "as_of": None,
        "repository_id": R,
        "repository_url": "https://forge.example/o/image",
        "report_stem": "web-container-audit",
        "image_repository": "registry.example/o/web",
        "reports": [
            {
                "assessment_id": A,
                "repository_ref_id": R,
                "occurred_at": AT,
                "image": "registry.example/o/web:1.2",
                "title": "web container audit",
            }
        ],
        "findings": [
            {
                "view": {
                    "finding": {
                        "id": F,
                        "created_at": AT,
                        "updated_at": AT,
                        "repository_id": R,
                        "advisory_id": None,
                        "advisory_match": None,
                        "fingerprint_algo": "v1",
                        "fingerprint": "abc",
                        "kind": "vulnerability",
                        "title": "openssl in the base image",
                    },
                    "occurrence": _occurrence(),
                    "disposition": {
                        "finding_id": F,
                        "line": None,
                        "validity": "confirmed",
                        "resolution": None,
                        "assurance": "human_reviewed",
                        "conflict": False,
                        "fp_overridden": False,
                        "fp_reassertion_blocked": False,
                        "awaiting_signoff": False,
                        "severity": None,
                        "last_decision_at": AT,
                    },
                    "effective_severity": "high",
                    "sla_due": None,
                    "first_reported_at": AT,
                    "last_reported_at": AT,
                    "locations": [
                        {
                            "id": "00000000-0000-4000-8000-000000000006",
                            "created_at": AT,
                            "occurrence_id": "00000000-0000-4000-8000-000000000004",
                            "path": "usr/lib/libssl.so.3",
                            "line_start": None,
                            "line_end": None,
                            "language": None,
                            "symbol": None,
                        }
                    ],
                    "cwes": [],
                    "labels": [],
                },
                "occurrences": [_occurrence()],
                "history": [_decision()],
            }
        ],
        "total": tally,
    }


OBJECTS: dict[str, tuple[Any, ...]] = {
    "view": (),
    "report": ("reports", 0),
    "row": ("findings", 0),
    "finding_view": ("findings", 0, "view"),
    "finding": ("findings", 0, "view", "finding"),
    "occurrence": ("findings", 0, "view", "occurrence"),
    "disposition": ("findings", 0, "view", "disposition"),
    "decision": ("findings", 0, "history", 0),
}


def _object(document: dict[str, Any], scope: str) -> dict[str, Any]:
    target: Any = document
    for key in OBJECTS[scope]:
        target = target[key]
    return target


def _set(document: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


@pytest.mark.parametrize("scope", OBJECTS)
def test_every_serialized_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    for field in list(_object(document, scope)):
        broken = copy.deepcopy(document)
        del _object(broken, scope)[field]
        with pytest.raises(ValidationError):
            validator.validate(broken)


@pytest.mark.parametrize("scope", OBJECTS)
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], scope: str
) -> None:
    _object(document, scope)["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


LOCATION = ("findings", 0, "view", "locations", 0)


def test_a_claim_location_carries_only_its_four_fields(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    claim = {"path": "Dockerfile", "line_start": None, "line_end": 3, "symbol": None}
    _set(document, LOCATION, claim)
    validator.validate(document)
    del claim["path"]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("report_stem",), "web-audit"),
        (("report_stem",), "web-container-audit\n"),
        (("reports",), []),
        (OBJECTS["row"] + ("occurrences",), []),
        (OBJECTS["occurrence"] + ("severity",), "severe"),
        (OBJECTS["occurrence"] + ("cvss_score",), "high"),
        (OBJECTS["occurrence"] + ("cvss_score",), "-1"),
        (OBJECTS["occurrence"] + ("cvss_score",), "11"),
        (OBJECTS["occurrence"] + ("cvss_score",), "0E-10"),
        (OBJECTS["finding"] + ("id",), None),
        (OBJECTS["occurrence"] + ("created_at",), None),
        (OBJECTS["decision"] + ("id",), None),
        (OBJECTS["disposition"] + ("assurance",), "trusted"),
        (OBJECTS["disposition"] + ("validity",), "probably"),
        (OBJECTS["finding_view"] + ("effective_severity",), "unrated"),
        ((*LOCATION, "line_start"), 0),
        (OBJECTS["decision"] + ("occurred_at",), None),
        (("total", "tracked"), -1),
    ],
)
def test_out_of_contract_values_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    _set(document, path, invalid)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (OBJECTS["finding_view"] + ("occurrence",), None),
        (OBJECTS["finding_view"] + ("disposition",), None),
        (OBJECTS["finding_view"] + ("effective_severity",), None),
        (OBJECTS["occurrence"] + ("cvss_score",), "10"),
        (OBJECTS["occurrence"] + ("cvss_score",), "0"),
        (OBJECTS["occurrence"] + ("cvss_score",), None),
        (OBJECTS["finding"] + ("kind",), "legacy-kind"),
        (OBJECTS["decision"] + ("validity",), "not_verified"),
        (OBJECTS["decision"] + ("reason",), "a historical reason"),
        (("as_of",), AT),
    ],
)
def test_raw_values_and_nulls_core_serves_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], value: Any
) -> None:
    _set(document, path, value)
    validator.validate(document)


def _records() -> dict[str, Any]:
    return json.loads(RECORDS.read_text())["$defs"]


@pytest.mark.parametrize(
    ("registry", "node"),
    [
        ("scanner-severity", ("occurrence", "severity")),
        ("validity", ("disposition", "validity")),
        ("disposition-resolution", ("disposition", "resolution")),
        ("disposition-assurance", ("disposition", "assurance")),
        ("severity", ("disposition", "severity")),
        ("severity", ("finding_view", "effective_severity")),
    ],
)
def test_record_vocabularies_match_their_registries(registry: str, node: tuple[str, str]) -> None:
    values = json.loads((ROOT / f"enums/v1/{registry}.json").read_text())["values"]
    enum = _records()[node[0]]["properties"][node[1]]["enum"]
    assert [v for v in enum if v is not None] == values


def test_finding_records_are_shared_definitions_not_a_view() -> None:
    records = json.loads(RECORDS.read_text())
    assert "type" not in records and "properties" not in records
    view = SCHEMA.read_text()
    for definition in ("finding_view", "occurrence", "decision"):
        assert f"finding-records.schema.json#/$defs/{definition}" in view


@pytest.mark.parametrize("partial", ["id", "created_at", "occurrence_id", "language"])
def test_a_location_is_a_claim_or_a_whole_recorded_one(
    validator: Draft202012Validator, document: dict[str, Any], partial: str
) -> None:
    recorded = {"id": F, "created_at": AT, "occurrence_id": F, "language": None}
    claim = {"path": "Dockerfile", "line_start": None, "line_end": 3, "symbol": None}
    _set(document, LOCATION, claim | {partial: recorded[partial]})
    with pytest.raises(ValidationError):
        validator.validate(document)
    _set(document, LOCATION, claim | recorded)
    validator.validate(document)
