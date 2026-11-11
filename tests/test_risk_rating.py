"""OWASP Risk Rating Methodology: the calculator and the threat-model schema.

The worked example below is the one the methodology itself uses
(https://owasp.org/www-community/OWASP_Risk_Rating_Methodology): likelihood
4.375 (medium), technical impact 7.25 (high), business impact 2.25 (low).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from traust_contracts.v1 import risk_rating as rr

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads(
    (ROOT / "artifacts_schema/v1/threat-model.schema.json").read_text(encoding="utf-8")
)

L = dict(zip(rr.LIKELIHOOD_FACTORS, [5, 2, 7, 1, 3, 6, 9, 2], strict=True))
T = dict(zip(rr.TECHNICAL_IMPACT_FACTORS, [9, 7, 5, 8], strict=True))
B = dict(zip(rr.BUSINESS_IMPACT_FACTORS, [1, 2, 1, 5], strict=True))


def test_worked_example_technical_basis():
    rating = rr.rate(L, T)
    assert rating["likelihood"]["score"] == 4.375
    assert rating["likelihood"]["level"] == "medium"
    assert rating["impact"]["score"] == 7.25
    assert rating["impact"]["level"] == "high"
    assert rating["severity"] == "high"


def test_worked_example_business_basis_is_preferred_when_known():
    rating = rr.rate(L, T, B)
    assert rating["impact"]["basis"] == "business"
    assert rating["impact"]["score"] == 2.25
    assert rating["impact"]["level"] == "low"
    assert rating["severity"] == "low"


@pytest.mark.parametrize(
    ("impact", "likelihood", "want"),
    [
        ("high", "low", "medium"),
        ("high", "medium", "high"),
        ("high", "high", "critical"),
        ("medium", "low", "low"),
        ("medium", "medium", "medium"),
        ("medium", "high", "high"),
        ("low", "low", "note"),
        ("low", "medium", "low"),
        ("low", "high", "medium"),
    ],
)
def test_severity_table(impact, likelihood, want):
    assert rr.severity(impact, likelihood) == want


@pytest.mark.parametrize(
    ("score", "want"),
    [(0, "low"), (2.999, "low"), (3, "medium"), (5.999, "medium"), (6, "high"), (9, "high")],
)
def test_level_boundaries(score, want):
    assert rr.level(score) == want


def test_severity_rank_orders_note_to_critical():
    assert [rr.severity_rank(s) for s in rr.SEVERITIES] == [0, 1, 2, 3, 4]
    assert rr.severity_rank(None) == -1


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda r: r["likelihood"].__setitem__("score", 5.0), "likelihood.score"),
        (lambda r: r["impact"].__setitem__("level", "low"), "impact.level"),
        (lambda r: r.__setitem__("severity", "critical"), "severity"),
        (lambda r: r["likelihood"]["factors"].__setitem__("motive", 10), "0 to 9"),
        (lambda r: r["likelihood"]["factors"].pop("awareness"), "missing factors ['awareness']"),
        (lambda r: r["impact"].__setitem__("basis", "business"), "needs its factor set"),
        (lambda r: r.__setitem__("method", "home-grown"), "method"),
    ],
)
def test_problems_catches_inconsistent_ratings(mutate, expected):
    rating = rr.rate(L, T)
    assert rr.problems(rating) == []
    broken = copy.deepcopy(rating)
    mutate(broken)
    found = rr.problems(broken)
    assert any(expected in p for p in found), found


def test_rate_rejects_bad_factors():
    with pytest.raises(ValueError, match="0 to 9"):
        rr.rate({**L, "motive": -1}, T)


def _model(threat: dict) -> dict:
    return {
        "system": "example",
        "provenance": {"mode": "bootstrap", "date": "2026-09-30", "target": "example"},
        "threats": [threat],
    }


_BASE = {
    "id": "T1",
    "threat": "Example threat",
    "actor": ["remote_unauth"],
    "status": "unmitigated",
}


def _errors(doc: dict) -> list[str]:
    return [e.message for e in jsonschema.Draft7Validator(SCHEMA).iter_errors(doc)]


def test_owasp_rated_threat_validates():
    rating = rr.rate(L, T, B, rationale={"motive": "Low reward for the attacker."})
    assert _errors(_model({**_BASE, "risk_rating": rating})) == []


def test_legacy_rated_threat_still_validates():
    assert _errors(_model({**_BASE, "impact": "high", "likelihood": "possible"})) == []


def test_unrated_threat_is_rejected():
    assert _errors(_model(dict(_BASE)))


def test_business_basis_requires_business_factors_in_the_schema():
    rating = rr.rate(L, T, B)
    rating["impact"].pop("business")
    assert _errors(_model({**_BASE, "risk_rating": rating}))
