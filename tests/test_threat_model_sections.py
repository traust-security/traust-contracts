"""The threat-model schema defines every section it declares.

Sections 2, 3, 5, 9 and the update history were `{"type": "object"}` until
0.47.0, so a misspelt field, a missing column or an off-list sensitivity
passed validation and was only caught, if at all, by the Markdown linter.
"""

import copy
import json

import jsonschema
import pytest

from traust_contracts.paths import schema_path


def _validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(schema_path("threat-model").read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


MODEL = {
    "system": "example",
    "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": "repo @ abc1234"},
    "system_context": "Decodes user-supplied audio.",
    "assets": [
        {"asset": "host process", "description": "decoder memory", "sensitivity": "critical"},
        {
            "asset": "user PII",
            "description": "uploader records",
            "sensitivity": "high",
            "regulatory_scope": "GDPR",
            "example_records": "name, email",
        },
    ],
    "entry_points": [
        {
            "entry_point": "upload",
            "description": "WAV decode path",
            "trust_boundary": "untrusted file -> process memory",
            "reachable_assets": "host process",
        }
    ],
    "threats": [
        {
            "id": "T1",
            "threat": "RCE via audio parsing",
            "actor": ["remote_unauth"],
            "impact": "critical",
            "likelihood": "likely",
            "status": "unmitigated",
        }
    ],
    "deprioritized": [{"threat": "physical access", "reason": "out of scope"}],
    "attack_scenarios": [
        {"id": "T1", "threat": "RCE via audio parsing", "steps": ["An attacker uploads a file."]}
    ],
    "update_history": [{"date": "2026-10-01", "changes": "added T1", "reason": "bootstrap"}],
}


def _errors(document: dict) -> list[str]:
    return [e.message for e in _validator().iter_errors(document)]


def test_a_complete_model_validates() -> None:
    assert _errors(MODEL) == []


@pytest.mark.parametrize(
    ("section", "mutate"),
    [
        ("assets", lambda d: d["assets"][0].update(sensitivty="high")),
        ("assets", lambda d: d["assets"][0].update(sensitivity="secret")),
        ("assets", lambda d: d["assets"][0].pop("description")),
        ("entry_points", lambda d: d["entry_points"][0].pop("trust_boundary")),
        ("deprioritized", lambda d: d["deprioritized"][0].update(reason="")),
        ("attack_scenarios", lambda d: d["attack_scenarios"][0].update(steps=[])),
        ("attack_scenarios", lambda d: d["attack_scenarios"][0].update(id="scenario-1")),
        ("update_history", lambda d: d["update_history"][0].update(date="1 Oct 2026")),
        ("update_history", lambda d: d["update_history"][0].pop("reason")),
    ],
)
def test_each_section_rejects_what_its_contract_forbids(section: str, mutate) -> None:
    document = copy.deepcopy(MODEL)
    mutate(document)
    assert _errors(document), f"{section}: an off-contract entry must not validate"


def test_sections_stay_optional() -> None:
    """The tightening is about shape, not presence: a model may omit them."""
    minimal = {k: MODEL[k] for k in ("system", "provenance", "threats")}
    assert _errors(minimal) == []


def test_an_entry_point_may_name_its_kind() -> None:
    model = copy.deepcopy(MODEL)
    model["entry_points"][0]["kind"] = "file-input"
    _validator().validate(model)
    model["entry_points"][0]["kind"] = "rest"
    with pytest.raises(jsonschema.ValidationError):
        _validator().validate(model)
