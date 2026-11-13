from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "views_schema/v1/attack-coverage.schema.json"


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _technique(technique_id: str, modeled: int, derived: int, score: int) -> dict[str, Any]:
    return {
        "technique_id": technique_id,
        "name": "Example technique",
        "tactics": ["execution"],
        "modeled": modeled,
        "derived": derived,
        "score": score,
    }


@pytest.fixture
def document() -> dict[str, Any]:
    return {
        "as_of": "2026-11-01T00:00:00Z",
        "attack_version": "19.1",
        "mapping_version": "1.0",
        "attribution": "ATT&CK is (c) The MITRE Corporation.",
        "repositories": 2,
        "threat_models": 1,
        "threats_with_techniques": 1,
        "findings_mapped": 3,
        "techniques": [_technique("T1059.001", 1, 2, 2), _technique("T1190", 0, 3, 1)],
        "dropped": {"T9999": 1},
        "navigator_layer": {
            "name": "Traust ATT&CK coverage (2026-11-01)",
            "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Deterministic fleet coverage.",
            "techniques": [
                {"techniqueID": "T1059.001", "score": 2, "comment": "modeled 1; derived 2"},
                {"techniqueID": "T1190", "score": 1, "comment": "derived 3"},
            ],
            "gradient": {"colors": ["#8ec843"], "minValue": 1, "maxValue": 3},
            "legend": [],
            "metadata": [],
        },
    }


def test_example_view_is_valid(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    validator.validate(document)


def test_a_scope_with_no_evidence_is_valid(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document.update(
        threat_models=0, threats_with_techniques=0, findings_mapped=0, techniques=[], dropped={}
    )
    document["navigator_layer"]["techniques"] = []
    validator.validate(document)


@pytest.mark.parametrize("field", list(json.loads(SCHEMA.read_text())["required"]))
def test_every_view_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field", ["technique_id", "name", "tactics", "modeled", "derived", "score"]
)
def test_every_technique_field_is_required(
    validator: Draft202012Validator, document: dict[str, Any], field: str
) -> None:
    del document["techniques"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("target", ["view", "technique"])
def test_unknown_fields_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], target: str
) -> None:
    (document if target == "view" else document["techniques"][0])["unexpected"] = 1
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_the_navigator_layer_keeps_mitres_own_fields(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["navigator_layer"]["filters"] = {"platforms": ["Linux"]}
    validator.validate(document)


@pytest.mark.parametrize(
    "path",
    [
        ("repositories",),
        ("threat_models",),
        ("threats_with_techniques",),
        ("findings_mapped",),
        ("techniques", 0, "modeled"),
        ("techniques", 1, "derived"),
    ],
)
@pytest.mark.parametrize("invalid", [-1, 1.5, "1", None])
def test_counts_are_nonnegative_integers(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("technique_id", ["T1059", "T1059.001"])
def test_technique_and_sub_technique_ids_are_accepted(
    validator: Draft202012Validator, document: dict[str, Any], technique_id: str
) -> None:
    document["techniques"][0]["technique_id"] = technique_id
    validator.validate(document)


@pytest.mark.parametrize("technique_id", ["T105", "T1059.1", "t1059", "TA0002", "T1059\n", ""])
def test_malformed_technique_ids_are_rejected(
    validator: Draft202012Validator, document: dict[str, Any], technique_id: str
) -> None:
    document["techniques"][0]["technique_id"] = technique_id
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_a_technique_has_evidence(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    document["techniques"][1].update(modeled=0, derived=0)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("modeled", "derived", "score", "valid"),
    [
        (1, 0, 2, True),
        (1, 4, 2, True),
        (0, 4, 1, True),
        (1, 0, 1, False),
        (0, 4, 2, False),
        (0, 4, 0, False),
        (0, 4, 4, False),
    ],
)
def test_a_modeled_technique_scores_two_and_a_derived_only_one_scores_one(
    validator: Draft202012Validator,
    document: dict[str, Any],
    modeled: int,
    derived: int,
    score: int,
    valid: bool,
) -> None:
    document["techniques"][0].update(modeled=modeled, derived=derived, score=score)
    assert validator.is_valid(document) is valid


def test_tactics_are_listed_once(validator: Draft202012Validator, document: dict[str, Any]) -> None:
    document["techniques"][0]["tactics"] = ["execution", "execution"]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("dropped", [{"T9999": 0}, {"T9999": -1}, {"T9999": "1"}])
def test_a_dropped_id_is_cited_at_least_once(
    validator: Draft202012Validator, document: dict[str, Any], dropped: dict[str, Any]
) -> None:
    document["dropped"] = dropped
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("navigator_layer", "versions", "layer"), "4.4"),
        (("navigator_layer", "domain"), "mobile-attack"),
        (("navigator_layer", "techniques", 0, "score"), 5),
        (("navigator_layer", "techniques", 0, "techniqueID"), "not-an-id"),
        (("as_of",), "2026-11-01T00:00:00"),
        (("attack_version",), ""),
    ],
)
def test_the_layer_envelope_and_view_strings_are_checked(
    validator: Draft202012Validator, document: dict[str, Any], path: tuple[Any, ...], invalid: Any
) -> None:
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_the_layer_requires_its_envelope(
    validator: Draft202012Validator, document: dict[str, Any]
) -> None:
    for field in ["name", "versions", "domain", "techniques"]:
        broken = copy.deepcopy(document)
        del broken["navigator_layer"][field]
        with pytest.raises(ValidationError):
            validator.validate(broken)
