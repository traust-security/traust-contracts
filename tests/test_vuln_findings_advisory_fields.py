"""vuln-findings findings carry an advisory's cvss and dependency evidence as data,
in the same shapes as a report finding's."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from storage_samples import sample

from traust_contracts.v1.models.scan_result import ScanResult

SCHEMA_DIR = Path(__file__).parent.parent / "artifacts_schema" / "v1"

ADVISORY = {
    "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "dependency": {
        "advisory": "CVE-2024-0001",
        "module": "golang.org/x/net",
        "ecosystem": "go",
        "installed_version": "v0.20.0",
        "classification": "likely_affected",
        "evidence_level": "manifest",
    },
}


def _document() -> dict:
    raw, _ = sample("vuln-findings")
    return json.loads(raw)


def _errors(document: dict) -> list[str]:
    resources = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        resources[doc.get("$id", path.name)] = Resource.from_contents(doc)
    schema = json.loads((SCHEMA_DIR / "vuln-findings.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, registry=Registry().with_resources(resources.items()))
    return [e.message for e in validator.iter_errors(document)]


def test_an_advisory_finding_carries_cvss_and_dependency() -> None:
    document = _document()
    document["findings"][0].update(copy.deepcopy(ADVISORY))
    assert _errors(document) == []
    out = ScanResult.from_dict(document).to_dict()
    assert out["findings"][0]["cvss"] == ADVISORY["cvss"]
    assert out["findings"][0]["dependency"] == ADVISORY["dependency"]


def test_the_fields_reuse_the_report_finding_shapes() -> None:
    document = _document()
    finding = document["findings"][0]
    finding.update(copy.deepcopy(ADVISORY))
    finding["dependency"]["classification"] = "fixed"
    assert _errors(document), "a classification outside impact-classification validated"
    finding["dependency"]["classification"] = "likely_affected"
    finding["cvss"] = {"score": 7.5}
    assert _errors(document), "a cvss block without a vector validated"
    finding["cvss"] = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "band": "high"}
    assert _errors(document), "a cvss block with an unknown key validated"


def test_a_vector_alone_is_a_complete_cvss_block() -> None:
    """traust-core computes the score from the vector at intake (data model: cvss_score is
    computed from cvss_vector), so a producer may send the vector without a score."""
    document = _document()
    finding = document["findings"][0]
    finding.update(copy.deepcopy(ADVISORY))
    finding["cvss"] = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
    assert _errors(document) == []


def test_findings_without_the_fields_stay_valid() -> None:
    assert _errors(_document()) == []


def test_the_cvss_model_matches_the_schema_on_a_missing_or_null_score() -> None:
    """Absent is allowed by both; an explicit null is refused by both."""
    import pytest
    from pydantic import ValidationError

    from traust_contracts.v1.models import CVSS

    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert CVSS.model_validate({"vector": vector}).score is None
    with pytest.raises(ValidationError):
        CVSS.model_validate({"vector": vector, "score": None})
    document = _document()
    finding = document["findings"][0]
    finding.update(copy.deepcopy(ADVISORY))
    finding["cvss"] = {"vector": vector, "score": None}
    assert _errors(document), "a null score validated against the schema"
