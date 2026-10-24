"""Scanner observations retain unreported facts without weakening authored reports."""

import json

import pytest
from jsonschema import Draft202012Validator
from storage_samples import sample
from test_classifier_compatibility import _definition_validator, _finding
from test_contracts import _canonical_write_validator


def _observation() -> dict:
    # Secret-free shape emitted by the native Gitleaks adapter for a bundled rule.
    return {
        "id": "gitleaks/traust-openshift-sha256-token",
        "title": "OpenShift OAuth access token (sha256~ bearer token)",
        "severity": "high",
        "cwes": [],
        "locations": [{"path": "settings.py", "lines": "1"}],
        "description": "OpenShift OAuth access token (sha256~ bearer token)",
        "remediation": "",
        "category": "traust-openshift-sha256-token",
    }


def _adapter(finding: dict) -> dict:
    return {
        "target": "example-repository",
        "scanned_at": "2026-10-23T00:00:00Z",
        "metadata": {"tool": "gitleaks", "scanner_version": "8.30.0"},
        "findings": [finding],
    }


@pytest.fixture(params=[False, True], ids=["historical-read", "canonical-write"])
def adapter_validator(request: pytest.FixtureRequest) -> Draft202012Validator:
    return _canonical_write_validator("adapter-result", canonical=request.param)


@pytest.mark.parametrize(
    ("rule", "description"),
    [
        ("traust-openshift-sha256-token", "OpenShift OAuth access token (sha256~ bearer token)"),
        (
            "traust-dsn-url-credentials",
            "Connection-string URL with embedded credentials (DSN user:password@host)",
        ),
        ("traust-ansible-vault-payload", "Ansible Vault ciphertext committed to the repository"),
    ],
)
def test_native_gitleaks_observations_need_no_authored_conclusions(
    adapter_validator: Draft202012Validator, rule: str, description: str
) -> None:
    observation = _observation()
    observation.update(
        id=f"gitleaks/{rule}", title=description, description=description, category=rule
    )
    adapter_validator.validate(_adapter(observation))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "scanner:rule@repository"),
        ("id", "gitleaks/" + "long-native-rule-" * 5),
        ("title", "x"),
        ("cwes", []),
        ("description", ""),
        ("description", "Pattern match"),
        ("remediation", ""),
        ("remediation", "Review"),
    ],
)
def test_adapter_observations_do_not_inherit_report_authoring_minima(
    adapter_validator: Draft202012Validator, field: str, value: object
) -> None:
    observation = {**_finding(), field: value}
    adapter_validator.validate(_adapter(observation))
    assert not _definition_validator("report", "/$defs/finding").is_valid(observation)


def test_report_still_rejects_native_scanner_observations() -> None:
    report = json.loads(sample("report")[0])
    validator = _canonical_write_validator("report")
    validator.validate(report)
    report["findings"] = [_observation()]
    assert not validator.is_valid(report)


@pytest.mark.parametrize("cwes", [["CWE-798"], ["CWE-693", "CWE-200"], ["CWE-12345"]])
def test_supplied_cwes_remain_validated(
    adapter_validator: Draft202012Validator, cwes: list[str]
) -> None:
    adapter_validator.validate(_adapter({**_observation(), "cwes": cwes}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", ""),
        ("id", None),
        ("id", 1),
        ("title", ""),
        ("title", None),
        ("title", 1),
        ("cwes", None),
        ("cwes", "CWE-798"),
        ("cwes", ["798"]),
        ("cwes", ["cwe-798"]),
        ("cwes", ["CWE-"]),
        ("cwes", ["CWE-123456"]),
        ("cwes", ["CWE-798", "unknown"]),
        ("cwes", [None]),
        ("cwes", [798]),
        ("description", None),
        ("description", 1),
        ("remediation", None),
        ("remediation", 1),
        ("remediation", []),
        ("remediation", {}),
        ("severity", "HIGH"),
        ("severity", "unknown"),
        ("severity", None),
        ("locations", []),
        ("locations", [{"path": ""}]),
        ("locations", [{"path": "settings.py", "lines": 1}]),
        ("locations", [{"path": "settings.py", "unknown": True}]),
        ("fingerprint", ""),
        ("fingerprint", "a" * 63),
        ("fingerprint", "A" * 64),
        ("fingerprint_algo", "sha256"),
        ("origin", "gitleaks"),
        ("kind", "candidate"),
        ("validation_status", "true-positive"),
        ("pqc_classification", "unknown"),
        ("effective_severity", "unknown"),
        ("blocked_external", "true"),
        ("blocked_external", None),
        ("peach_references", []),
        ("peach_references", ["PEACH-X"]),
        ("isolation_dimensions", []),
        ("isolation_dimensions", ["privilege", "privilege"]),
        ("isolation_dimensions", ["unknown"]),
        ("cvss", {"score": 11, "vector": "CVSS:3.1"}),
        ("capec", ["CAPEC-X"]),
        ("evidence", [{"code": "sanitized", "unknown": True}]),
        ("passes", [0]),
        ("unknown", "scanner-specific extension"),
    ],
)
def test_adapter_rejects_malformed_supplied_values(
    adapter_validator: Draft202012Validator, field: str, value: object
) -> None:
    assert not adapter_validator.is_valid(_adapter({**_observation(), field: value}))


@pytest.mark.parametrize(
    "field", ["id", "title", "severity", "cwes", "locations", "description", "remediation"]
)
def test_observation_fields_remain_required(
    adapter_validator: Draft202012Validator, field: str
) -> None:
    observation = _observation()
    del observation[field]
    assert not adapter_validator.is_valid(_adapter(observation))


@pytest.mark.parametrize(
    "dependency",
    [
        None,
        {},
        {"advisory": "CVE-2026-1234"},
        {"module": "example-module"},
        {"advisory": 1234, "module": "example-module"},
        {"advisory": "CVE-2026-1234", "module": None},
        {"advisory": "CVE-2026-1234", "module": "x", "ecosystem": "unknown"},
        {"advisory": "CVE-2026-1234", "module": "x", "evidence_level": "confirmed"},
        {"advisory": "CVE-2026-1234", "module": "x", "classification": "confirmed"},
        {"advisory": "CVE-2026-1234", "module": "x", "classification": None},
        {"advisory": "CVE-2026-1234", "module": "x", "unknown": True},
    ],
)
def test_adapter_rejects_malformed_dependency_provenance(
    adapter_validator: Draft202012Validator, dependency: object
) -> None:
    assert not adapter_validator.is_valid(_adapter({**_observation(), "dependency": dependency}))


def test_fully_authored_adapter_records_remain_valid(
    adapter_validator: Draft202012Validator,
) -> None:
    finding = {
        **_finding(),
        "asvs_references": ["V1.1.1"],
        "peach_references": ["PEACH-P"],
        "cvss": {"score": 3.1, "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"},
        "capec": ["CAPEC-1"],
        "evidence": [{"code": "sanitized example", "language": "text", "caption": "Observed"}],
        "attack_pattern": "A caller crosses the documented security boundary.",
        "category": "authorization",
        "kind": "weakness",
        "validation_status": "true_positive",
        "source_findings": ["EXAMPLE-abcdef0-001"],
        "origin": "impact-analysis",
        "pqc_classification": "classically-broken",
        "remediation_effort": "s",
        "blocked_external": True,
        "isolation_dimensions": ["privilege"],
        "isolation_boundary": "IF-1",
        "disposition": {
            "validity": "true_positive",
            "resolution": "open",
            "last_updated": "2026-10-23T00:00:00Z",
            "events": [],
            "assurance": "claimed",
        },
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v3",
        "effective_severity": "low",
        "passes": [1, 2],
        "dependency": {
            "advisory": "CVE-2026-1234",
            "module": "example-module",
            "ecosystem": "go",
            "purl": "pkg:golang/example-module@0.1.0",
            "vulnerable_range": "<0.2.0",
            "fixed_version": "0.2.0",
            "installed_version": "0.1.0",
            "evidence_level": "symbol-usage",
            "classification": "likely_affected",
            "impact_artifact": "impact-analysis.json",
        },
    }
    _definition_validator("report", "/$defs/finding").validate(finding)
    adapter_validator.validate(_adapter(finding))


@pytest.mark.parametrize("effort", ["xs", "s", "m", "l", "xl", None])
@pytest.mark.parametrize("blocked", [False, True])
def test_canonical_effort_and_blocking_are_independent_of_unreported_remediation(
    adapter_validator: Draft202012Validator, effort: str | None, blocked: bool
) -> None:
    adapter_validator.validate(
        _adapter({**_observation(), "remediation_effort": effort, "blocked_external": blocked})
    )


@pytest.mark.parametrize("effort", ["trivial", "moderate", "significant", "blocked-external"])
def test_historical_effort_is_readable_but_not_a_canonical_write(effort: str) -> None:
    document = _adapter({**_observation(), "remediation_effort": effort})
    _canonical_write_validator("adapter-result").validate(document)
    assert not _canonical_write_validator("adapter-result", canonical=True).is_valid(document)


@pytest.mark.parametrize("effort", ["", "XXL", "unknown", 0, [], {}])
def test_invalid_effort_is_not_accepted_as_unreported(
    adapter_validator: Draft202012Validator, effort: object
) -> None:
    assert not adapter_validator.is_valid(
        _adapter({**_observation(), "remediation_effort": effort})
    )


@pytest.mark.parametrize("section", ["document", "metadata", "summary"])
def test_adapter_envelope_stays_closed(
    adapter_validator: Draft202012Validator, section: str
) -> None:
    document = _adapter(_observation())
    if section == "summary":
        document["summary"] = {"total": 1}
    target = document if section == "document" else document[section]
    target["unknown"] = True
    assert not adapter_validator.is_valid(document)
