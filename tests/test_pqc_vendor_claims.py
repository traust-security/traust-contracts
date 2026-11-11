"""PQC vendor claims: a curated scope-ref document, published as successor versions.

Shape derived from build_pqc_vendor_tracker.py's vendor-registry.json input; the
tracker's fleet counts are derived by the reader and never stored.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_contracts import build_registry

SCHEMA = Path(__file__).parents[1] / "artifacts_schema/v1/pqc-vendor-claims.schema.json"

CLAIMS: dict[str, Any] = {
    "artifact": "pqc-vendor-claims",
    "version": 2,
    "updated": "2026-10-01",
    "note": "Quarterly review.",
    "vendors": [
        {
            "id": "example-tls",
            "name": "Example TLS provider",
            "class": "provider",
            "packages": [
                {"name": "example-tls", "ecosystem": "rpm"},
                {"name": "example-tls-sys", "ecosystem": "cargo"},
                {"name": "example-tls-bindings"},
            ],
            "status": "available",
            "claim": "3.x ships ML-KEM and ML-DSA; hybrid key exchange is the default.",
            "watch": "FIPS provider adoption across the fleet",
            "sources": [
                {
                    "url": "https://example.test/release-notes/3.5",
                    "title": "Release notes",
                    "retrieved": "2026-09-30",
                }
            ],
            "last_reviewed": "2026-09-30",
            "reviewer": "crypto-review team",
        },
        {
            "id": "example-sso",
            "name": "Example SSO service",
            "class": "service",
            "packages": [],
            "status": "none",
            "claim": "No public post-quantum roadmap.",
            "sources": [{"url": "https://example.test/roadmap", "retrieved": "2026-09-30"}],
            "last_reviewed": "2026-09-30",
            "reviewer": "crypto-review team",
        },
    ],
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=build_registry(), format_checker=FormatChecker())


def test_dated_sourced_claims_validate(validator: Draft202012Validator) -> None:
    validator.validate(CLAIMS)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("artifact",), "pqc-vendor-registry"),
        (("version",), 0),
        (("updated",), "last week"),
        (("vendors",), []),
        (("vendors", 0, "id"), "Example TLS"),
        (("vendors", 0, "class"), "toolchain"),
        (("vendors", 0, "status"), "in-progress"),
        (("vendors", 0, "packages", 0, "ecosystem"), "crates"),
        (("vendors", 0, "sources"), []),
        (("vendors", 0, "sources", 0, "retrieved"), "2026/09/30"),
        (("vendors", 0, "last_reviewed"), "Q3"),
        (("vendors", 0, "reviewer"), ""),
        (("vendors", 0, "fleet_repos_via_graph"), 12),
        (("blocked_external",), ["repo-a"]),
    ],
)
def test_rejects_unknown_malformed_or_derived_fields(
    validator: Draft202012Validator, path: tuple[str | int, ...], value: object
) -> None:
    document = deepcopy(CLAIMS)
    node: Any = document
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "missing",
    ["id", "name", "class", "packages", "status", "claim", "sources", "last_reviewed", "reviewer"],
)
def test_every_claim_is_dated_sourced_and_attributed(
    validator: Draft202012Validator, missing: str
) -> None:
    document = deepcopy(CLAIMS)
    del document["vendors"][0][missing]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("missing", ["artifact", "version", "updated", "vendors"])
def test_requires_successor_version_fields(validator: Draft202012Validator, missing: str) -> None:
    with pytest.raises(ValidationError):
        validator.validate({key: value for key, value in CLAIMS.items() if key != missing})
