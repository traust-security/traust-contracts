"""Provider connection blocks in the model registry.

A provider section may declare how a runner reaches it: the wire it speaks
(``type``), its endpoint (``base_url``), the harness fronting it and where its
credential lives. The block is optional, so existing registries load unchanged.
The schema checks the shape; which types, harnesses and credential sources
exist is the consumer's closed set, like tier names.
"""

from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest
import yaml

from traust_contracts.config import load_section

_CONNECTION = {
    "type": "openai-compatible",
    "base_url": "https://gateway.example.invalid/v1",
    "harness": "omp",
    "credential": {"source": "secret", "name": "sci-enmaas-model", "key": "GATEWAY_API_KEY"},
}


def _registry(connection: dict | None) -> dict:
    provider = {
        "data_handling": "test",
        "models": {"m": {"tier": "haiku-class", "batch_eligible": True}},
    }
    if connection is not None:
        provider["connection"] = connection
    return {
        "version": 1,
        "updated": "2026-11-06",
        "tiers": {"haiku-class": {"description": "h"}},
        "providers": {"gateway": provider},
        "roles": {
            "r": {
                "floor": "haiku-class",
                "approved": ["m"],
                "candidates": [],
                "ledger_validity_writer": False,
            }
        },
    }


def _load(tmp_path: Path, connection: dict | None):
    (tmp_path / "model-registry.yaml").write_text(yaml.safe_dump(_registry(connection)))
    return load_section("model-registry.yaml", config_home=tmp_path)


def test_a_provider_without_a_connection_still_loads(tmp_path):
    assert _load(tmp_path, None).providers["gateway"].models["m"].tier == "haiku-class"


def test_a_connection_block_loads_and_stays_typed(tmp_path):
    reg = _load(tmp_path, _CONNECTION)
    provider = reg.providers["gateway"]
    assert provider.model_extra["connection"] == _CONNECTION


@pytest.mark.parametrize(
    "connection",
    [
        {"credential": {"source": "env"}},  # no type
        {**_CONNECTION, "endpoint": "https://x"},  # unknown key
        {k: v for k, v in _CONNECTION.items() if k != "credential"},  # no credential
        {**_CONNECTION, "credential": {}},  # no source
        {**_CONNECTION, "credential": {"source": "env", "token": "x"}},  # unknown key
        {**_CONNECTION, "base_url": ""},  # empty string
        {**_CONNECTION, "type": ""},  # empty string
    ],
)
def test_malformed_connections_are_rejected(tmp_path, connection: dict):
    with pytest.raises(jsonschema.ValidationError):
        _load(tmp_path, connection)
