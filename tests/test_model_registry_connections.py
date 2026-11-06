"""Provider connection blocks in the model registry.

sci#287 (source-code-intelligence) routes the runner pool's model delivery
through a provider's connection block: the wire it speaks, its endpoint, the
harness fronting it and where its credential lives. The Go executor parses
the block leniently, but the engine's config-completeness audit validates the
registry against this schema, so a registry carrying a connection block
failed startup until the block was declared here. The schema mirrors the
executor's validate() exactly: the type vocabulary, the compatible types'
required endpoint, the proprietary types' refusal of one, and a secret
credential's required Secret name and key. The block is routing data only —
never the credentials themselves.
"""

from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest
import yaml

from traust_contracts.config import load_section


def _registry(connection: dict | None) -> dict:
    provider: dict = {
        "data_handling": "test",
        "models": {"m": {"tier": "haiku-class", "batch_eligible": True}},
    }
    if connection is not None:
        provider["connection"] = connection
    return {
        "version": 1,
        "updated": "2026-11-06",
        "tiers": {"haiku-class": {"description": "h"}},
        "providers": {"enmaas": provider},
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


@pytest.mark.parametrize(
    "connection",
    [
        # The dev cluster's shape (providers/enmaas): an OpenAI-compatible
        # gateway fronted by the omp harness, its credential a named Secret.
        {
            "type": "openai-compatible",
            "base_url": "https://api.enmaas.devshift.net",
            "harness": "omp",
            "credential": {
                "source": "secret",
                "name": "sci-enmaas-model",
                "key": "ANTHROPIC_API_KEY",
            },
        },
        {
            "type": "anthropic-compatible",
            "base_url": "https://gw.example",
            "harness": "claude",
            "credential": {"source": "env"},
        },
        # A proprietary endpoint: no base_url, the credential already in the
        # pod's environment.
        {"type": "anthropic", "credential": {"source": "env"}},
        # An empty base_url reads as absent, as the executor's validate() does.
        {"type": "anthropic", "base_url": "", "credential": {"source": "env"}},
        # Known vocabulary the worker has no lane for yet: the shape is valid,
        # the executor refuses at delivery until the worker grows the lane.
        {"type": "gemini", "credential": {"source": "env"}},
        {"type": "openai", "credential": {"source": "env"}},
    ],
    ids=[
        "openai-compatible gateway with a secret credential",
        "anthropic-compatible gateway with the claude harness",
        "proprietary anthropic endpoint",
        "empty base_url reads as absent",
        "gemini vocabulary",
        "openai vocabulary",
    ],
)
def test_a_connection_block_validates(tmp_path, connection):
    reg = _load(tmp_path, connection)
    # The typed section is permissive by design (the schema is the
    # authority); the block survives the load for the section's consumers.
    assert reg.providers["enmaas"].connection == connection


def test_a_provider_without_a_connection_still_loads(tmp_path):
    """Registries predating connections are exactly as valid as before."""
    reg = _load(tmp_path, None)
    assert reg.all_models()["m"].tier == "haiku-class"


@pytest.mark.parametrize(
    "connection",
    [
        # An unknown type or credential source would silently misroute.
        {"type": "vertex-ai", "credential": {"source": "env"}},
        {"type": "anthropic", "credential": {"source": "vault"}},
        # The type names the wire; the credential names where it lives.
        {"credential": {"source": "env"}},
        {"type": "anthropic"},
        # The compatible types exist for endpoint overrides: they need one.
        {"type": "openai-compatible", "credential": {"source": "env"}},
        {"type": "anthropic-compatible", "base_url": "", "credential": {"source": "env"}},
        # A base_url on a proprietary type contradicts the type: the default
        # endpoint serves.
        {"type": "anthropic", "base_url": "https://gw.example", "credential": {"source": "env"}},
        {"type": "gemini", "base_url": "https://gw.example", "credential": {"source": "env"}},
        {"type": "openai", "base_url": "https://gw.example", "credential": {"source": "env"}},
        # A secret credential names nothing verifiable without the Secret's
        # name and the key within it.
        {
            "type": "openai-compatible",
            "base_url": "https://gw.example",
            "credential": {"source": "secret", "name": "sci-enmaas-model"},
        },
        {
            "type": "openai-compatible",
            "base_url": "https://gw.example",
            "credential": {"source": "secret", "key": "ANTHROPIC_API_KEY"},
        },
        {
            "type": "openai-compatible",
            "base_url": "https://gw.example",
            "credential": {"source": "secret"},
        },
        # The block is routing data, never the credentials themselves: an
        # inline credential or any other stray key is refused.
        {"type": "anthropic", "credential": {"source": "env"}, "api_key": "sk-ant-example"},
        {"type": "anthropic", "credential": {"source": "env"}, "endpoint": "https://gw.example"},
    ],
    ids=[
        "unknown connection type",
        "unknown credential source",
        "missing type",
        "missing credential",
        "compatible type without a base_url",
        "compatible type with an empty base_url",
        "base_url on anthropic",
        "base_url on gemini",
        "base_url on openai",
        "secret credential without the key",
        "secret credential without the Secret name",
        "secret credential without both",
        "inline credential",
        "unknown connection property",
    ],
)
def test_unroutable_connections_are_rejected(tmp_path, connection):
    with pytest.raises(jsonschema.ValidationError):
        _load(tmp_path, connection)
