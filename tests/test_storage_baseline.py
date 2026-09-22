import json
import sqlite3

import pytest

from traust_contracts.v1.storage import IngestError, Store
from traust_contracts.v1.storage.sql import BASELINE_ID, CONTRACT_VERSION, REVISION, load_metadata


@pytest.mark.parametrize(
    "metadata",
    [
        [],
        {},
        {"CONTRACT_VERSION": "v1", "revision": 1, "baseline_id": "test"},
        {"contract_version": "v1", "revision": True, "baseline_id": "test"},
        {"contract_version": "v1", "revision": 0, "baseline_id": "test"},
        {"contract_version": "v1", "revision": 1, "baseline_id": ""},
        {"contract_version": "v2", "revision": 1, "baseline_id": "test"},
    ],
)
def test_invalid_canonical_metadata(tmp_path, monkeypatch, metadata) -> None:
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))
    monkeypatch.setattr("traust_contracts.v1.storage.sql.storage_dir", lambda: tmp_path)
    with pytest.raises(ValueError):
        load_metadata()


def test_duplicate_metadata_keys(tmp_path, monkeypatch) -> None:
    (tmp_path / "metadata.json").write_text(
        '{"contract_version":"v1","revision":1,"revision":null,"baseline_id":"test"}'
    )
    monkeypatch.setattr("traust_contracts.v1.storage.sql.storage_dir", lambda: tmp_path)
    with pytest.raises(ValueError, match="duplicate"):
        load_metadata()


@pytest.mark.parametrize(
    "setup",
    [
        "CREATE TABLE report (marker TEXT)",
        "CREATE VIEW current_binding AS SELECT 1",
        "CREATE VIEW CURRENT_BINDING AS SELECT 1",
        "CREATE TEMP TABLE REPORT (marker TEXT)",
        "CREATE TEMP TABLE report (marker TEXT)",
        "CREATE TABLE traust_storage_meta "
        "(id INTEGER, contract_version TEXT, revision INTEGER, applied_at TEXT)",
    ],
)
def test_unstamped_or_legacy_storage_rejected(setup: str) -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute(setup)
        before = connection.iterdump()
        snapshot = list(before)
        with pytest.raises(IngestError):
            Store(connection).init()
        assert list(connection.iterdump()) == snapshot


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE traust_storage_meta SET baseline_id = 'old-baseline'",
        "UPDATE traust_storage_meta SET revision = 15",
        "UPDATE traust_storage_meta SET revision = 16",
        "UPDATE traust_storage_meta SET revision = 2",
        "UPDATE traust_storage_meta SET contract_version = 'v0'",
        "DELETE FROM traust_storage_meta",
        "DROP TABLE traust_storage_meta",
    ],
)
def test_changed_baseline_rejected_without_repair(mutation: str) -> None:
    with sqlite3.connect(":memory:") as connection:
        store = Store(connection)
        store.init()
        connection.execute(mutation)
        connection.commit()
        before = list(connection.iterdump())
        with pytest.raises(IngestError):
            store.init()
        assert list(connection.iterdump()) == before


def test_fresh_baseline_and_unrelated_tables() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE sci_inventory (id TEXT)")
        store = Store(connection)
        store.init()
        row = connection.execute("SELECT * FROM traust_storage_meta").fetchone()
        assert row[:4] == (1, CONTRACT_VERSION, 1, BASELINE_ID)
        assert REVISION == 1
        store.init()
        assert connection.execute("SELECT * FROM traust_storage_meta").fetchone() == row
        assert connection.execute("SELECT count(*) FROM sci_inventory").fetchone() == (0,)
