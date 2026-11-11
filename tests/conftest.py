"""Shared test fixtures."""

import os
import sqlite3
import uuid as uuid_lib
import warnings
from typing import Never

import pytest

POSTGRES_DSN = os.environ.get(
    "TRAUST_TEST_DATABASE_URL", "postgresql://traust:traust-test-only@127.0.0.1:5432/traust_test"
)
POSTGRES_SETUP = (
    "Run:\n  podman run --name traust-postgres --rm -d "
    "-e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only "
    "-e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 "
    "-v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16"
)


def bootstrap_namespaces_sqlite(*modules) -> sqlite3.Connection:
    """One SQLite database file carrying every namespace, in load order.

    SQLite checks FK parent existence on DML, so a database with assessment
    rows needs the ops tables too - one file holds all namespaces by design.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    # The id DEFAULTs call uuid(): provided by SQLite's ext/misc/uuid.c in
    # production, by the driver here.
    conn.create_function("uuid", 0, lambda: str(uuid_lib.uuid4()))
    for module in modules:
        for path in module.bootstrap_files("sqlite"):
            for statement in module.bootstrap_statements("sqlite", path):
                conn.execute(statement)
    return conn


def skip_postgres(reason: str) -> Never:
    warnings.warn(
        f"PostgreSQL E2E skipped: {reason}. {POSTGRES_SETUP}",
        pytest.PytestWarning,
        stacklevel=2,
    )
    pytest.skip(reason)


@pytest.fixture(scope="session")
def postgres_dsn() -> str:
    try:
        import psycopg
    except ImportError:
        skip_postgres("psycopg is not installed")
    try:
        with psycopg.connect(POSTGRES_DSN, connect_timeout=2):
            pass
    except psycopg.OperationalError:
        skip_postgres("local database is unavailable")
    return POSTGRES_DSN
