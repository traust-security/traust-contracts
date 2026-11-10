-- The upgrade channel's stamp table, created by the runner on first open -
-- never by bootstrap. Each row is one authored upgrade script this database
-- has run, verified by the sha256 of the file's bytes (see
-- traust_contracts.v1.migrations). A database without this table predates
-- the runner and is recreated, not migrated.
CREATE TABLE IF NOT EXISTS db_upgrade (
    name TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
