-- The upgrade channel's stamp table, created by the runner on first open -
-- never by bootstrap. Each row is one authored upgrade script this database
-- has run, verified by the sha256 of the file's bytes (see
-- traust_contracts.v1.migrations). A database without this table predates
-- the runner and is recreated, not migrated.
CREATE SCHEMA IF NOT EXISTS traust;
CREATE TABLE IF NOT EXISTS traust.db_upgrade (
    name TEXT PRIMARY KEY,
    sha256 CHAR(64) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
