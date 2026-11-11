-- The traust namespace: domain tables - inventory,
-- dependencies, assessments & findings.
--
-- Sibling namespaces own their own directories and schema creation:
-- ops/ (traust_ops) and ledger/ (traust_ledger).
-- Cross-schema foreign keys are the contract between namespaces. The SQLite
-- dialect carries the same namespaces as table prefixes (`ops_`, `ledger_`)
-- bootstrapped into one file, because FKs do not work across ATTACHed files.
CREATE SCHEMA IF NOT EXISTS traust;

-- Shared guard for append-only tables: sbom,
-- dependency, image, and later assessment, artifact, occurrence, location,
-- decision, assessment_input, feed_snapshot, spend_event. Corrections are
-- new rows, never updates or deletes.
CREATE OR REPLACE FUNCTION traust.reject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%.% rows are append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = '55000';
END
$$;

-- Shared touch for mutable tables: the database owns updated_at.
-- Timestamps use statement_timestamp(), not now(): now() is the transaction's
-- start, so every row a transaction writes would tie on created_at. Per
-- statement matches SQLite's strftime('now') and keeps created_at = updated_at
-- on insert (both defaults read the same statement time).
CREATE OR REPLACE FUNCTION traust.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END
$$;
