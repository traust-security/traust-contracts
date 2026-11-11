-- The traust_ledger namespace: append-only proof of decisions - one Merkle
-- tree and signature per layer, many layers per repository.
--
-- Sibling namespaces: db/v1/traust and db/v1/traust_ops.
-- Bootstraps after the traust namespace: layers and events reference repository,
-- repository_ref and decision there. In SQLite these tables carry the
-- `ledger_` prefix in the same database file.
CREATE SCHEMA IF NOT EXISTS traust_ledger;

-- Shared guard for append-only tables: events. Corrections are new rows,
-- never updates or deletes.
CREATE OR REPLACE FUNCTION traust_ledger.reject_mutation()
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
CREATE OR REPLACE FUNCTION traust_ledger.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END
$$;
