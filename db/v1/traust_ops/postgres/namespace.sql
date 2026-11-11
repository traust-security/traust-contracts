-- The traust_ops namespace: traust's own application state -
-- run_batch, run_order, spend_event, feed_snapshot,
-- assessment_input. Written by continuous ops.
--
-- Sibling namespaces: db/v1/traust and db/v1/traust_ledger.
-- (traust_ledger). In SQLite these tables carry the `ops_` prefix
-- in the same database file.
--
-- Bootstrap order: traust first (run_order references repository and
-- artifact), then this namespace, which closes the cycle by adding
-- assessment.run_order_id's FK back to run_order.
CREATE SCHEMA IF NOT EXISTS traust_ops;

-- Shared guard for append-only tables: spend_event, feed_snapshot,
-- assessment_input. Corrections are new rows, never updates or deletes.
CREATE OR REPLACE FUNCTION traust_ops.reject_mutation()
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
CREATE OR REPLACE FUNCTION traust_ops.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END
$$;
