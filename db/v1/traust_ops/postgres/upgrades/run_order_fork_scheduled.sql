-- Explicit additive upgrade for existing databases missing this column.
-- Existing orders carry no scheduling stamp: none is inferred, so their fork
-- facts are checked against the current fork policy, as before.
ALTER TABLE traust_ops.run_order
    ADD COLUMN fork_scheduled_at TIMESTAMPTZ;
