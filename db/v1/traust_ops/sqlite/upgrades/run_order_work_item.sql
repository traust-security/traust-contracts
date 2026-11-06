-- Explicit additive upgrade for existing databases whose run_order predates
-- work_item_id. Existing orders name no work item; never infer one.
ALTER TABLE ops_run_order
    ADD COLUMN work_item_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON ops_run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;
