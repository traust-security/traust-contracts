-- Explicit additive upgrade for existing databases whose run_order predates
-- work_item_id. Existing orders name no work item; never infer one.
ALTER TABLE traust_ops.run_order
    ADD COLUMN work_item_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON traust_ops.run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;

-- An order runs a work item of its own repository: the work item's commit
-- (assessment -> repository_ref) is on the repository the order names.
CREATE OR REPLACE FUNCTION traust_ops.run_order_work_item_of_repository()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.work_item_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM traust.assessment a
        JOIN traust.repository_ref r ON r.id = a.repository_ref_id
        WHERE a.id = NEW.work_item_id AND r.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'run_order.work_item_id % is not a work item of repository %',
            NEW.work_item_id, NEW.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS run_order_work_item_of_repository ON traust_ops.run_order;
CREATE TRIGGER run_order_work_item_of_repository
BEFORE INSERT OR UPDATE OF work_item_id, repository_id ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.run_order_work_item_of_repository();
