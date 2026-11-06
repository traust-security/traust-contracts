-- Explicit additive upgrade for existing databases whose run_order predates
-- work_item_id. Existing orders name no work item; never infer one.
ALTER TABLE traust_ops.run_order
    ADD COLUMN work_item_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON traust_ops.run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;

-- An order runs a work item of its own repository: the work item's commit
-- (assessment -> repository_ref) is on the repository the order names.
-- FOR SHARE on the ref makes a concurrent move of it wait for this order (and
-- this order wait for a move in flight, then read where it went).
CREATE OR REPLACE FUNCTION traust_ops.run_order_work_item_of_repository()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    owner UUID;
BEGIN
    IF NEW.work_item_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT r.repository_id INTO owner
    FROM traust.assessment a JOIN traust.repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id
    FOR SHARE OF r;
    IF FOUND AND owner IS DISTINCT FROM NEW.repository_id THEN
        RAISE EXCEPTION 'run_order.work_item_id % is not a work item of repository %',
            NEW.work_item_id, NEW.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS run_order_work_item_of_repository ON traust_ops.run_order;
CREATE TRIGGER run_order_work_item_of_repository
BEFORE INSERT OR UPDATE OF work_item_id, repository_id ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.run_order_work_item_of_repository();

-- ...and a commit whose work item an order runs stays on that repository:
-- assessments never change, so only the ref moving could break the pairing.
-- This runs once the ref is locked, on a fresh snapshot, so it sees an order
-- committed while it waited.
CREATE OR REPLACE FUNCTION traust_ops.ref_of_ordered_work_item_stays()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM traust_ops.run_order o
        JOIN traust.assessment a ON a.id = o.work_item_id
        WHERE a.repository_ref_id = NEW.id AND o.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'repository_ref % holds a work item ordered on repository %',
            NEW.id, OLD.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ref_of_ordered_work_item_stays ON traust.repository_ref;
CREATE TRIGGER ref_of_ordered_work_item_stays
BEFORE UPDATE OF repository_id ON traust.repository_ref
FOR EACH ROW EXECUTE FUNCTION traust_ops.ref_of_ordered_work_item_stays();
