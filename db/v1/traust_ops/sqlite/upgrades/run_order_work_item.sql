-- Explicit additive upgrade for existing databases whose run_order predates
-- work_item_id. Existing orders name no work item; never infer one.
ALTER TABLE ops_run_order
    ADD COLUMN work_item_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT;

-- The mirror an effort runs on (remediate_finding only); see run_order.sql.
ALTER TABLE ops_run_order
    ADD COLUMN fork_url TEXT;
ALTER TABLE ops_run_order
    ADD COLUMN fork_branch TEXT;

CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON ops_run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;

-- An order runs a work item of its own repository: the work item's commit
-- (assessment -> repository_ref) is on the repository the order names.
CREATE TRIGGER IF NOT EXISTS ops_run_order_work_item_of_repository
BEFORE INSERT ON ops_run_order
WHEN NEW.work_item_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM assessment a JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id AND r.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_run_order.work_item_id is not a work item of its repository');
END;

CREATE TRIGGER IF NOT EXISTS ops_run_order_work_item_of_repository_update
BEFORE UPDATE OF work_item_id, repository_id ON ops_run_order
WHEN NEW.work_item_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM assessment a JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id AND r.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_run_order.work_item_id is not a work item of its repository');
END;

-- ...and a commit whose work item an order runs stays on that repository:
-- assessments never change, so only the ref moving could break the pairing.
CREATE TRIGGER IF NOT EXISTS ops_ref_of_ordered_work_item_stays
BEFORE UPDATE OF repository_id ON repository_ref
WHEN EXISTS (
    SELECT 1 FROM ops_run_order o JOIN assessment a ON a.id = o.work_item_id
    WHERE a.repository_ref_id = NEW.id AND o.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'a repository_ref holding an ordered work item keeps its repository');
END;
