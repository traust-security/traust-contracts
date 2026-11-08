-- Explicit additive upgrade for existing databases missing this column.
-- Existing artifacts name no recording order: none is inferred.
ALTER TABLE artifact
    ADD COLUMN run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS ops_artifact_order_owns_its_assessment
BEFORE INSERT ON artifact
WHEN NEW.run_order_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM ops_run_order o
    WHERE o.id = NEW.run_order_id AND o.work_item_id IS NEW.assessment_id)
  AND NOT EXISTS (
    SELECT 1 FROM assessment a
    WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id)
BEGIN
  SELECT RAISE(ABORT, 'artifact.run_order_id owns neither its work item nor its assessment');
END;
