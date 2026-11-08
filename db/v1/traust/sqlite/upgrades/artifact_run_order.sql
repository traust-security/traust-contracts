-- Explicit additive upgrade for existing databases missing this column.
-- Existing artifacts name no recording order: none is inferred.
-- Needs ops_run_order.work_item_id (contracts#117): this fails, changing
-- nothing, on a database that predates it.
SELECT work_item_id FROM ops_run_order LIMIT 0;

-- The guards come before the column, so an upgrade interrupted part-way never
-- leaves the column unguarded (callers retry while the column is absent).
-- An artifact names the order whose run recorded it only for an assessment
-- that order owns: the work item it runs, or an assessment it produced. An
-- imported artifact (no assessment) names none. Artifacts never change, so
-- the insert is checked.
CREATE TRIGGER IF NOT EXISTS ops_artifact_order_owns_its_assessment
BEFORE INSERT ON artifact
WHEN NEW.run_order_id IS NOT NULL
  AND (NEW.assessment_id IS NULL OR (
    NOT EXISTS (
      SELECT 1 FROM ops_run_order o
      WHERE o.id = NEW.run_order_id AND o.work_item_id = NEW.assessment_id)
    AND NOT EXISTS (
      SELECT 1 FROM assessment a
      WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id)))
BEGIN
  SELECT RAISE(ABORT, 'artifact.run_order_id owns neither its work item nor its assessment');
END;

-- ...and an order an artifact credits keeps the work item it ran.
CREATE TRIGGER IF NOT EXISTS ops_credited_order_keeps_its_work_item
BEFORE UPDATE OF work_item_id ON ops_run_order
WHEN NEW.work_item_id IS NOT OLD.work_item_id AND EXISTS (
    SELECT 1 FROM artifact r
    WHERE r.run_order_id = OLD.id AND r.assessment_id = OLD.work_item_id)
BEGIN
  SELECT RAISE(ABORT, 'a run_order credited with a report keeps its work item');
END;

ALTER TABLE artifact
    ADD COLUMN run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;
