-- Explicit additive upgrade for existing databases missing this column.
-- Existing artifacts name no recording order: none is inferred.
-- Needs run_order.work_item_id (contracts#117): this fails, changing
-- nothing, on a database that predates it.
SELECT work_item_id FROM traust_ops.run_order LIMIT 0;

-- The guards come before the column, so an upgrade interrupted part-way never
-- leaves the column unguarded (callers retry while the column is absent).
-- An artifact names the order whose run recorded it only for an assessment
-- that order owns: the work item it runs, or an assessment it produced. An
-- imported artifact (no assessment) names none. Artifacts never change, so
-- the insert is checked; the order's row is locked so a concurrent change of
-- its work item waits.
CREATE OR REPLACE FUNCTION traust_ops.artifact_order_owns_its_assessment()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.run_order_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.assessment_id IS NOT NULL AND (EXISTS (
        SELECT 1 FROM traust_ops.run_order o
        WHERE o.id = NEW.run_order_id AND o.work_item_id = NEW.assessment_id
        FOR SHARE
    ) OR EXISTS (
        SELECT 1 FROM traust.assessment a
        WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id
    )) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'artifact.run_order_id % owns neither its work item nor assessment %',
        NEW.run_order_id, NEW.assessment_id USING ERRCODE = 'check_violation';
END $$;

DROP TRIGGER IF EXISTS artifact_order_owns_its_assessment ON traust.artifact;
CREATE TRIGGER artifact_order_owns_its_assessment
BEFORE INSERT ON traust.artifact
FOR EACH ROW EXECUTE FUNCTION traust_ops.artifact_order_owns_its_assessment();

-- ...and an order an artifact credits keeps the work item it ran.
CREATE OR REPLACE FUNCTION traust_ops.credited_order_keeps_its_work_item()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.work_item_id IS DISTINCT FROM OLD.work_item_id AND EXISTS (
        SELECT 1 FROM traust.artifact r
        WHERE r.run_order_id = OLD.id AND r.assessment_id = OLD.work_item_id
    ) THEN
        RAISE EXCEPTION 'run_order % is credited with a report on work item %',
            OLD.id, OLD.work_item_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS credited_order_keeps_its_work_item ON traust_ops.run_order;
CREATE TRIGGER credited_order_keeps_its_work_item
BEFORE UPDATE OF work_item_id ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.credited_order_keeps_its_work_item();

ALTER TABLE traust.artifact
    ADD COLUMN run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON traust.artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;
