-- Explicit additive upgrade for existing databases missing this column.
-- Existing artifacts name no recording order: none is inferred.
ALTER TABLE traust.artifact
    ADD COLUMN run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON traust.artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;

CREATE OR REPLACE FUNCTION traust_ops.artifact_order_owns_its_assessment()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.run_order_id IS NULL OR EXISTS (
        SELECT 1 FROM traust_ops.run_order o
        WHERE o.id = NEW.run_order_id AND o.work_item_id IS NOT DISTINCT FROM NEW.assessment_id
    ) OR EXISTS (
        SELECT 1 FROM traust.assessment a
        WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id
    ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'artifact.run_order_id % owns neither its work item nor assessment %',
        NEW.run_order_id, NEW.assessment_id USING ERRCODE = 'check_violation';
END $$;

DROP TRIGGER IF EXISTS artifact_order_owns_its_assessment ON traust.artifact;
CREATE TRIGGER artifact_order_owns_its_assessment
BEFORE INSERT ON traust.artifact
FOR EACH ROW EXECUTE FUNCTION traust_ops.artifact_order_owns_its_assessment();
