-- Which feed snapshot an assessment used: the stale-result detector.
--
-- Append-only. What each result was computed from, so "results from stale
-- feeds" is a query, not a rebuild.
CREATE TABLE IF NOT EXISTS traust_ops.assessment_input (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    feed_snapshot_id UUID NOT NULL REFERENCES traust_ops.feed_snapshot(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (assessment_id, feed_snapshot_id)
);

-- Results that used a snapshot ("results from stale feeds").
CREATE INDEX IF NOT EXISTS idx_ops_assessment_input_feed_snapshot
    ON traust_ops.assessment_input (feed_snapshot_id);

DROP TRIGGER IF EXISTS ops_assessment_input_reject_mutation ON traust_ops.assessment_input;
CREATE TRIGGER ops_assessment_input_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ops.assessment_input
FOR EACH ROW EXECUTE FUNCTION traust_ops.reject_mutation();

DROP TRIGGER IF EXISTS ops_assessment_input_reject_truncate ON traust_ops.assessment_input;
CREATE TRIGGER ops_assessment_input_reject_truncate
BEFORE TRUNCATE ON traust_ops.assessment_input
FOR EACH STATEMENT EXECUTE FUNCTION traust_ops.reject_mutation();
