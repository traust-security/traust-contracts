-- Which feed snapshot an assessment used: the stale-result detector.
--
-- Append-only. What each result was computed from, so "results from stale
-- feeds" is a query, not a rebuild.
CREATE TABLE IF NOT EXISTS ops_assessment_input (
    id TEXT NOT NULL DEFAULT (uuid()),
    assessment_id TEXT NOT NULL REFERENCES assessment(id) ON DELETE RESTRICT,
    feed_snapshot_id TEXT NOT NULL REFERENCES ops_feed_snapshot(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (assessment_id, feed_snapshot_id)
);

-- Results that used a snapshot ("results from stale feeds").
CREATE INDEX IF NOT EXISTS idx_ops_assessment_input_feed_snapshot
    ON ops_assessment_input (feed_snapshot_id);

CREATE TRIGGER IF NOT EXISTS ops_assessment_input_reject_update
BEFORE UPDATE ON ops_assessment_input BEGIN
  SELECT RAISE(ABORT, 'ops_assessment_input rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ops_assessment_input_reject_delete
BEFORE DELETE ON ops_assessment_input BEGIN
  SELECT RAISE(ABORT, 'ops_assessment_input rows are append-only');
END;
