-- One fetched copy of an external feed (osv, epss, kev, a scanner DB).
--
-- Append-only. The snapshot content is artifact_id (provenance - built,
-- sha256, scanner_version - stays in the artifact); failed fetches are
-- run_order failures, not rows. run_order_id: the refresh that fetched it.
CREATE TABLE IF NOT EXISTS traust_ops.feed_snapshot (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT,
    artifact_id UUID NOT NULL REFERENCES traust.artifact(id) ON DELETE RESTRICT,
    feed TEXT NOT NULL CHECK (feed <> ''),
    retrieved_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- Latest snapshot per feed (feeds staleness, every EPSS / KEV /
-- DB read).
CREATE INDEX IF NOT EXISTS idx_ops_feed_snapshot_feed_retrieved
    ON traust_ops.feed_snapshot (feed, retrieved_at);

DROP TRIGGER IF EXISTS ops_feed_snapshot_reject_mutation ON traust_ops.feed_snapshot;
CREATE TRIGGER ops_feed_snapshot_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ops.feed_snapshot
FOR EACH ROW EXECUTE FUNCTION traust_ops.reject_mutation();

DROP TRIGGER IF EXISTS ops_feed_snapshot_reject_truncate ON traust_ops.feed_snapshot;
CREATE TRIGGER ops_feed_snapshot_reject_truncate
BEFORE TRUNCATE ON traust_ops.feed_snapshot
FOR EACH STATEMENT EXECUTE FUNCTION traust_ops.reject_mutation();
