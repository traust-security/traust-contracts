-- One scoreboard number as reported: a dashboard's headline metric at a snapshot.
--
-- Append-only, replacing metrics-history.jsonl. Most series re-derive from the
-- append-only facts at any as_of; this keeps what was reported under the
-- methodology of the day, so a methodology change is a new snapshot with a
-- note, never a revision. source: the dashboard (view name); metric: its key
-- (findings_total, sev_critical, ...). run_order_id: the refresh that took it.
CREATE TABLE IF NOT EXISTS traust_ops.metric_snapshot (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source <> ''),
    metric TEXT NOT NULL CHECK (metric <> ''),
    value NUMERIC NOT NULL,
    note TEXT CHECK (note <> ''),
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- One value per metric per snapshot; a series reads (source, metric) in time
-- order (trend line, previous snapshot).
CREATE UNIQUE INDEX IF NOT EXISTS uq_ops_metric_snapshot_source_metric_at
    ON traust_ops.metric_snapshot (source, metric, snapshot_at);

DROP TRIGGER IF EXISTS ops_metric_snapshot_reject_mutation ON traust_ops.metric_snapshot;
CREATE TRIGGER ops_metric_snapshot_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ops.metric_snapshot
FOR EACH ROW EXECUTE FUNCTION traust_ops.reject_mutation();

DROP TRIGGER IF EXISTS ops_metric_snapshot_reject_truncate ON traust_ops.metric_snapshot;
CREATE TRIGGER ops_metric_snapshot_reject_truncate
BEFORE TRUNCATE ON traust_ops.metric_snapshot
FOR EACH STATEMENT EXECUTE FUNCTION traust_ops.reject_mutation();
