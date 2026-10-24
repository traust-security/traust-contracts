-- One scoreboard number as reported: a dashboard's headline metric at a snapshot.
--
-- Append-only, replacing metrics-history.jsonl. Most series re-derive from the
-- append-only facts at any as_of; this keeps what was reported under the
-- methodology of the day, so a methodology change is a new snapshot with a
-- note, never a revision. source: the dashboard (view name); metric: its key
-- (findings_total, sev_critical, ...). run_order_id: the refresh that took it.
CREATE TABLE IF NOT EXISTS ops_metric_snapshot (
    id TEXT NOT NULL DEFAULT (uuid()),
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source <> ''),
    metric TEXT NOT NULL CHECK (metric <> ''),
    value NUMERIC NOT NULL,
    note TEXT CHECK (note <> ''),
    snapshot_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- One value per metric per snapshot; a series reads (source, metric) in time
-- order (trend line, previous snapshot).
CREATE UNIQUE INDEX IF NOT EXISTS uq_ops_metric_snapshot_source_metric_at
    ON ops_metric_snapshot (source, metric, snapshot_at);

CREATE TRIGGER IF NOT EXISTS ops_metric_snapshot_reject_update
BEFORE UPDATE ON ops_metric_snapshot BEGIN
  SELECT RAISE(ABORT, 'ops_metric_snapshot rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ops_metric_snapshot_reject_delete
BEFORE DELETE ON ops_metric_snapshot BEGIN
  SELECT RAISE(ABORT, 'ops_metric_snapshot rows are append-only');
END;
