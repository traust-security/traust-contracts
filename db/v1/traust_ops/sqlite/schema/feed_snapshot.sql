-- One fetched copy of an external feed (osv, epss, kev, a scanner DB).
--
-- Append-only. The snapshot content is artifact_id (provenance - built,
-- sha256, scanner_version - stays in the artifact); failed fetches are
-- run_order failures, not rows. run_order_id: the refresh that fetched it.
CREATE TABLE IF NOT EXISTS ops_feed_snapshot (
    id TEXT NOT NULL DEFAULT (uuid()),
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    artifact_id TEXT NOT NULL REFERENCES artifact(id) ON DELETE RESTRICT,
    feed TEXT NOT NULL CHECK (feed <> ''),
    retrieved_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- Latest snapshot per feed (feeds staleness, every EPSS / KEV /
-- DB read).
CREATE INDEX IF NOT EXISTS idx_ops_feed_snapshot_feed_retrieved
    ON ops_feed_snapshot (feed, retrieved_at);

CREATE TRIGGER IF NOT EXISTS ops_feed_snapshot_reject_update
BEFORE UPDATE ON ops_feed_snapshot BEGIN
  SELECT RAISE(ABORT, 'ops_feed_snapshot rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ops_feed_snapshot_reject_delete
BEFORE DELETE ON ops_feed_snapshot BEGIN
  SELECT RAISE(ABORT, 'ops_feed_snapshot rows are append-only');
END;
