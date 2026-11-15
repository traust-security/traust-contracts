-- One fetched copy of one feed document, keyed by the identifier it was
-- fetched by: a CVE's nvd record, a Red Hat advisory. feed_snapshot holds
-- whole-feed copies (osv, epss, kev, a scanner DB); this holds documents.
--
-- Append-only: each fetch is a new row, so the latest row per (feed,
-- identifier) is what the feed said most recently and older rows record what
-- it said before. The document is artifact_id (its provenance stays in the
-- artifact); facts such as CVSS scores are derived from it when read, never
-- stored beside it. Failed fetches are run_order failures, not rows.
-- run_order_id: the refresh that fetched it.
CREATE TABLE IF NOT EXISTS ops_feed_document (
    id TEXT NOT NULL DEFAULT (uuid()),
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    artifact_id TEXT NOT NULL REFERENCES artifact(id) ON DELETE RESTRICT,
    feed TEXT NOT NULL CHECK (feed <> ''),
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    retrieved_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- The latest document per identifier: retrieved_at first, then the order
-- rows were written, then id, so two fetches stamped alike still read in one
-- deterministic order.
CREATE INDEX IF NOT EXISTS idx_ops_feed_document_latest
    ON ops_feed_document (feed, identifier, retrieved_at DESC, created_at DESC, id DESC);

CREATE TRIGGER IF NOT EXISTS ops_feed_document_reject_update
BEFORE UPDATE ON ops_feed_document BEGIN
  SELECT RAISE(ABORT, 'ops_feed_document rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ops_feed_document_reject_delete
BEFORE DELETE ON ops_feed_document BEGIN
  SELECT RAISE(ABORT, 'ops_feed_document rows are append-only');
END;
