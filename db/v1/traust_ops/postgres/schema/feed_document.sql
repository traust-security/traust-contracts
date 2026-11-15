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
CREATE TABLE IF NOT EXISTS traust_ops.feed_document (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT,
    artifact_id UUID NOT NULL REFERENCES traust.artifact(id) ON DELETE RESTRICT,
    feed TEXT NOT NULL CHECK (feed <> ''),
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    retrieved_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- The latest document per identifier: retrieved_at first, then the order
-- rows were written, then id, so two fetches stamped alike still read in one
-- deterministic order.
CREATE INDEX IF NOT EXISTS idx_ops_feed_document_latest
    ON traust_ops.feed_document (feed, identifier, retrieved_at DESC, created_at DESC, id DESC);

DROP TRIGGER IF EXISTS ops_feed_document_reject_mutation ON traust_ops.feed_document;
CREATE TRIGGER ops_feed_document_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ops.feed_document
FOR EACH ROW EXECUTE FUNCTION traust_ops.reject_mutation();

DROP TRIGGER IF EXISTS ops_feed_document_reject_truncate ON traust_ops.feed_document;
CREATE TRIGGER ops_feed_document_reject_truncate
BEFORE TRUNCATE ON traust_ops.feed_document
FOR EACH STATEMENT EXECUTE FUNCTION traust_ops.reject_mutation();
