-- Explicit additive upgrade for existing databases missing this column.
-- Existing snapshots are whole-feed copies: their identifier stays null, and
-- none is inferred from the artifact.
ALTER TABLE traust_ops.feed_snapshot
    ADD COLUMN identifier TEXT CHECK (identifier IS NULL OR identifier <> '');

CREATE INDEX IF NOT EXISTS idx_ops_feed_snapshot_feed_identifier_retrieved
    ON traust_ops.feed_snapshot (feed, identifier, retrieved_at);
