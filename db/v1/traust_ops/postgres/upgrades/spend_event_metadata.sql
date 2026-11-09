-- Explicit additive upgrade for spend events missing adoption metadata.
-- Apply only when all five columns are absent, in a caller-owned transaction.
-- Old events retain null metadata; no identity, reference, or count is inferred.
ALTER TABLE traust_ops.spend_event
    ADD COLUMN repository_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    ADD COLUMN repository_label TEXT,
    ADD COLUMN loc BIGINT CHECK (loc >= 0),
    ADD COLUMN batch TEXT,
    ADD COLUMN note TEXT;

CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON traust_ops.spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;
