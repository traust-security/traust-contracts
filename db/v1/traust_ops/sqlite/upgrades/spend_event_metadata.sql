-- Explicit additive upgrade for spend events missing adoption metadata.
-- Apply only when all five columns are absent. Old events retain null metadata;
-- no canonical identity, raw reference, or line count is inferred.
BEGIN;

ALTER TABLE ops_spend_event
    ADD COLUMN repository_id TEXT REFERENCES repository(id) ON DELETE RESTRICT;
ALTER TABLE ops_spend_event
    ADD COLUMN repository_label TEXT;
ALTER TABLE ops_spend_event
    ADD COLUMN loc INTEGER CHECK (loc IS NULL OR (typeof(loc) = 'integer' AND loc >= 0));
ALTER TABLE ops_spend_event
    ADD COLUMN batch TEXT;
ALTER TABLE ops_spend_event
    ADD COLUMN note TEXT;

CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON ops_spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;

COMMIT;
