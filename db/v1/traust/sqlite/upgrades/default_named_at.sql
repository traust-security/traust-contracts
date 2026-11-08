-- Explicit additive upgrade for existing databases missing this column.
-- Existing default flags carry no naming time: never invent one from
-- timestamps. A row stays default with an unknown naming time; the first
-- import or observation that names it again sets the column.
ALTER TABLE repository_ref
    ADD COLUMN default_named_at TEXT;

CREATE INDEX IF NOT EXISTS idx_repository_ref_default
    ON repository_ref (repository_id, default_named_at)
    WHERE is_default;
