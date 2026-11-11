-- A source repository, once, however many products include it.
--
-- Mutable table. One natural key (url, exact string - not canonicalized).
-- upstream_id self-references the repository this one forks: null = no
-- upstream recorded. Not indexed on purpose: rare single-row lookups.
-- public, upstream_id and archived are kept current by forge observation;
-- archived null = not observed yet. Per-observation measurements are an
-- assessment of kind repo-state (artifact: repo-state.schema.json).
-- "public" is quoted: PUBLIC is reserved in PostgreSQL.
CREATE TABLE IF NOT EXISTS traust.repository (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    upstream_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    url TEXT NOT NULL CHECK (url <> ''),
    "public" BOOLEAN NOT NULL,
    archived BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (url)
);

DROP TRIGGER IF EXISTS repository_touch ON traust.repository;
CREATE TRIGGER repository_touch
BEFORE UPDATE ON traust.repository
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
