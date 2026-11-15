-- A source repository, once, however many products include it.
--
-- Mutable table. One natural key (url, exact string - not canonicalized).
-- upstream_id self-references the repository this one forks: null = no
-- upstream recorded. Not indexed on purpose: rare single-row lookups.
-- public, upstream_id and archived are kept current by forge observation;
-- archived null = not observed yet. Per-observation measurements are an
-- assessment of kind repo-state (artifact: repo-state.schema.json).
-- "public" is quoted: PUBLIC is reserved in PostgreSQL.
--
-- The unreachable disposition (foundry plan repo-unreachable): disposition
-- NULL = active, the only value so far is 'repo_unreachable' - the repository
-- left the planner's universe after two consecutive gone-class observation
-- failures and returns only through a person's verify. reason names the class
-- (gone: the forge's 404/410; empty: answered but no commits; unreachable:
-- the transport's positive word the endpoint is not there), evidence carries
-- the last error, and gone_streak counts the consecutive gone-class failures
-- (reset to 0 by any successful observation; the transient classes never
-- count).
CREATE TABLE IF NOT EXISTS traust.repository (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    upstream_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    url TEXT NOT NULL CHECK (url <> ''),
    "public" BOOLEAN NOT NULL,
    archived BOOLEAN,
    disposition TEXT CHECK (disposition IS NULL OR disposition = 'repo_unreachable'),
    disposition_reason TEXT CHECK (
        disposition_reason IS NULL
        OR disposition_reason IN ('gone', 'empty', 'unreachable')
    ),
    disposition_evidence TEXT,
    disposition_at TIMESTAMPTZ,
    gone_streak INTEGER NOT NULL DEFAULT 0 CHECK (gone_streak >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (url)
);

DROP TRIGGER IF EXISTS repository_touch ON traust.repository;
CREATE TRIGGER repository_touch
BEFORE UPDATE ON traust.repository
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
