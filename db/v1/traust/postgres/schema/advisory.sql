-- A published vulnerability: CVE / GHSA / OSV identifiers of one issue, one
-- canonical row plus aliases pointing at it.
--
-- Mutable table. alias_of_id self-references the canonical advisory
-- (null = canonical). Affected-version ranges stay in the artifact, not here.
CREATE TABLE IF NOT EXISTS traust.advisory (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    alias_of_id UUID REFERENCES traust.advisory(id) ON DELETE RESTRICT,
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (identifier)
);

-- Aliases of a vulnerability (exposure dedupe, first discovery).
CREATE INDEX IF NOT EXISTS idx_advisory_alias_of
    ON traust.advisory (alias_of_id)
    WHERE alias_of_id IS NOT NULL;

DROP TRIGGER IF EXISTS advisory_touch ON traust.advisory;
CREATE TRIGGER advisory_touch
BEFORE UPDATE ON traust.advisory
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
