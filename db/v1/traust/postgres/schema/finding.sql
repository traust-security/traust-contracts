-- What was found: one issue per repository. Identity comes from the
-- producer-owned fingerprint recipe; the model stores the recipe id and
-- value, never computes them.
--
-- Mutable table: current status is derived (decision view), never stored.
-- kind classifies (vulnerability | weakness) and advisory_match classifies
-- (confirmed | probable, contracts to add) - both checked at intake. advisory_id is set exactly when advisory_match is.
CREATE TABLE IF NOT EXISTS traust.finding (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES traust.repository(id) ON DELETE RESTRICT,
    advisory_id UUID REFERENCES traust.advisory(id) ON DELETE RESTRICT,
    advisory_match TEXT,
    fingerprint_algo TEXT NOT NULL CHECK (fingerprint_algo <> ''),
    fingerprint TEXT NOT NULL CHECK (fingerprint <> ''),
    kind TEXT CHECK (kind <> ''),
    title TEXT NOT NULL CHECK (title <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (repository_id, fingerprint_algo, fingerprint),
    CHECK ((advisory_id IS NULL) = (advisory_match IS NULL))
);

-- Exact identity reads when the producer's algorithm is not supplied.
CREATE INDEX IF NOT EXISTS idx_finding_repository_fingerprint
    ON traust.finding (repository_id, fingerprint);

-- Findings known as an advisory (exposure, first discovery).
CREATE INDEX IF NOT EXISTS idx_finding_advisory
    ON traust.finding (advisory_id)
    WHERE advisory_id IS NOT NULL;

DROP TRIGGER IF EXISTS finding_touch ON traust.finding;
CREATE TRIGGER finding_touch
BEFORE UPDATE ON traust.finding
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
