-- What was found: one issue per repository. Identity comes from the
-- producer-owned fingerprint recipe; the model stores the recipe id and
-- value, never computes them.
--
-- Mutable table: current status is derived (decision view), never stored.
-- kind classifies (vulnerability | weakness) and advisory_match classifies
-- (confirmed | probable, contracts to add) - both checked at intake. advisory_id is set exactly when advisory_match is.
CREATE TABLE IF NOT EXISTS finding (
    id TEXT NOT NULL DEFAULT (uuid()),
    repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE RESTRICT,
    advisory_id TEXT REFERENCES advisory(id) ON DELETE RESTRICT,
    advisory_match TEXT,
    fingerprint_algo TEXT NOT NULL CHECK (fingerprint_algo <> ''),
    fingerprint TEXT NOT NULL CHECK (fingerprint <> ''),
    kind TEXT CHECK (kind <> ''),
    title TEXT NOT NULL CHECK (title <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (repository_id, fingerprint_algo, fingerprint),
    CHECK ((advisory_id IS NULL) = (advisory_match IS NULL))
);

-- Exact identity reads when the producer's algorithm is not supplied.
CREATE INDEX IF NOT EXISTS idx_finding_repository_fingerprint
    ON finding (repository_id, fingerprint);

-- Findings known as an advisory (exposure, first discovery).
CREATE INDEX IF NOT EXISTS idx_finding_advisory
    ON finding (advisory_id)
    WHERE advisory_id IS NOT NULL;

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS finding_touch
AFTER UPDATE ON finding FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE finding SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
