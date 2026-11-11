-- A published vulnerability: CVE / GHSA / OSV identifiers of one issue, one
-- canonical row plus aliases pointing at it.
--
-- Mutable table. alias_of_id self-references the canonical advisory
-- (null = canonical). Affected-version ranges stay in the artifact, not here.
CREATE TABLE IF NOT EXISTS advisory (
    id TEXT NOT NULL DEFAULT (uuid()),
    alias_of_id TEXT REFERENCES advisory(id) ON DELETE RESTRICT,
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    published_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (identifier)
);

-- Aliases of a vulnerability (exposure dedupe, first discovery).
CREATE INDEX IF NOT EXISTS idx_advisory_alias_of
    ON advisory (alias_of_id)
    WHERE alias_of_id IS NOT NULL;

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS advisory_touch
AFTER UPDATE ON advisory FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE advisory SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
