-- CWE identifiers findings report. A row is recorded at intake for each
-- well-formed identifier (CWE-306), as the report schemas checked.
--
-- Mutable table. abstraction, mapping_usage and catalog_version are optional
-- MITRE catalog enrichment (closed catalog values when loaded; no loader yet):
-- they refine the finding_primary_cwe ranking and stay null until then.
CREATE TABLE IF NOT EXISTS cwe (
    id TEXT NOT NULL DEFAULT (uuid()),
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    abstraction TEXT,
    mapping_usage TEXT,
    catalog_version TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (identifier)
);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS cwe_touch
AFTER UPDATE ON cwe FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE cwe SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
