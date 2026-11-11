-- The CWEs a finding was reported with: the set as reported, no primary
-- selection (that is a view over cwe).
CREATE TABLE IF NOT EXISTS finding_cwe (
    id TEXT NOT NULL DEFAULT (uuid()),
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    cwe_id TEXT NOT NULL REFERENCES cwe(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (finding_id, cwe_id)
);

-- Findings of a CWE (insecure patterns, rule mining,
-- primary-CWE view).
CREATE INDEX IF NOT EXISTS idx_finding_cwe_cwe
    ON finding_cwe (cwe_id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS finding_cwe_touch
AFTER UPDATE ON finding_cwe FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE finding_cwe SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
