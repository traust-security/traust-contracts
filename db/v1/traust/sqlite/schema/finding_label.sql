-- A label on a finding, from a taxonomy: public catalogs (attack, asvs,
-- cis, slsa, ...) or adopter taxonomies as extensions.
--
-- taxonomy and label are closed per taxonomy (contracts
-- enums/v1/label-taxonomy.json, to add) - checked at intake, not a database
-- constraint. Multi-valued by design: rows, never columns.
CREATE TABLE IF NOT EXISTS finding_label (
    id TEXT NOT NULL DEFAULT (uuid()),
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    taxonomy TEXT NOT NULL CHECK (taxonomy <> ''),
    label TEXT NOT NULL CHECK (label <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (finding_id, taxonomy, label)
);

-- Findings with a label (RBAC tenancy, ATT&CK coverage,
-- compliance).
CREATE INDEX IF NOT EXISTS idx_finding_label_taxonomy_label
    ON finding_label (taxonomy, label);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS finding_label_touch
AFTER UPDATE ON finding_label FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE finding_label SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
