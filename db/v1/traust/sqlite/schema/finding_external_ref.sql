-- A finding's ticket in an external system: a lookup lead, never the system
-- of record. Advisories live in advisory, not here.
--
-- system is a registered provider name (deployment data), never a core
-- enum - checked at intake.
CREATE TABLE IF NOT EXISTS finding_external_ref (
    id TEXT NOT NULL DEFAULT (uuid()),
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT,
    system TEXT NOT NULL CHECK (system <> ''),
    ref TEXT NOT NULL CHECK (ref <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (system, ref, finding_id)
);

-- Tickets for a finding; "no ticket yet" anti-join
-- (remediation, scoreboard).
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_finding
    ON finding_external_ref (finding_id);

-- A remediation attempt's tracker, separate from finding-wide tickets.
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_assessment
    ON finding_external_ref (assessment_id) WHERE assessment_id IS NOT NULL;

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS finding_external_ref_touch
AFTER UPDATE ON finding_external_ref FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE finding_external_ref SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
