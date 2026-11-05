-- The current state of one remediation effort: where the fix lives (the fork
-- and its branch) and where the effort stands.
--
-- Mutable table, like finding. Decisions stay the source of truth; this row
-- is an explicitly maintained projection the services that write those
-- decisions keep in the same transaction (status sync). status values
-- (candidate..merged/abandoned) come from contracts (remediation-status) -
-- checked at intake, not database constraints. fork_url is operational
-- context - where the fix lives - not a FK to repository: forks are only
-- used for remediation and may not be registered in the inventory; the
-- upstream repository relationship rides remediation_finding's FK.
-- assessment_id: the remediation assessment (work item) this effort runs
-- through; ON DELETE SET NULL because assessments are append-only, so this
-- only guards against a re-created database.
CREATE TABLE IF NOT EXISTS remediation (
    id TEXT NOT NULL DEFAULT (uuid()),
    fork_url TEXT NOT NULL CHECK (fork_url <> ''),
    fork_branch TEXT NOT NULL CHECK (fork_branch <> ''),
    status TEXT NOT NULL CHECK (status <> ''),
    assessment_id TEXT REFERENCES assessment(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- Remediations by status (the console's lanes, GC's terminal sweep).
CREATE INDEX IF NOT EXISTS idx_remediation_status
    ON remediation (status);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS remediation_touch
AFTER UPDATE ON remediation FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE remediation SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
