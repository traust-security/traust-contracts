-- The findings a remediation resolves, on which repositories (many-to-many).
-- Follows the finding_cwe junction-table precedent: the set as scheduled,
-- RESTRICT on every FK so a finding under remediation is never deleted out
-- from under the effort.
CREATE TABLE IF NOT EXISTS remediation_finding (
    id TEXT NOT NULL DEFAULT (uuid()),
    remediation_id TEXT NOT NULL REFERENCES remediation(id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (remediation_id, finding_id, repository_id)
);

-- Remediations of a finding (the finding's remediation history).
CREATE INDEX IF NOT EXISTS idx_remediation_finding_finding
    ON remediation_finding (finding_id);

-- Remediations of a repository (the console's per-repo view).
CREATE INDEX IF NOT EXISTS idx_remediation_finding_repository
    ON remediation_finding (repository_id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS remediation_finding_touch
AFTER UPDATE ON remediation_finding FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE remediation_finding SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;

-- A row names the repository that owns its finding: the per-repository view
-- reads repository_id, so it must never attribute a finding elsewhere. A
-- missing finding is left to its foreign key.
CREATE TRIGGER IF NOT EXISTS remediation_finding_repository_of_finding
BEFORE INSERT ON remediation_finding
WHEN EXISTS (SELECT 1 FROM finding
             WHERE id = NEW.finding_id AND repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'remediation_finding.repository_id does not own its finding');
END;

CREATE TRIGGER IF NOT EXISTS remediation_finding_repository_of_finding_update
BEFORE UPDATE OF finding_id, repository_id ON remediation_finding
WHEN EXISTS (SELECT 1 FROM finding
             WHERE id = NEW.finding_id AND repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'remediation_finding.repository_id does not own its finding');
END;
