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

-- Scoped trackers name an assessment of the finding's repository, not an
-- occurrence: remediation assessments need not have reported the finding.
-- NULL retains historical, finding-wide links without inferred attribution.
CREATE TRIGGER IF NOT EXISTS finding_external_ref_scope_insert
BEFORE INSERT ON finding_external_ref FOR EACH ROW
WHEN NEW.assessment_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM finding f
    JOIN assessment a ON a.id = NEW.assessment_id
    JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE f.id = NEW.finding_id AND f.repository_id = r.repository_id
) BEGIN
    SELECT RAISE(ABORT, 'tracker assessment and finding must belong to the same repository');
END;

CREATE TRIGGER IF NOT EXISTS finding_external_ref_scope_update
BEFORE UPDATE OF finding_id, assessment_id ON finding_external_ref FOR EACH ROW
WHEN NEW.assessment_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM finding f
    JOIN assessment a ON a.id = NEW.assessment_id
    JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE f.id = NEW.finding_id AND f.repository_id = r.repository_id
) BEGIN
    SELECT RAISE(ABORT, 'tracker assessment and finding must belong to the same repository');
END;

-- Assessments already reject every update, including repository_ref_id.
-- Mutable parents must not move existing scoped links across repositories.
CREATE TRIGGER IF NOT EXISTS finding_external_ref_finding_scope_update
BEFORE UPDATE OF repository_id ON finding FOR EACH ROW
WHEN NEW.repository_id IS NOT OLD.repository_id AND EXISTS (
    SELECT 1 FROM finding_external_ref e
    JOIN assessment a ON a.id = e.assessment_id
    JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE e.finding_id = OLD.id AND r.repository_id IS NOT NEW.repository_id
) BEGIN
    SELECT RAISE(ABORT, 'finding repository change would invalidate tracker scope');
END;

CREATE TRIGGER IF NOT EXISTS finding_external_ref_repository_ref_scope_update
BEFORE UPDATE OF repository_id ON repository_ref FOR EACH ROW
WHEN NEW.repository_id IS NOT OLD.repository_id AND EXISTS (
    SELECT 1 FROM assessment a
    JOIN finding_external_ref e ON e.assessment_id = a.id
    JOIN finding f ON f.id = e.finding_id
    WHERE a.repository_ref_id = OLD.id AND f.repository_id IS NOT NEW.repository_id
) BEGIN
    SELECT RAISE(ABORT, 'repository ref change would invalidate tracker scope');
END;
