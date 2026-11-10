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
-- The pairing is a join predicate between two stored columns, and core is the
-- sole writer: its insert path checks it (an EXISTS over the finding and the
-- assessment's repository ref), so no insert or link-update trigger stands
-- here. Of the parents, assessments are immutable and a finding cannot move
-- between repositories without breaking its (repository_id, fingerprint)
-- identity; only repository_ref.repository_id can move, and this plain check
-- keeps an existing scoped link from crossing repositories with it.
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
