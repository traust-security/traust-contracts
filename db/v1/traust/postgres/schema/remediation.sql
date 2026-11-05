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
CREATE TABLE IF NOT EXISTS traust.remediation (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    fork_url TEXT NOT NULL CHECK (fork_url <> ''),
    fork_branch TEXT NOT NULL CHECK (fork_branch <> ''),
    status TEXT NOT NULL CHECK (status <> ''),
    assessment_id UUID REFERENCES traust.assessment(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- Remediations by status (the console's lanes, GC's terminal sweep).
CREATE INDEX IF NOT EXISTS idx_remediation_status
    ON traust.remediation (status);

DROP TRIGGER IF EXISTS remediation_touch ON traust.remediation;
CREATE TRIGGER remediation_touch
BEFORE UPDATE ON traust.remediation
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
