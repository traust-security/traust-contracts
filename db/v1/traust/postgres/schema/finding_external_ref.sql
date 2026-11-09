-- A finding's ticket in an external system: a lookup lead, never the system
-- of record. Advisories live in advisory, not here.
--
-- system is a registered provider name (deployment data), never a core
-- enum - checked at intake.
CREATE TABLE IF NOT EXISTS traust.finding_external_ref (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    assessment_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    system TEXT NOT NULL CHECK (system <> ''),
    ref TEXT NOT NULL CHECK (ref <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (system, ref, finding_id)
);

-- Tickets for a finding; "no ticket yet" anti-join
-- (remediation, scoreboard).
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_finding
    ON traust.finding_external_ref (finding_id);

-- A remediation attempt's tracker, separate from finding-wide tickets.
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_assessment
    ON traust.finding_external_ref (assessment_id) WHERE assessment_id IS NOT NULL;

DROP TRIGGER IF EXISTS finding_external_ref_touch ON traust.finding_external_ref;
CREATE TRIGGER finding_external_ref_touch
BEFORE UPDATE ON traust.finding_external_ref
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
