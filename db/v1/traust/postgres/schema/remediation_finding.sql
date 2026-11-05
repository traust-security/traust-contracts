-- The findings a remediation resolves, on which repositories (many-to-many).
-- Follows the finding_cwe junction-table precedent: the set as scheduled,
-- RESTRICT on every FK so a finding under remediation is never deleted out
-- from under the effort.
CREATE TABLE IF NOT EXISTS traust.remediation_finding (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    remediation_id UUID NOT NULL REFERENCES traust.remediation(id) ON DELETE RESTRICT,
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    repository_id UUID NOT NULL REFERENCES traust.repository(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (remediation_id, finding_id, repository_id)
);

-- Remediations of a finding (the finding's remediation history).
CREATE INDEX IF NOT EXISTS idx_remediation_finding_finding
    ON traust.remediation_finding (finding_id);

-- Remediations of a repository (the console's per-repo view).
CREATE INDEX IF NOT EXISTS idx_remediation_finding_repository
    ON traust.remediation_finding (repository_id);

DROP TRIGGER IF EXISTS remediation_finding_touch ON traust.remediation_finding;
CREATE TRIGGER remediation_finding_touch
BEFORE UPDATE ON traust.remediation_finding
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
