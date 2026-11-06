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

-- A row names the repository that owns its finding: the per-repository view
-- reads repository_id, so it must never attribute a finding elsewhere. A
-- missing finding is left to its foreign key.
CREATE OR REPLACE FUNCTION traust.remediation_finding_repository_of_finding()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM traust.finding
               WHERE id = NEW.finding_id AND repository_id IS DISTINCT FROM NEW.repository_id) THEN
        RAISE EXCEPTION 'remediation_finding.repository_id % does not own finding %',
            NEW.repository_id, NEW.finding_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS remediation_finding_repository_of_finding ON traust.remediation_finding;
CREATE TRIGGER remediation_finding_repository_of_finding
BEFORE INSERT OR UPDATE OF finding_id, repository_id ON traust.remediation_finding
FOR EACH ROW EXECUTE FUNCTION traust.remediation_finding_repository_of_finding();

-- ...and a finding under remediation keeps that repository: moving it would
-- leave its links attributing it to the old one.
CREATE OR REPLACE FUNCTION traust.finding_under_remediation_stays()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM traust.remediation_finding
               WHERE finding_id = NEW.id AND repository_id IS DISTINCT FROM NEW.repository_id) THEN
        RAISE EXCEPTION 'finding % is under remediation on repository %, not %',
            NEW.id, OLD.repository_id, NEW.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS finding_under_remediation_stays ON traust.finding;
CREATE TRIGGER finding_under_remediation_stays
BEFORE UPDATE OF repository_id ON traust.finding
FOR EACH ROW EXECUTE FUNCTION traust.finding_under_remediation_stays();
