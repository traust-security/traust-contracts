-- Guard-only upgrade for stores that already have assessment_id.
-- Run outside an existing transaction; roll back on any failure.
BEGIN;

-- Repair a prior interrupted column-only upgrade without changing links.
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_assessment
    ON traust.finding_external_ref (assessment_id) WHERE assessment_id IS NOT NULL;

-- Scoped trackers name an assessment of the finding's repository, not an
-- occurrence: remediation assessments need not have reported the finding.
-- NULL retains historical, finding-wide links without inferred attribution.
CREATE OR REPLACE FUNCTION traust.check_finding_external_ref_scope()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.assessment_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM traust.finding f
        JOIN traust.assessment a ON a.id = NEW.assessment_id
        JOIN traust.repository_ref r ON r.id = a.repository_ref_id
        WHERE f.id = NEW.finding_id AND f.repository_id = r.repository_id
    ) THEN
        RAISE EXCEPTION 'tracker assessment and finding must belong to the same repository';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS finding_external_ref_scope_insert ON traust.finding_external_ref;
CREATE TRIGGER finding_external_ref_scope_insert
BEFORE INSERT ON traust.finding_external_ref
FOR EACH ROW EXECUTE FUNCTION traust.check_finding_external_ref_scope();

DROP TRIGGER IF EXISTS finding_external_ref_scope_update ON traust.finding_external_ref;
CREATE TRIGGER finding_external_ref_scope_update
BEFORE UPDATE OF finding_id, assessment_id ON traust.finding_external_ref
FOR EACH ROW EXECUTE FUNCTION traust.check_finding_external_ref_scope();

-- Assessments already reject every update, including repository_ref_id.
-- Mutable parents must not move existing scoped links across repositories.
CREATE OR REPLACE FUNCTION traust.check_tracker_finding_repository()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM traust.finding_external_ref e
        JOIN traust.assessment a ON a.id = e.assessment_id
        JOIN traust.repository_ref r ON r.id = a.repository_ref_id
        WHERE e.finding_id = OLD.id AND r.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'finding repository change would invalidate tracker scope';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS finding_external_ref_finding_scope_update ON traust.finding;
CREATE TRIGGER finding_external_ref_finding_scope_update
BEFORE UPDATE OF repository_id ON traust.finding
FOR EACH ROW WHEN (NEW.repository_id IS DISTINCT FROM OLD.repository_id)
EXECUTE FUNCTION traust.check_tracker_finding_repository();

CREATE OR REPLACE FUNCTION traust.check_tracker_ref_repository()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM traust.assessment a
        JOIN traust.finding_external_ref e ON e.assessment_id = a.id
        JOIN traust.finding f ON f.id = e.finding_id
        WHERE a.repository_ref_id = OLD.id AND f.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'repository ref change would invalidate tracker scope';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS finding_external_ref_repository_ref_scope_update ON traust.repository_ref;
CREATE TRIGGER finding_external_ref_repository_ref_scope_update
BEFORE UPDATE OF repository_id ON traust.repository_ref
FOR EACH ROW WHEN (NEW.repository_id IS DISTINCT FROM OLD.repository_id)
EXECUTE FUNCTION traust.check_tracker_ref_repository();

-- Refuse inconsistent existing scopes without inferring or repairing history.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM traust.finding_external_ref e
        WHERE e.assessment_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM traust.finding f
            JOIN traust.assessment a ON a.id = e.assessment_id
            JOIN traust.repository_ref r ON r.id = a.repository_ref_id
            WHERE f.id = e.finding_id AND f.repository_id = r.repository_id
        )
    ) THEN
        RAISE EXCEPTION 'existing tracker assessment and finding must belong to the same repository';
    END IF;
END;
$$;

COMMIT;
