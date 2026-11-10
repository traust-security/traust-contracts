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

-- Scoped trackers name an assessment of the finding's repository, not an
-- occurrence: remediation assessments need not have reported the finding.
-- NULL retains historical, finding-wide links without inferred attribution.
-- The check FOR SHARE-locks the finding and the assessment's repository ref:
-- under READ COMMITTED a concurrent repository move then either waits for
-- this transaction (and is itself rejected by the parent guard) or has
-- already committed, so this check reads the moved rows - a scoped link can
-- never commit against stale parent repositories.
CREATE OR REPLACE FUNCTION traust.check_finding_external_ref_scope()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.assessment_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM traust.finding f
        JOIN traust.assessment a ON a.id = NEW.assessment_id
        JOIN traust.repository_ref r ON r.id = a.repository_ref_id
        WHERE f.id = NEW.finding_id AND f.repository_id = r.repository_id
        FOR SHARE OF f, r
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
