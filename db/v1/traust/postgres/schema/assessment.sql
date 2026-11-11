-- What was examined: one run of one assessor over a repository_ref (or an
-- image), at a point in time.
--
-- Append-only: id, created_at and a reject-mutation trigger. kind and status
-- classify, so their values come from contracts (assessment-kind and
-- assessment-status, to add) - checked at intake, not database constraints.
-- status degraded = ran without a usable input (e.g. no scanner DB), never
-- read as clean. assessor is a principal id: skill:<name> | tool:<name> |
-- user:<id>. run_order_id: the order that produced it (ops namespace);
-- null = manual / imported - the FK is added by the ops bootstrap, because
-- run_order references storage tables back and the namespaces are mutually
-- recursive. baseline_assessment_id: what a diff_scan compared against.
CREATE TABLE IF NOT EXISTS traust.assessment (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    repository_ref_id UUID NOT NULL REFERENCES traust.repository_ref(id) ON DELETE RESTRICT,
    image_id UUID REFERENCES traust.image(id) ON DELETE RESTRICT,
    baseline_assessment_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    run_order_id UUID,
    kind TEXT NOT NULL CHECK (kind <> ''),
    status TEXT NOT NULL CHECK (status <> ''),
    assessor TEXT NOT NULL CHECK (assessor <> ''),
    assessor_version TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- Latest assessment of a kind per ref (census, freshness,
-- default-branch cohort, artifact lane, LoC).
CREATE INDEX IF NOT EXISTS idx_assessment_ref_kind_occurred
    ON traust.assessment (repository_ref_id, kind, occurred_at);

-- What an order produced (spend per scan, lane cost).
CREATE INDEX IF NOT EXISTS idx_assessment_run_order
    ON traust.assessment (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- The ops feed: assessments recorded after a (created_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_assessment_created
    ON traust.assessment (created_at, id);

-- repository_ref -> assessment -> repository_ref closes a cycle: add the
-- current manifest scan FK here, once both tables exist. SQLite has it inline.
ALTER TABLE traust.repository_ref
    DROP CONSTRAINT IF EXISTS repository_ref_manifest_sbom_assessment_id_fkey;
ALTER TABLE traust.repository_ref
    ADD CONSTRAINT repository_ref_manifest_sbom_assessment_id_fkey
    FOREIGN KEY (manifest_sbom_assessment_id) REFERENCES traust.assessment(id) ON DELETE RESTRICT;

DROP TRIGGER IF EXISTS assessment_reject_mutation ON traust.assessment;
CREATE TRIGGER assessment_reject_mutation
BEFORE UPDATE OR DELETE ON traust.assessment
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS assessment_reject_truncate ON traust.assessment;
CREATE TRIGGER assessment_reject_truncate
BEFORE TRUNCATE ON traust.assessment
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
