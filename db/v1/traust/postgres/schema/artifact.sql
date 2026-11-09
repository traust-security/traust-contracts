-- A document produced by (or imported into) an assessment: the artifact lane.
-- A pointer plus integrity, never content.
--
-- Append-only. id is the identity; uri is where the bytes live (file://,
-- s3://, or an adopter's own store) - a location, never an id, and never
-- parsed for meaning; download links are minted from it per request.
-- digest is the sha256 of the exact bytes: proves the bytes at uri are the
-- ones recorded (verify, ledger evidence) and makes a retried publish a
-- no-op. kind is a contracts schema id, checked at intake. assessment_id
-- null = imported. run_order_id: the order whose run recorded it (ops
-- namespace), so a run can tell its own document from an earlier one on the
-- same assessment; null = recorded outside an order, or imported. One row per
-- producer and document: the same bytes from
-- two assessments are two rows; the store keeps them once. A storage move
-- is a deliberate relocation migration, not a routine update.
CREATE TABLE IF NOT EXISTS traust.artifact (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    assessment_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    run_order_id UUID,
    publication_revision BIGINT CHECK (
        publication_revision IS NULL OR (assessment_id IS NULL AND publication_revision > 0)),
    digest TEXT NOT NULL CHECK (digest <> ''),
    kind TEXT NOT NULL CHECK (kind <> ''),
    uri TEXT NOT NULL CHECK (uri <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    CONSTRAINT artifact_imported_revision_required CHECK (
        assessment_id IS NOT NULL OR publication_revision IS NOT NULL),
    UNIQUE (assessment_id, digest)
);
-- Imported documents (no assessment) dedupe on digest alone; a plain UNIQUE
-- would let NULL assessment_id slip through.
CREATE UNIQUE INDEX IF NOT EXISTS uq_artifact_imported
    ON traust.artifact (digest)
    WHERE assessment_id IS NULL;

-- An assessment's documents (every artifact-lane read).
CREATE INDEX IF NOT EXISTS idx_artifact_assessment
    ON traust.artifact (assessment_id)
    WHERE assessment_id IS NOT NULL;

-- What an order's run recorded.
CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON traust.artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- The latest imported document of a kind (configuration documents such as the
-- corpus registry, versioned as whole documents).
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifact_imported_kind
    ON traust.artifact (kind, publication_revision DESC)
    WHERE assessment_id IS NULL;

-- sbom.artifact_id closes a cycle (sbom -> artifact -> assessment -> image
-- -> sbom), so it cannot be inline on Postgres: added here, once all four
-- tables exist. SQLite carries it inline in sbom.sql.
ALTER TABLE traust.sbom DROP CONSTRAINT IF EXISTS sbom_artifact_id_fkey;
ALTER TABLE traust.sbom
    ADD CONSTRAINT sbom_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES traust.artifact(id) ON DELETE RESTRICT;

DROP TRIGGER IF EXISTS artifact_reject_mutation ON traust.artifact;
CREATE TRIGGER artifact_reject_mutation
BEFORE UPDATE OR DELETE ON traust.artifact
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS artifact_reject_truncate ON traust.artifact;
CREATE TRIGGER artifact_reject_truncate
BEFORE TRUNCATE ON traust.artifact
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
