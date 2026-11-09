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
CREATE TABLE IF NOT EXISTS artifact (
    id TEXT NOT NULL DEFAULT (uuid()),
    assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT,
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    publication_revision INTEGER CHECK (
        publication_revision IS NULL OR (
            assessment_id IS NULL
            AND typeof(publication_revision) = 'integer'
            AND publication_revision > 0)),
    digest TEXT NOT NULL CHECK (digest <> ''),
    kind TEXT NOT NULL CHECK (kind <> ''),
    uri TEXT NOT NULL CHECK (uri <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (assessment_id, digest)
);
-- Imported documents (no assessment) dedupe on digest alone; a plain UNIQUE
-- would let NULL assessment_id slip through.
CREATE UNIQUE INDEX IF NOT EXISTS uq_artifact_imported
    ON artifact (digest)
    WHERE assessment_id IS NULL;

-- An assessment's documents (every artifact-lane read).
CREATE INDEX IF NOT EXISTS idx_artifact_assessment
    ON artifact (assessment_id)
    WHERE assessment_id IS NOT NULL;

-- What an order's run recorded.
CREATE INDEX IF NOT EXISTS idx_artifact_run_order
    ON artifact (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- The latest imported document of a kind (configuration documents such as the
-- corpus registry, versioned as whole documents).
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifact_imported_kind
    ON artifact (kind, publication_revision DESC)
    WHERE assessment_id IS NULL;

-- Legacy storage may represent an unversioned import, but new writes must
-- publish into a revisioned stream. The column CHECK also keeps revisions
-- off assessment-produced artifacts.
CREATE TRIGGER IF NOT EXISTS artifact_imported_revision_required
BEFORE INSERT ON artifact
WHEN NEW.assessment_id IS NULL AND NEW.publication_revision IS NULL BEGIN
  SELECT RAISE(ABORT, 'imported artifacts require a publication revision');
END;

CREATE TRIGGER IF NOT EXISTS artifact_reject_update
BEFORE UPDATE ON artifact BEGIN
  SELECT RAISE(ABORT, 'artifact rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS artifact_reject_delete
BEFORE DELETE ON artifact BEGIN
  SELECT RAISE(ABORT, 'artifact rows are append-only');
END;
