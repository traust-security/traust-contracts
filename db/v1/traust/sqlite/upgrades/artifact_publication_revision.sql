-- Apply only when publication_revision is absent, outside an open transaction.
-- Equal historical timestamps have no recoverable publication order: the first
-- index refuses them before changing rows. Resolve them from proven history first.
BEGIN IMMEDIATE;

CREATE UNIQUE INDEX artifact_revision_upgrade_unambiguous
    ON artifact (kind, created_at) WHERE assessment_id IS NULL;

ALTER TABLE artifact ADD COLUMN publication_revision INTEGER CHECK (
    publication_revision IS NULL OR (assessment_id IS NULL AND publication_revision > 0));

DROP TRIGGER artifact_reject_update;
WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY kind ORDER BY created_at) AS revision
    FROM artifact WHERE assessment_id IS NULL
)
UPDATE artifact SET publication_revision = (
    SELECT revision FROM ranked WHERE ranked.id = artifact.id
) WHERE assessment_id IS NULL;
CREATE TRIGGER artifact_reject_update
BEFORE UPDATE ON artifact BEGIN
    SELECT RAISE(ABORT, 'artifact rows are append-only');
END;

DROP INDEX idx_artifact_imported_kind;
CREATE UNIQUE INDEX idx_artifact_imported_kind
    ON artifact (kind, publication_revision DESC) WHERE assessment_id IS NULL;
DROP INDEX artifact_revision_upgrade_unambiguous;

COMMIT;
