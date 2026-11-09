-- Apply only when publication_revision is absent; this file is one atomic statement.
-- Equal historical timestamps have no recoverable publication order: the first
-- index refuses them before changing rows. Resolve them from proven history first.
LOCK TABLE traust.artifact IN ACCESS EXCLUSIVE MODE;
CREATE UNIQUE INDEX artifact_revision_upgrade_unambiguous
    ON traust.artifact (kind, created_at) WHERE assessment_id IS NULL;

ALTER TABLE traust.artifact ADD COLUMN publication_revision BIGINT CHECK (
    publication_revision IS NULL OR (assessment_id IS NULL AND publication_revision > 0));

ALTER TABLE traust.artifact DISABLE TRIGGER artifact_reject_mutation;
WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY kind ORDER BY created_at) AS revision
    FROM traust.artifact WHERE assessment_id IS NULL
)
UPDATE traust.artifact SET publication_revision = ranked.revision
FROM ranked WHERE ranked.id = artifact.id;
ALTER TABLE traust.artifact ENABLE TRIGGER artifact_reject_mutation;

DROP INDEX IF EXISTS traust.idx_artifact_imported_kind;
CREATE UNIQUE INDEX idx_artifact_imported_kind
    ON traust.artifact (kind, publication_revision DESC) WHERE assessment_id IS NULL;
DROP INDEX traust.artifact_revision_upgrade_unambiguous;
