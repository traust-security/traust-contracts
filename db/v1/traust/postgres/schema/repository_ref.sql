-- A repository at one commit: branch/tag + sha, or a bare commit.
--
-- Mutable table. A line is (repository_id, name) - derived, no table.
-- name/kind are null together (bare commit); is_default marks the default
-- branch when scanned, from the forge - branches only.
-- UNIQUE (id, repository_id) is the target of composite FKs .
-- manifest_sbom_id: the SBOM read from the source tree (manifests, lockfiles,
-- Dockerfile FROM).
-- manifest_sbom_assessment_id: the exact scan that produced current coverage,
-- even when the SBOM content is unchanged; null means coverage is unknown.
-- default_named_at: when this row was last named the default head (import or
-- observation) — a line is immutable once recorded, and a re-import of an old
-- head must still win over an earlier observation, so the row's creation time
-- can't carry it.
-- manifest_sbom_assessment_id's FK closes a cycle and is added after
-- assessment exists in assessment.sql.
CREATE TABLE IF NOT EXISTS traust.repository_ref (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES traust.repository(id) ON DELETE RESTRICT,
    name TEXT,
    kind TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    sha TEXT NOT NULL CHECK (sha <> ''),
    default_named_at TIMESTAMPTZ,
    manifest_sbom_id UUID REFERENCES traust.sbom(id) ON DELETE RESTRICT,
    manifest_sbom_assessment_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (id, repository_id),
    CHECK (NOT is_default OR (kind IS NOT NULL AND kind = 'branch')),
    CHECK ((name IS NULL) = (kind IS NULL))
);

-- One named ref per (repository, name, sha); a plain UNIQUE would let NULL
-- names slip through, so bare commits get their own partial index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ref_named
    ON traust.repository_ref (repository_id, name, sha)
    WHERE name IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ref_bare
    ON traust.repository_ref (repository_id, sha)
    WHERE name IS NULL;

-- A repository's refs (portfolio reads, review-surface coverage); the unique
-- indexes above are partial, so they can't serve an unconditioned lookup.
CREATE INDEX IF NOT EXISTS idx_repository_ref_repository
    ON traust.repository_ref (repository_id);

-- Refs carrying a manifest SBOM (blast radius, usage query, drift).
CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom
    ON traust.repository_ref (manifest_sbom_id)
    WHERE manifest_sbom_id IS NOT NULL;

-- Refs bound to a manifest scan; also supports the assessment FK check.
CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom_assessment
    ON traust.repository_ref (manifest_sbom_assessment_id)
    WHERE manifest_sbom_assessment_id IS NOT NULL;

-- The default-head lookup (portfolio's default line); partial like the unique
-- indexes above, and ordered by the naming time, not the row's creation.
CREATE INDEX IF NOT EXISTS idx_repository_ref_default
    ON traust.repository_ref (repository_id, default_named_at)
    WHERE is_default;

DROP TRIGGER IF EXISTS repository_ref_touch ON traust.repository_ref;
CREATE TRIGGER repository_ref_touch
BEFORE UPDATE ON traust.repository_ref
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
