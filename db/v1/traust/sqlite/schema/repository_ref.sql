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
CREATE TABLE IF NOT EXISTS repository_ref (
    id TEXT NOT NULL DEFAULT (uuid()),
    repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE RESTRICT,
    name TEXT,
    kind TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE CHECK (is_default IN (0, 1)),
    sha TEXT NOT NULL CHECK (sha <> ''),
    manifest_sbom_id TEXT REFERENCES sbom(id) ON DELETE RESTRICT,
    manifest_sbom_assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (id, repository_id),
    CHECK (NOT is_default OR (kind IS NOT NULL AND kind = 'branch')),
    CHECK ((name IS NULL) = (kind IS NULL))
);

-- One named ref per (repository, name, sha); a plain UNIQUE would let NULL
-- names slip through, so bare commits get their own partial index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ref_named
    ON repository_ref (repository_id, name, sha)
    WHERE name IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ref_bare
    ON repository_ref (repository_id, sha)
    WHERE name IS NULL;

-- A repository's refs (portfolio reads, review-surface coverage); the unique
-- indexes above are partial, so they can't serve an unconditioned lookup.
CREATE INDEX IF NOT EXISTS idx_repository_ref_repository
    ON repository_ref (repository_id);

-- Refs carrying a manifest SBOM (blast radius, usage query, drift).
CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom
    ON repository_ref (manifest_sbom_id)
    WHERE manifest_sbom_id IS NOT NULL;

-- Refs bound to a manifest scan; also supports the assessment FK check.
CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom_assessment
    ON repository_ref (manifest_sbom_assessment_id)
    WHERE manifest_sbom_assessment_id IS NOT NULL;

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS repository_ref_touch
AFTER UPDATE ON repository_ref FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE repository_ref SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
