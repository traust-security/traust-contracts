-- A container image, one per digest (the per-platform manifest).
--
-- Append-only. repository_ref_id: the commit it was built from, set only from
-- declared provenance (OCI org.opencontainers.image.revision, SLSA) - never
-- inferred; null when the build does not declare it. sbom_id: its own SBOM,
-- null until ingested. Which images a release ships (payloads, bundles) is
-- the adopter's release process: an extension, not core.
CREATE TABLE IF NOT EXISTS image (
    id TEXT NOT NULL DEFAULT (uuid()),
    digest TEXT NOT NULL CHECK (digest <> ''),
    platform TEXT,
    repository_ref_id TEXT REFERENCES repository_ref(id) ON DELETE RESTRICT,
    sbom_id TEXT REFERENCES sbom(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (digest)
);

-- Images built from a commit (blast radius, drift, container
-- findings).
CREATE INDEX IF NOT EXISTS idx_image_repository_ref
    ON image (repository_ref_id)
    WHERE repository_ref_id IS NOT NULL;

-- Images containing an SBOM (blast radius, drift).
CREATE INDEX IF NOT EXISTS idx_image_sbom
    ON image (sbom_id)
    WHERE sbom_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS image_reject_update
BEFORE UPDATE ON image BEGIN
  SELECT RAISE(ABORT, 'image rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS image_reject_delete
BEFORE DELETE ON image BEGIN
  SELECT RAISE(ABORT, 'image rows are append-only');
END;
