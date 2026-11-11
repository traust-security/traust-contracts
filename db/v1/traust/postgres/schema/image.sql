-- A container image, one per digest (the per-platform manifest).
--
-- Append-only. repository_ref_id: the commit it was built from, set only from
-- declared provenance (OCI org.opencontainers.image.revision, SLSA) - never
-- inferred; null when the build does not declare it. sbom_id: its own SBOM,
-- null until ingested. Which images a release ships (payloads, bundles) is
-- the adopter's release process: an extension, not core.
CREATE TABLE IF NOT EXISTS traust.image (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    digest TEXT NOT NULL CHECK (digest <> ''),
    platform TEXT,
    repository_ref_id UUID REFERENCES traust.repository_ref(id) ON DELETE RESTRICT,
    sbom_id UUID REFERENCES traust.sbom(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (digest)
);

-- Images built from a commit (blast radius, drift, container
-- findings).
CREATE INDEX IF NOT EXISTS idx_image_repository_ref
    ON traust.image (repository_ref_id)
    WHERE repository_ref_id IS NOT NULL;

-- Images containing an SBOM (blast radius, drift).
CREATE INDEX IF NOT EXISTS idx_image_sbom
    ON traust.image (sbom_id)
    WHERE sbom_id IS NOT NULL;

DROP TRIGGER IF EXISTS image_reject_mutation ON traust.image;
CREATE TRIGGER image_reject_mutation
BEFORE UPDATE OR DELETE ON traust.image
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS image_reject_truncate ON traust.image;
CREATE TRIGGER image_reject_truncate
BEFORE TRUNCATE ON traust.image
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
