-- Explicit additive upgrade for existing databases missing this column.
-- Existing SBOMs have unknown coverage; never infer a scan from timestamps.
ALTER TABLE traust.repository_ref
    ADD COLUMN manifest_sbom_assessment_id UUID
    CONSTRAINT repository_ref_manifest_sbom_assessment_id_fkey
    REFERENCES traust.assessment(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom_assessment
    ON traust.repository_ref (manifest_sbom_assessment_id)
    WHERE manifest_sbom_assessment_id IS NOT NULL;
