-- Explicit additive upgrade for existing databases missing this column.
-- Existing SBOMs have unknown coverage; never infer a scan from timestamps.
ALTER TABLE repository_ref
    ADD COLUMN manifest_sbom_assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_repository_ref_manifest_sbom_assessment
    ON repository_ref (manifest_sbom_assessment_id)
    WHERE manifest_sbom_assessment_id IS NOT NULL;
