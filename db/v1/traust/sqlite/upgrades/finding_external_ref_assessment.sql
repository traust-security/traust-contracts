ALTER TABLE finding_external_ref
    ADD COLUMN assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_finding_external_ref_assessment
    ON finding_external_ref (assessment_id) WHERE assessment_id IS NOT NULL;
