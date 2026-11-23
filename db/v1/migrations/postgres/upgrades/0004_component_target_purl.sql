-- Component PURL target scoping for monorepo audits: assessment.target_purl and
-- run_order.{target_purl, target_sha, target_module_path}.
-- Existing assessments and orders keep these columns NULL (whole-repository scope).
ALTER TABLE traust.assessment
    ADD COLUMN target_purl TEXT CHECK (target_purl <> '');

CREATE INDEX IF NOT EXISTS idx_assessment_ref_target_kind_occurred
    ON traust.assessment (repository_ref_id, target_purl, kind, occurred_at)
    WHERE target_purl IS NOT NULL;

ALTER TABLE traust_ops.run_order
    ADD COLUMN target_purl TEXT CHECK (target_purl <> ''),
    ADD COLUMN target_sha TEXT CHECK (target_sha ~ '^[0-9a-f]{40}$'),
    ADD COLUMN target_module_path TEXT CHECK (target_module_path <> ''),
    ADD CONSTRAINT chk_run_order_component_target CHECK (
        (target_purl IS NULL) = (target_sha IS NULL)
        AND (target_purl IS NULL) = (target_module_path IS NULL)
    );

CREATE INDEX IF NOT EXISTS idx_ops_run_order_target_purl
    ON traust_ops.run_order (repository_id, target_purl, state)
    WHERE target_purl IS NOT NULL;
