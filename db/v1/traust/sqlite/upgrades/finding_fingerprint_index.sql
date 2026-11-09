CREATE INDEX IF NOT EXISTS idx_finding_repository_fingerprint
    ON finding (repository_id, fingerprint);
