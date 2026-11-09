CREATE INDEX IF NOT EXISTS idx_finding_repository_fingerprint
    ON traust.finding (repository_id, fingerprint);
