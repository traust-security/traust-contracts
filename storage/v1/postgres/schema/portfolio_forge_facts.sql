-- Latest forge observation only; derived RepoState is never stored.
-- identity is a canonical URL key or a distinct missing-URL filing key, supplied by Core.
-- audited_sha, audit_date and has_audit identify the baseline used for the observation.
CREATE TABLE IF NOT EXISTS traust_storage.portfolio_forge_facts (
    identity TEXT NOT NULL PRIMARY KEY,
    repo_key TEXT NOT NULL UNIQUE,
    repo_url TEXT,
    source_url TEXT,
    audited_sha TEXT,
    audit_date TEXT,
    has_audit BOOLEAN NOT NULL,
    status TEXT NOT NULL,
    pushed_at TEXT,
    archived BOOLEAN,
    default_branch TEXT,
    visibility TEXT,
    fork BOOLEAN,
    parent TEXT,
    ahead_by BIGINT,
    changed_lines BIGINT,
    sensitive_changed BOOLEAN,
    sensitive_lines BIGINT,
    deps_only BOOLEAN,
    compare_truncated BOOLEAN,
    observed_at TIMESTAMPTZ NOT NULL,
    error TEXT
);
