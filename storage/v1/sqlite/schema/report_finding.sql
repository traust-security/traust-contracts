-- Per-finding projection of a cumulative report.
--
-- report.findings is an opaque JSON column: the disposition every dashboard
-- filters on (validity, resolution) and the identity every distinct-exposure
-- count needs (fingerprint) were present in the contract but unqueryable.
-- This makes them columns without changing what the schema models.
--
-- One row per finding per report binding. Disposition is optional on the
-- artifact -- it appears only on cumulative reports -- so a finding without
-- one still projects, carrying its identity with NULL disposition.
CREATE TABLE IF NOT EXISTS report_finding (
    binding_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    -- Secondary correlation key, never the sole key of a disposition record
    -- (report.schema.json): the scan-scoped finding_id stays primary.
    fingerprint TEXT,
    validation_status TEXT,
    validity TEXT,
    resolution TEXT,
    assurance TEXT,
    last_updated TEXT,
    -- The four flags that carry the two-person rule and the countersign
    -- queue. Dropping them is how a dashboard loses sight of whether an FP
    -- was overridden by execution evidence.
    conflict INTEGER,
    fp_overridden INTEGER,
    fp_reassertion_blocked INTEGER,
    refuted_awaiting_signoff INTEGER,
    severity_override TEXT CHECK (severity_override IS NULL OR json_valid(severity_override)),
    -- The body of the finding. `description` and `remediation` are
    -- REQUIRED by report.schema.json and were the two largest strings
    -- the projection dropped; a finding without them is a title.
    description TEXT,
    remediation TEXT,
    -- The analytical axes. `category` and `cwes` are what an
    -- insecure-patterns rollup groups by, and neither was reachable:
    -- the pattern dashboard is the one consumer that cannot be
    -- expressed on this table without them.
    category TEXT,
    cwes TEXT CHECK (cwes IS NULL OR json_valid(cwes)),
    locations TEXT CHECK (locations IS NULL OR json_valid(locations)),
    asvs_references TEXT CHECK (asvs_references IS NULL OR json_valid(asvs_references)),
    peach_references TEXT CHECK (peach_references IS NULL OR json_valid(peach_references)),
    owasp_llm_references TEXT CHECK (owasp_llm_references IS NULL OR json_valid(owasp_llm_references)),
    capec TEXT CHECK (capec IS NULL OR json_valid(capec)),
    attack_pattern TEXT,
    cvss TEXT CHECK (cvss IS NULL OR json_valid(cvss)),
    evidence TEXT CHECK (evidence IS NULL OR json_valid(evidence)),
    -- Provenance and downgrade context. `effective_severity` is the
    -- severity after disposition; reading `severity` alone reports a
    -- downgraded finding at its original rating.
    effective_severity TEXT,
    origin TEXT,
    source_findings TEXT CHECK (source_findings IS NULL OR json_valid(source_findings)),
    passes TEXT CHECK (passes IS NULL OR json_valid(passes)),
    remediation_effort TEXT,
    blocked_external INTEGER,
    pqc_classification TEXT,
    fingerprint_algo TEXT,
    isolation_boundary TEXT,
    isolation_dimensions TEXT CHECK (isolation_dimensions IS NULL OR json_valid(isolation_dimensions)),
    dependency TEXT CHECK (dependency IS NULL OR json_valid(dependency)),
    PRIMARY KEY (binding_id, finding_id),
    FOREIGN KEY (binding_id, artifact_digest)
        REFERENCES artifact_binding(binding_id, artifact_digest)
);

CREATE INDEX IF NOT EXISTS idx_report_finding_fingerprint
    ON report_finding (fingerprint)
    WHERE fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_report_finding_disposition
    ON report_finding (validity, resolution);
