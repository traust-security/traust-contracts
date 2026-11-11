-- A finding reported by one assessment: the scan-level record.
--
-- Append-only. severity is the scanner severity, normalised at intake (the
-- raw value stays in the artifact) - values from contracts
-- scanner-severity, checked at intake. cvss_score is computed from
-- cvss_vector at intake - null when the vector has no version prefix.
-- rule is the detector rule that matched (SARIF ruleId).
CREATE TABLE IF NOT EXISTS occurrence (
    id TEXT NOT NULL DEFAULT (uuid()),
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    assessment_id TEXT NOT NULL REFERENCES assessment(id) ON DELETE RESTRICT,
    severity TEXT NOT NULL CHECK (severity <> ''),
    cvss_vector TEXT,
    cvss_score NUMERIC CHECK (cvss_score BETWEEN 0 AND 10),
    rule TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (finding_id, assessment_id)
);

-- What one scan reported (x-vs-y, recall, triage of a run).
CREATE INDEX IF NOT EXISTS idx_occurrence_assessment
    ON occurrence (assessment_id);

CREATE TRIGGER IF NOT EXISTS occurrence_reject_update
BEFORE UPDATE ON occurrence BEGIN
  SELECT RAISE(ABORT, 'occurrence rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS occurrence_reject_delete
BEFORE DELETE ON occurrence BEGIN
  SELECT RAISE(ABORT, 'occurrence rows are append-only');
END;
