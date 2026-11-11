-- A finding reported by one assessment: the scan-level record.
--
-- Append-only. severity is the scanner severity, normalised at intake (the
-- raw value stays in the artifact) - values from contracts
-- scanner-severity, checked at intake. cvss_score is computed from
-- cvss_vector at intake - null when the vector has no version prefix.
-- rule is the detector rule that matched (SARIF ruleId).
CREATE TABLE IF NOT EXISTS traust.occurrence (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    assessment_id UUID NOT NULL REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    severity TEXT NOT NULL CHECK (severity <> ''),
    cvss_vector TEXT,
    cvss_score NUMERIC CHECK (cvss_score BETWEEN 0 AND 10),
    rule TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (finding_id, assessment_id)
);

-- What one scan reported (x-vs-y, recall, triage of a run).
CREATE INDEX IF NOT EXISTS idx_occurrence_assessment
    ON traust.occurrence (assessment_id);

DROP TRIGGER IF EXISTS occurrence_reject_mutation ON traust.occurrence;
CREATE TRIGGER occurrence_reject_mutation
BEFORE UPDATE OR DELETE ON traust.occurrence
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS occurrence_reject_truncate ON traust.occurrence;
CREATE TRIGGER occurrence_reject_truncate
BEFORE TRUNCATE ON traust.occurrence
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
