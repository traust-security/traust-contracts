-- The CWEs a finding was reported with: the set as reported, no primary
-- selection (that is a view over cwe).
CREATE TABLE IF NOT EXISTS traust.finding_cwe (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    cwe_id UUID NOT NULL REFERENCES traust.cwe(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (finding_id, cwe_id)
);

-- Findings of a CWE (insecure patterns, rule mining,
-- primary-CWE view).
CREATE INDEX IF NOT EXISTS idx_finding_cwe_cwe
    ON traust.finding_cwe (cwe_id);

DROP TRIGGER IF EXISTS finding_cwe_touch ON traust.finding_cwe;
CREATE TRIGGER finding_cwe_touch
BEFORE UPDATE ON traust.finding_cwe
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
