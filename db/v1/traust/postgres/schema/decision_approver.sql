-- An approver a restatement names: someone other than its author who agreed
-- to the correction. The deployment sets how many independent approvers a
-- restatement needs; the decision service checks it.
--
-- Append-only: id, created_at and a reject-mutation trigger.
CREATE TABLE IF NOT EXISTS traust.decision_approver (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    decision_id UUID NOT NULL REFERENCES traust.decision(id) ON DELETE RESTRICT,
    approver TEXT NOT NULL CHECK (approver <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (decision_id, approver)
);

DROP TRIGGER IF EXISTS decision_approver_reject_mutation ON traust.decision_approver;
CREATE TRIGGER decision_approver_reject_mutation
BEFORE UPDATE OR DELETE ON traust.decision_approver
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS decision_approver_reject_truncate ON traust.decision_approver;
CREATE TRIGGER decision_approver_reject_truncate
BEFORE TRUNCATE ON traust.decision_approver
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
