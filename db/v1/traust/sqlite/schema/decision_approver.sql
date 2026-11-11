-- An approver a restatement names: someone other than its author who agreed
-- to the correction. The deployment sets how many independent approvers a
-- restatement needs; the decision service checks it.
--
-- Append-only: id, created_at and a reject-mutation trigger.
CREATE TABLE IF NOT EXISTS decision_approver (
    id TEXT NOT NULL DEFAULT (uuid()),
    decision_id TEXT NOT NULL REFERENCES decision(id) ON DELETE RESTRICT,
    approver TEXT NOT NULL CHECK (approver <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (decision_id, approver)
);

CREATE TRIGGER IF NOT EXISTS decision_approver_reject_update
BEFORE UPDATE ON decision_approver BEGIN
  SELECT RAISE(ABORT, 'decision_approver rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS decision_approver_reject_delete
BEFORE DELETE ON decision_approver BEGIN
  SELECT RAISE(ABORT, 'decision_approver rows are append-only');
END;
