-- The finding state projection: the folded state carried on each decision row (plan schema-performance-audit, decision B; Young's ledger running-balance).

-- The finding state projection: the folded state carried on each decision row (plan schema-performance-audit, decision B; Young's ledger running-balance).
-- destructive: recreate the decision append-only guard with a projection carve-out — an update that changes anything but the folded_* columns still aborts.
DROP TRIGGER IF EXISTS decision_reject_update;

CREATE TRIGGER decision_reject_update
BEFORE UPDATE ON decision
WHEN (
       NEW.id IS NOT OLD.id
    OR NEW.finding_id IS NOT OLD.finding_id
    OR NEW.assessment_id IS NOT OLD.assessment_id
    OR NEW.fixed_repository_ref_id IS NOT OLD.fixed_repository_ref_id
    OR NEW.repository_ref_id IS NOT OLD.repository_ref_id
    OR NEW.restates_id IS NOT OLD.restates_id
    OR NEW.artifact_id IS NOT OLD.artifact_id
    OR NEW.statement_key IS NOT OLD.statement_key
    OR NEW.validity IS NOT OLD.validity
    OR NEW.resolution IS NOT OLD.resolution
    OR NEW.evidence_grade IS NOT OLD.evidence_grade
    OR NEW.reason IS NOT OLD.reason
    OR NEW.severity IS NOT OLD.severity
    OR NEW.source_channel IS NOT OLD.source_channel
    OR NEW.actor IS NOT OLD.actor
    OR NEW.rationale IS NOT OLD.rationale
    OR NEW.ticket IS NOT OLD.ticket
    OR NEW.auto_accept_tier IS NOT OLD.auto_accept_tier
    OR NEW.occurred_at IS NOT OLD.occurred_at
    OR NEW.created_at IS NOT OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'decision rows are append-only outside the state projection');
END;

ALTER TABLE decision
    ADD COLUMN folded_state TEXT CHECK (
        folded_state IS NULL
        OR folded_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE decision
    ADD COLUMN folded_severity TEXT CHECK (
        folded_severity IS NULL
        OR folded_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

ALTER TABLE decision
    ADD COLUMN folded_decided BOOLEAN CHECK (folded_decided IS NULL OR folded_decided IN (0, 1));

ALTER TABLE decision
    ADD COLUMN folded_proven BOOLEAN CHECK (folded_proven IS NULL OR folded_proven IN (0, 1));

ALTER TABLE decision
    ADD COLUMN folded_unverified BOOLEAN CHECK (
        folded_unverified IS NULL OR folded_unverified IN (0, 1)
    );

ALTER TABLE decision
    ADD COLUMN folded_policy_version TEXT;

-- The finding's current answer: state, effective severity and decided, stamped by core's
-- write doors from the fold (finding_state, effective_severity) on every finding, decision
-- and occurrence write; the first category label, copied by a trigger. A new finding is
-- identified - open, undecided - until a judgment says otherwise; NULL severity is unrated.
ALTER TABLE finding
    ADD COLUMN current_state TEXT NOT NULL DEFAULT 'open' CHECK (
        current_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE finding
    ADD COLUMN current_severity TEXT CHECK (
        current_severity IS NULL OR current_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

ALTER TABLE finding
    ADD COLUMN current_decided BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE finding
    ADD COLUMN category TEXT;

CREATE INDEX IF NOT EXISTS idx_finding_repository_current
    ON finding (repository_id, current_state, current_severity);

CREATE INDEX IF NOT EXISTS idx_decision_finding_occurred
    ON decision (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON ops_run_order (asset, state, finished_at, repository_id);

-- updated_at tracks the finding's own record, not its derived current answer: the touch
-- fires only when one of the finding's own columns is set.
DROP TRIGGER IF EXISTS finding_touch;

CREATE TRIGGER finding_touch
AFTER UPDATE OF repository_id, advisory_id, advisory_match, fingerprint_algo, fingerprint, kind, title ON finding FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE finding SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;

-- The first category label is a copy, not a rule: a trigger keeps it.
CREATE TRIGGER IF NOT EXISTS finding_current_label
AFTER INSERT ON finding_label FOR EACH ROW WHEN NEW.taxonomy = 'category'
BEGIN
  UPDATE finding SET category = NEW.label WHERE id = NEW.finding_id AND category IS NULL;
END;

-- Existing rows: the first category label; state, severity and decided arrive with core's
-- data channel, which restamps every finding from the fold.
UPDATE finding SET category = (
  SELECT l.label FROM finding_label l
  WHERE l.finding_id = finding.id AND l.taxonomy = 'category'
  ORDER BY l.created_at, l.id LIMIT 1);
