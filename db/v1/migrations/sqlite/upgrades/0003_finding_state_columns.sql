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

-- The finding's current answer, stamped by the write doors (state and severity on each
-- decision, severity on each occurrence, the first category label): dashboards read one
-- indexed row per finding instead of the latest decision, occurrence and label per read.
ALTER TABLE finding
    ADD COLUMN current_state TEXT CHECK (
        current_state IS NULL OR current_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE finding
    ADD COLUMN current_severity TEXT CHECK (
        current_severity IS NULL OR current_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

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

-- The finding's current answer is kept by triggers, so no writer can leave it behind: a
-- decision (inserted, or its fold stamped) sets state and severity, an occurrence sets
-- severity unless the latest decision rated it, the first category label sets category.
CREATE TRIGGER IF NOT EXISTS finding_current_decision_insert
AFTER INSERT ON decision FOR EACH ROW
BEGIN
  UPDATE finding SET
    current_state = NEW.folded_state,
    current_severity = coalesce(NEW.folded_severity, (
      SELECT nullif(o.severity, 'unrated') FROM occurrence o
      WHERE o.finding_id = NEW.finding_id
      ORDER BY o.created_at DESC, o.id DESC LIMIT 1))
  WHERE id = NEW.finding_id;
END;

CREATE TRIGGER IF NOT EXISTS finding_current_decision_stamp
AFTER UPDATE OF folded_state, folded_severity ON decision FOR EACH ROW
BEGIN
  UPDATE finding SET
    current_state = NEW.folded_state,
    current_severity = coalesce(NEW.folded_severity, (
      SELECT nullif(o.severity, 'unrated') FROM occurrence o
      WHERE o.finding_id = NEW.finding_id
      ORDER BY o.created_at DESC, o.id DESC LIMIT 1))
  WHERE id = NEW.finding_id;
END;

CREATE TRIGGER IF NOT EXISTS finding_current_occurrence
AFTER INSERT ON occurrence FOR EACH ROW
BEGIN
  UPDATE finding SET current_severity = coalesce((
      SELECT d.folded_severity FROM decision d
      WHERE d.finding_id = NEW.finding_id
      ORDER BY d.created_at DESC, d.id DESC LIMIT 1),
    nullif(NEW.severity, 'unrated'))
  WHERE id = NEW.finding_id;
END;

CREATE TRIGGER IF NOT EXISTS finding_current_label
AFTER INSERT ON finding_label FOR EACH ROW WHEN NEW.taxonomy = 'category'
BEGIN
  UPDATE finding SET category = NEW.label WHERE id = NEW.finding_id AND category IS NULL;
END;

-- Existing rows: severity and category from what is recorded; state arrives with the data
-- channel's fold stamp (the decision trigger fires on it).
UPDATE finding SET current_severity = (
  SELECT nullif(o.severity, 'unrated') FROM occurrence o
  WHERE o.finding_id = finding.id ORDER BY o.created_at DESC, o.id DESC LIMIT 1);

UPDATE finding SET category = (
  SELECT l.label FROM finding_label l
  WHERE l.finding_id = finding.id AND l.taxonomy = 'category'
  ORDER BY l.created_at, l.id LIMIT 1);
