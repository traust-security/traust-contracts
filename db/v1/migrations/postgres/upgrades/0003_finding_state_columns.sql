-- The finding state projection: the folded state carried on each decision row (plan schema-performance-audit, decision B; Young's ledger running-balance).
-- destructive: recreate the decision append-only guard (its baseline name on
-- postgres) with a projection carve-out — an update that changes anything but
-- the folded_* columns still aborts.
DROP TRIGGER IF EXISTS decision_reject_mutation ON traust.decision;

CREATE TRIGGER decision_reject_mutation
BEFORE UPDATE ON traust.decision
FOR EACH ROW
WHEN (
       NEW.id IS DISTINCT FROM OLD.id
    OR NEW.finding_id IS DISTINCT FROM OLD.finding_id
    OR NEW.assessment_id IS DISTINCT FROM OLD.assessment_id
    OR NEW.fixed_repository_ref_id IS DISTINCT FROM OLD.fixed_repository_ref_id
    OR NEW.repository_ref_id IS DISTINCT FROM OLD.repository_ref_id
    OR NEW.restates_id IS DISTINCT FROM OLD.restates_id
    OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id
    OR NEW.statement_key IS DISTINCT FROM OLD.statement_key
    OR NEW.validity IS DISTINCT FROM OLD.validity
    OR NEW.resolution IS DISTINCT FROM OLD.resolution
    OR NEW.evidence_grade IS DISTINCT FROM OLD.evidence_grade
    OR NEW.reason IS DISTINCT FROM OLD.reason
    OR NEW.severity IS DISTINCT FROM OLD.severity
    OR NEW.source_channel IS DISTINCT FROM OLD.source_channel
    OR NEW.actor IS DISTINCT FROM OLD.actor
    OR NEW.rationale IS DISTINCT FROM OLD.rationale
    OR NEW.ticket IS DISTINCT FROM OLD.ticket
    OR NEW.auto_accept_tier IS DISTINCT FROM OLD.auto_accept_tier
    OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
)
EXECUTE FUNCTION traust.reject_mutation();

ALTER TABLE traust.decision
    ADD COLUMN folded_state TEXT CHECK (
        folded_state IS NULL
        OR folded_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE traust.decision
    ADD COLUMN folded_severity TEXT CHECK (
        folded_severity IS NULL
        OR folded_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

ALTER TABLE traust.decision
    ADD COLUMN folded_decided BOOLEAN;

ALTER TABLE traust.decision
    ADD COLUMN folded_proven BOOLEAN;

ALTER TABLE traust.decision
    ADD COLUMN folded_unverified BOOLEAN;

ALTER TABLE traust.decision
    ADD COLUMN folded_policy_version TEXT;

ALTER TABLE traust.finding
    ADD COLUMN first_seen TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_decision_finding_occurred
    ON traust.decision (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON traust_ops.run_order (asset, state, finished_at, repository_id);
