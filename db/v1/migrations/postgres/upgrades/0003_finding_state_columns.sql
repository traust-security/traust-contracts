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

-- The finding's current answer: state, effective severity and decided, stamped by core's
-- write doors from the fold (finding_state, effective_severity) on every finding, decision
-- and occurrence write; the first category label, copied by a trigger. A new finding is
-- identified - open, undecided - until a judgment says otherwise; NULL severity is unrated.
ALTER TABLE traust.finding
    ADD COLUMN current_state TEXT NOT NULL DEFAULT 'open' CHECK (
        current_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE traust.finding
    ADD COLUMN current_severity TEXT CHECK (
        current_severity IS NULL OR current_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

ALTER TABLE traust.finding
    ADD COLUMN current_decided BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE traust.finding
    ADD COLUMN category TEXT;

CREATE INDEX IF NOT EXISTS idx_finding_repository_current
    ON traust.finding (repository_id, current_state, current_severity);

CREATE INDEX IF NOT EXISTS idx_decision_finding_occurred
    ON traust.decision (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON traust_ops.run_order (asset, state, finished_at, repository_id);

-- updated_at tracks the finding's own record, not its derived current answer: the touch
-- fires only when one of the finding's own columns is set.
DROP TRIGGER IF EXISTS finding_touch ON traust.finding;

CREATE TRIGGER finding_touch
BEFORE UPDATE OF repository_id, advisory_id, advisory_match, fingerprint_algo, fingerprint, kind, title ON traust.finding
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();

-- The first category label is a copy, not a rule: a trigger keeps it.
CREATE OR REPLACE FUNCTION traust.finding_current_from_label() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE traust.finding SET category = NEW.label
    WHERE id = NEW.finding_id AND category IS NULL;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS finding_current_label ON traust.finding_label;

CREATE TRIGGER finding_current_label
AFTER INSERT ON traust.finding_label
FOR EACH ROW WHEN (NEW.taxonomy = 'category')
EXECUTE FUNCTION traust.finding_current_from_label();

-- Existing rows: the first category label; state, severity and decided arrive with core's
-- data channel, which restamps every finding from the fold.
UPDATE traust.finding f SET category = c.label
FROM (
    SELECT DISTINCT ON (finding_id) finding_id, label FROM traust.finding_label
    WHERE taxonomy = 'category' ORDER BY finding_id, created_at, id
) c
WHERE c.finding_id = f.id;
