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

-- The finding's current answer, stamped by the write doors (state and severity on each
-- decision, severity on each occurrence, the first category label): dashboards read one
-- indexed row per finding instead of the latest decision, occurrence and label per read.
ALTER TABLE traust.finding
    ADD COLUMN current_state TEXT CHECK (
        current_state IS NULL OR current_state IN ('open', 'hardening', 'accepted', 'resolved', 'false_positive')
    );

ALTER TABLE traust.finding
    ADD COLUMN current_severity TEXT CHECK (
        current_severity IS NULL OR current_severity IN ('critical', 'high', 'medium', 'low', 'informational')
    );

ALTER TABLE traust.finding
    ADD COLUMN category TEXT;

CREATE INDEX IF NOT EXISTS idx_finding_repository_current
    ON traust.finding (repository_id, current_state, current_severity);

CREATE INDEX IF NOT EXISTS idx_decision_finding_occurred
    ON traust.decision (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON traust_ops.run_order (asset, state, finished_at, repository_id);

-- The finding's current answer is kept by triggers, so no writer can leave it behind: a
-- decision (inserted, or its fold stamped) sets state and severity, an occurrence sets
-- severity unless the latest decision rated it, the first category label sets category.
CREATE OR REPLACE FUNCTION traust.finding_current_from_decision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE traust.finding SET
        current_state = NEW.folded_state,
        current_severity = coalesce(NEW.folded_severity, (
            SELECT nullif(o.severity, 'unrated') FROM traust.occurrence o
            WHERE o.finding_id = NEW.finding_id
            ORDER BY o.created_at DESC, o.id DESC LIMIT 1))
    WHERE id = NEW.finding_id;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS finding_current_decision ON traust.decision;

CREATE TRIGGER finding_current_decision
AFTER INSERT OR UPDATE OF folded_state, folded_severity ON traust.decision
FOR EACH ROW EXECUTE FUNCTION traust.finding_current_from_decision();

CREATE OR REPLACE FUNCTION traust.finding_current_from_occurrence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE traust.finding SET current_severity = coalesce((
            SELECT d.folded_severity FROM traust.decision d
            WHERE d.finding_id = NEW.finding_id
            ORDER BY d.created_at DESC, d.id DESC LIMIT 1),
        nullif(NEW.severity, 'unrated'))
    WHERE id = NEW.finding_id;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS finding_current_occurrence ON traust.occurrence;

CREATE TRIGGER finding_current_occurrence
AFTER INSERT ON traust.occurrence
FOR EACH ROW EXECUTE FUNCTION traust.finding_current_from_occurrence();

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

-- Existing rows: severity and category from what is recorded; state arrives with the data
-- channel's fold stamp (the decision trigger fires on it).
UPDATE traust.finding f SET current_severity = o.severity
FROM (
    SELECT DISTINCT ON (finding_id) finding_id, nullif(severity, 'unrated') AS severity
    FROM traust.occurrence ORDER BY finding_id, created_at DESC, id DESC
) o
WHERE o.finding_id = f.id;

UPDATE traust.finding f SET category = c.label
FROM (
    SELECT DISTINCT ON (finding_id) finding_id, label FROM traust.finding_label
    WHERE taxonomy = 'category' ORDER BY finding_id, created_at, id
) c
WHERE c.finding_id = f.id;
