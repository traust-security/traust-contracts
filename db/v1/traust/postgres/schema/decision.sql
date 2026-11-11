-- A judgement on a finding, always on the commit it judged: its assessment's
-- commit, or repository_ref_id for a human - never both, and never two
-- "who"s (an assessment decided, or an actor did).
--
-- Append-only: corrections are new rows; restates_id points at the decision
-- being corrected. validity / resolution / evidence_grade / severity /
-- reason / source_channel are null = no answer, never "cleared"; their
-- values come from contracts - checked at
-- intake. statement_key is the hash of every judged column, normalised
-- first, so retries and old spellings are no-ops and real changes are not.
-- repository_ref_id must belong to the finding's repository - not
-- expressible as a constraint (it crosses finding); the decision service
-- enforces it.
--
-- rationale is the actor's why. A restatement (restates_id set) is an
-- administrator correcting the record: it names a person, its authority
-- (ticket), its reason and rationale, and any approvers in
-- decision_approver. auto_accept_tier marks an assessor's false positive
-- that met the auto-accept bar, so it stands without a human countersign.
CREATE TABLE IF NOT EXISTS traust.decision (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    assessment_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT,
    fixed_repository_ref_id UUID REFERENCES traust.repository_ref(id) ON DELETE RESTRICT,
    repository_ref_id UUID REFERENCES traust.repository_ref(id) ON DELETE RESTRICT,
    restates_id UUID REFERENCES traust.decision(id) ON DELETE RESTRICT,
    artifact_id UUID REFERENCES traust.artifact(id) ON DELETE RESTRICT,
    statement_key TEXT NOT NULL CHECK (statement_key <> ''),
    validity TEXT,
    resolution TEXT,
    evidence_grade TEXT,
    reason TEXT,
    severity TEXT,
    source_channel TEXT,
    actor TEXT,
    rationale TEXT,
    ticket TEXT,
    auto_accept_tier BOOLEAN NOT NULL DEFAULT FALSE,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (finding_id, statement_key),
    CHECK (assessment_id IS NOT NULL OR actor IS NOT NULL),
    CHECK (assessment_id IS NULL OR actor IS NULL),
    CHECK (assessment_id IS NULL OR repository_ref_id IS NULL),
    CHECK (restates_id IS NULL OR (actor IS NOT NULL AND ticket IS NOT NULL
        AND reason IS NOT NULL AND rationale IS NOT NULL)),
    CHECK (NOT auto_accept_tier OR (assessment_id IS NOT NULL
        AND validity IS NOT NULL AND validity = 'false_positive'))
);

-- A finding's decisions in judgement order (the findings service's fold:
-- every findings dashboard, SLA, x-vs-y).
CREATE INDEX IF NOT EXISTS idx_decision_finding_occurred
    ON traust.decision (finding_id, occurred_at);

-- Decisions since t (trends, ledger sync, list_since).
CREATE INDEX IF NOT EXISTS idx_decision_occurred
    ON traust.decision (occurred_at);

-- A work item's decisions (the remediation fold: lanes, in-flight queries).
CREATE INDEX IF NOT EXISTS idx_decision_assessment
    ON traust.decision (assessment_id)
    WHERE assessment_id IS NOT NULL;

DROP TRIGGER IF EXISTS decision_reject_mutation ON traust.decision;
CREATE TRIGGER decision_reject_mutation
BEFORE UPDATE OR DELETE ON traust.decision
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS decision_reject_truncate ON traust.decision;
CREATE TRIGGER decision_reject_truncate
BEFORE TRUNCATE ON traust.decision
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
