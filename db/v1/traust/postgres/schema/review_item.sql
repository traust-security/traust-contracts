-- Something a human must look at, and the decision that answered it.
--
-- Mutable table. reason and status values come from contracts (merged
-- review reasons; pending | accepted | rejected | closed_unreviewed) -
-- checked at intake.
CREATE TABLE IF NOT EXISTS traust.review_item (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    decision_id UUID REFERENCES traust.decision(id) ON DELETE RESTRICT,
    resolved_by_decision_id UUID REFERENCES traust.decision(id) ON DELETE RESTRICT,
    reason TEXT,
    status TEXT NOT NULL CHECK (status <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

DROP TRIGGER IF EXISTS review_item_touch ON traust.review_item;
CREATE TRIGGER review_item_touch
BEFORE UPDATE ON traust.review_item
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();

-- A finding's review items; the pending review queue.
CREATE INDEX IF NOT EXISTS idx_review_item_finding
    ON traust.review_item (finding_id);
CREATE INDEX IF NOT EXISTS idx_review_item_pending
    ON traust.review_item (created_at)
    WHERE status = 'pending';
