-- Explicit additive upgrade for spend events missing adoption metadata.
-- Apply only when all five columns are absent. Old events retain null metadata;
-- no canonical identity, raw reference, or line count is inferred.
BEGIN;

ALTER TABLE ops_spend_event
    ADD COLUMN repository_id TEXT REFERENCES repository(id) ON DELETE RESTRICT;
ALTER TABLE ops_spend_event
    ADD COLUMN repository_label TEXT;
ALTER TABLE ops_spend_event
    ADD COLUMN loc INTEGER CHECK (loc IS NULL OR (typeof(loc) = 'integer' AND loc >= 0));
ALTER TABLE ops_spend_event
    ADD COLUMN batch TEXT;
ALTER TABLE ops_spend_event
    ADD COLUMN note TEXT;

CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON ops_spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;

-- An attributed event charges the repository its order runs on.
CREATE TRIGGER IF NOT EXISTS ops_spend_event_repository_of_order
BEFORE INSERT ON ops_spend_event
WHEN NEW.run_order_id IS NOT NULL AND NEW.repository_id IS NOT NULL AND NEW.repository_id IS NOT
    (SELECT repository_id FROM ops_run_order WHERE id = NEW.run_order_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_spend_event.repository_id is not the repository of its run_order');
END;

-- ...and an order a charged event names keeps its repository.
CREATE TRIGGER IF NOT EXISTS ordered_repository_of_charged_spend_stays
BEFORE UPDATE OF repository_id ON ops_run_order
WHEN NEW.repository_id IS NOT OLD.repository_id AND EXISTS (
    SELECT 1 FROM ops_spend_event e
    WHERE e.run_order_id = OLD.id AND e.repository_id IS NOT NULL
      AND e.repository_id IS NOT NEW.repository_id
)
BEGIN
  SELECT RAISE(ABORT, 'ops_run_order carries charged spend on its repository');
END;
COMMIT;
