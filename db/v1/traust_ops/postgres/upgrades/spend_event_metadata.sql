-- Explicit additive upgrade for spend events missing adoption metadata.
-- Apply only when all five columns are absent, in a caller-owned transaction.
-- Old events retain null metadata; no identity, reference, or count is inferred.
ALTER TABLE traust_ops.spend_event
    ADD COLUMN repository_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    ADD COLUMN repository_label TEXT,
    ADD COLUMN loc BIGINT CHECK (loc >= 0),
    ADD COLUMN batch TEXT,
    ADD COLUMN note TEXT;

CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON traust_ops.spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;

-- An attributed event charges the repository its order runs on: repository
-- rollups then read this table alone. The order row is locked FOR SHARE, so a
-- concurrent change of run_order.repository_id either waits for this insert
-- (and re-fires its own pairing check below) or has already committed and is
-- read here.
CREATE OR REPLACE FUNCTION traust_ops.spend_event_repository_of_order()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    charged UUID;
BEGIN
    IF NEW.run_order_id IS NULL OR NEW.repository_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT o.repository_id INTO charged
    FROM traust_ops.run_order o
    WHERE o.id = NEW.run_order_id
    FOR SHARE OF o;
    IF FOUND AND charged IS DISTINCT FROM NEW.repository_id THEN
        RAISE EXCEPTION 'spend_event.repository_id % is not the repository of run_order %',
            NEW.repository_id, NEW.run_order_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ops_spend_event_repository_of_order ON traust_ops.spend_event;
CREATE TRIGGER ops_spend_event_repository_of_order
BEFORE INSERT ON traust_ops.spend_event
FOR EACH ROW EXECUTE FUNCTION traust_ops.spend_event_repository_of_order();

-- ...and an order a charged event names keeps its repository.
CREATE OR REPLACE FUNCTION traust_ops.ordered_repository_of_charged_spend_stays()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.repository_id IS DISTINCT FROM OLD.repository_id AND EXISTS (
        SELECT 1 FROM traust_ops.spend_event e
        WHERE e.run_order_id = OLD.id AND e.repository_id IS NOT NULL
            AND e.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'run_order % carries charged spend on repository %',
            OLD.id, OLD.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ordered_repository_of_charged_spend_stays ON traust_ops.run_order;
CREATE TRIGGER ordered_repository_of_charged_spend_stays
BEFORE UPDATE OF repository_id ON traust_ops.run_order
FOR EACH ROW WHEN (NEW.repository_id IS DISTINCT FROM OLD.repository_id)
EXECUTE FUNCTION traust_ops.ordered_repository_of_charged_spend_stays();
