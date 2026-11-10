-- What a run cost: one row per chargeable event, priced at the time.
--
-- Append-only. provider is a registered model provider; skill a registered
-- skill name - deployment data, checked at intake. run_order_id null =
-- unattributed. lane is the order's lane at the time of spend (null when
-- unattributed or not routed), copied so lane rollups read this table alone:
-- budget month-to-date runs on every admission tick. Retention: rolled up
-- monthly after N months.
CREATE TABLE IF NOT EXISTS traust_ops.spend_event (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_order_id UUID REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT,
    repository_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    -- Raw supplied reference, retained even when canonical identity is unresolved.
    repository_label TEXT,
    loc BIGINT CHECK (loc >= 0),
    batch TEXT,
    note TEXT,
    provider TEXT NOT NULL CHECK (provider <> ''),
    model TEXT NOT NULL CHECK (model <> ''),
    skill TEXT,
    lane TEXT CHECK (lane <> ''),
    tokens_in BIGINT NOT NULL,
    tokens_out BIGINT NOT NULL,
    cost_usd NUMERIC NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    CHECK (tokens_in >= 0 AND tokens_out >= 0 AND cost_usd >= 0)
);

-- Spend for an order (spend per scan, lane cost).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_run_order
    ON traust_ops.spend_event (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- Spend in a window (spend dashboard, budget month-to-date).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_occurred
    ON traust_ops.spend_event (occurred_at);

-- A canonical repository's spend in a window, independent of order attribution.
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON traust_ops.spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;

-- A lane's spend in a window (budget month-to-date, lane cost).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_lane_occurred
    ON traust_ops.spend_event (lane, occurred_at)
    WHERE lane IS NOT NULL;

CREATE OR REPLACE FUNCTION traust_ops.spend_event_lane_of_order()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lane IS DISTINCT FROM
        (SELECT lane FROM traust_ops.run_order WHERE id = NEW.run_order_id) THEN
        RAISE EXCEPTION 'spend_event.lane % is not the lane of run_order %',
            NEW.lane, NEW.run_order_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ops_spend_event_lane_of_order ON traust_ops.spend_event;
CREATE TRIGGER ops_spend_event_lane_of_order
BEFORE INSERT ON traust_ops.spend_event
FOR EACH ROW EXECUTE FUNCTION traust_ops.spend_event_lane_of_order();

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

-- ...and an order a charged event names keeps its repository: the pairing is
-- checked on a fresh snapshot once this insert's lock is released.
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

DROP TRIGGER IF EXISTS ops_spend_event_reject_mutation ON traust_ops.spend_event;
CREATE TRIGGER ops_spend_event_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ops.spend_event
FOR EACH ROW EXECUTE FUNCTION traust_ops.reject_mutation();

DROP TRIGGER IF EXISTS ops_spend_event_reject_truncate ON traust_ops.spend_event;
CREATE TRIGGER ops_spend_event_reject_truncate
BEFORE TRUNCATE ON traust_ops.spend_event
FOR EACH STATEMENT EXECUTE FUNCTION traust_ops.reject_mutation();
