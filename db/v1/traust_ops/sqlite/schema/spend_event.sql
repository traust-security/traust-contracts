-- What a run cost: one row per chargeable event, priced at the time.
--
-- Append-only. provider is a registered model provider; skill a registered
-- skill name - deployment data, checked at intake. run_order_id null =
-- unattributed. lane is the order's lane at the time of spend (null when
-- unattributed or not routed), copied so lane rollups read this table alone:
-- budget month-to-date runs on every admission tick. Retention: rolled up
-- monthly after N months.
CREATE TABLE IF NOT EXISTS ops_spend_event (
    id TEXT NOT NULL DEFAULT (uuid()),
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    repository_id TEXT REFERENCES repository(id) ON DELETE RESTRICT,
    -- Raw supplied reference, retained even when canonical identity is unresolved.
    repository_label TEXT,
    loc INTEGER CHECK (loc IS NULL OR (typeof(loc) = 'integer' AND loc >= 0)),
    batch TEXT,
    note TEXT,
    provider TEXT NOT NULL CHECK (provider <> ''),
    model TEXT NOT NULL CHECK (model <> ''),
    skill TEXT,
    lane TEXT CHECK (lane <> ''),
    tokens_in INTEGER NOT NULL,
    tokens_out INTEGER NOT NULL,
    cost_usd NUMERIC NOT NULL,
    occurred_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    CHECK (tokens_in >= 0 AND tokens_out >= 0 AND cost_usd >= 0)
);

-- Spend for an order (spend per scan, lane cost).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_run_order
    ON ops_spend_event (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- Spend in a window (spend dashboard, budget month-to-date).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_occurred
    ON ops_spend_event (occurred_at);

-- A canonical repository's spend in a window, independent of order attribution.
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_repository_occurred
    ON ops_spend_event (repository_id, occurred_at)
    WHERE repository_id IS NOT NULL;

-- A lane's spend in a window (budget month-to-date, lane cost).
CREATE INDEX IF NOT EXISTS idx_ops_spend_event_lane_occurred
    ON ops_spend_event (lane, occurred_at)
    WHERE lane IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS ops_spend_event_lane_of_order
BEFORE INSERT ON ops_spend_event
WHEN NEW.lane IS NOT (SELECT lane FROM ops_run_order WHERE id = NEW.run_order_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_spend_event.lane is not the lane of its run_order');
END;

CREATE TRIGGER IF NOT EXISTS ops_spend_event_reject_update
BEFORE UPDATE ON ops_spend_event BEGIN
  SELECT RAISE(ABORT, 'ops_spend_event rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ops_spend_event_reject_delete
BEFORE DELETE ON ops_spend_event BEGIN
  SELECT RAISE(ABORT, 'ops_spend_event rows are append-only');
END;
