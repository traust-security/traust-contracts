-- A named batch of orders: one tranche per (kind, period), e.g. one
-- drain_tranche per ISO week (2026-W31).
--
-- Mutable table. kind is a pack asset name from assets.yaml (drain_tranche,
-- router_run, feeds_refresh) - pack vocabulary, never a core enum, checked
-- at intake.
CREATE TABLE IF NOT EXISTS traust_ops.run_batch (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL CHECK (kind <> ''),
    period TEXT NOT NULL CHECK (period <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (kind, period)
);

DROP TRIGGER IF EXISTS run_batch_touch ON traust_ops.run_batch;
CREATE TRIGGER run_batch_touch
BEFORE UPDATE ON traust_ops.run_batch
FOR EACH ROW EXECUTE FUNCTION traust_ops.touch_updated_at();
