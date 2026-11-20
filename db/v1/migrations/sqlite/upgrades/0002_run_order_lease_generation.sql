-- Zero means no fenced claim has been issued, including on a legacy lease.
-- Leave its holder and expiry intact: after expiry, reclaim issues generation 1.
ALTER TABLE ops_run_order
    ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0
    CHECK (typeof(lease_generation) = 'integer' AND lease_generation >= 0);

-- The worker that completed this generation; unknown on historical rows.
ALTER TABLE ops_run_order ADD COLUMN completed_by TEXT;
