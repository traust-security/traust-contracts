-- Zero means no fenced claim has been issued, including on a legacy lease.
-- Leave its holder and expiry intact: after expiry, reclaim issues generation 1.
ALTER TABLE traust_ops.run_order
    ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    -- The worker that completed this generation; unknown on historical rows.
    ADD COLUMN completed_by TEXT;
