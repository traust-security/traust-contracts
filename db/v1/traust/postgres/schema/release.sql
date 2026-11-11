-- A release of a product: versioned cut of the product's components.
--
-- Mutable table. Natural key (product_id, version); payload names are
-- releases, never products.
CREATE TABLE IF NOT EXISTS traust.release (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES traust.product(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (version <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (product_id, version)
);

-- The ops feed: releases recorded after a (created_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_release_created
    ON traust.release (created_at, id);

DROP TRIGGER IF EXISTS release_touch ON traust.release;
CREATE TRIGGER release_touch
BEFORE UPDATE ON traust.release
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
