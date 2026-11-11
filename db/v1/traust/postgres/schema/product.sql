-- A product in the inventory: the top of the
-- product -> release -> component -> repository_ref -> repository spine.
--
-- Mutable table: database-generated UUID v4 identity, one natural key (slug).
-- Consumers join by id; slug is the stable human handle.
CREATE TABLE IF NOT EXISTS traust.product (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL CHECK (slug <> ''),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (slug)
);

DROP TRIGGER IF EXISTS product_touch ON traust.product;
CREATE TRIGGER product_touch
BEFORE UPDATE ON traust.product
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
