-- A release of a product: versioned cut of the product's components.
--
-- Mutable table. Natural key (product_id, version); payload names are
-- releases, never products.
CREATE TABLE IF NOT EXISTS release (
    id TEXT NOT NULL DEFAULT (uuid()),
    product_id TEXT NOT NULL REFERENCES product(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (version <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (product_id, version)
);

-- The ops feed: releases recorded after a (created_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_release_created
    ON release (created_at, id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS release_touch
AFTER UPDATE ON release FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE release SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
