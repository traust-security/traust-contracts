-- A product in the inventory: the top of the
-- product -> release -> component -> repository_ref -> repository spine.
--
-- Mutable table: database-generated UUID v4 identity, one natural key (slug).
-- Consumers join by id; slug is the stable human handle.
CREATE TABLE IF NOT EXISTS product (
    id TEXT NOT NULL DEFAULT (uuid()),
    slug TEXT NOT NULL CHECK (slug <> ''),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (slug)
);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS product_touch
AFTER UPDATE ON product FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE product SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
