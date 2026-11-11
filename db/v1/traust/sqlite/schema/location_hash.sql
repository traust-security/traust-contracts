CREATE TABLE IF NOT EXISTS location_hash (
    id TEXT NOT NULL DEFAULT (uuid()),
    location_id TEXT NOT NULL REFERENCES location(id) ON DELETE RESTRICT,
    algorithm TEXT NOT NULL CHECK (typeof(algorithm) = 'text' AND algorithm <> ''),
    digest TEXT NOT NULL CHECK (typeof(digest) = 'text' AND digest <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (location_id, algorithm),
    CHECK (algorithm <> 'file-bytes-sha256/v1' OR
        (length(digest) = 64 AND instr(digest, char(0)) = 0
            AND digest NOT GLOB '*[^0-9a-f]*'))
);

-- SQLite REPLACE can bypass DELETE triggers when recursive_triggers is disabled.
CREATE TRIGGER IF NOT EXISTS location_hash_reject_replacement
BEFORE INSERT ON location_hash
WHEN EXISTS (SELECT 1 FROM location_hash
    WHERE id = NEW.id OR (location_id = NEW.location_id AND algorithm = NEW.algorithm)) BEGIN
    SELECT RAISE(ABORT, 'location_hash rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS location_hash_reject_update
BEFORE UPDATE ON location_hash BEGIN
    SELECT RAISE(ABORT, 'location_hash rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS location_hash_reject_delete
BEFORE DELETE ON location_hash BEGIN
    SELECT RAISE(ABORT, 'location_hash rows are append-only');
END;
