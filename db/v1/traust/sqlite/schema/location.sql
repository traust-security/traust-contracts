-- Where an occurrence sits: path relative to the occurrence's commit.
--
-- Append-only. line_start / line_end are null together (null = whole file);
-- single line = start. language is set from the path at intake (Linguist
-- map, pinned) - SARIF sourceLanguage; symbol is the enclosing function /
-- method from the symbol index - SARIF logicalLocations.
CREATE TABLE IF NOT EXISTS location (
    id TEXT NOT NULL DEFAULT (uuid()),
    occurrence_id TEXT NOT NULL REFERENCES occurrence(id) ON DELETE RESTRICT,
    path TEXT NOT NULL CHECK (path <> ''),
    line_start INTEGER,
    line_end INTEGER,
    language TEXT,
    symbol TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    CHECK (line_start IS NULL OR line_start >= 1),
    CHECK ((line_start IS NULL) = (line_end IS NULL)),
    CHECK (line_end IS NULL OR line_end >= line_start)
);

-- One location per occurrence, path and line range; whole-file locations
-- dedupe on path alone.
CREATE UNIQUE INDEX IF NOT EXISTS uq_location_range
    ON location (occurrence_id, path, line_start, line_end)
    WHERE line_start IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_location_file
    ON location (occurrence_id, path)
    WHERE line_start IS NULL;

-- Precedents: the same enclosing function in any repository (the reader then
-- compares vendor-normalized paths). Most locations have no symbol.
DROP INDEX IF EXISTS idx_location_symbol;
CREATE INDEX IF NOT EXISTS idx_location_symbol_page
    ON location (symbol, id)
    WHERE symbol IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS location_reject_update
BEFORE UPDATE ON location BEGIN
  SELECT RAISE(ABORT, 'location rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS location_reject_delete
BEFORE DELETE ON location BEGIN
  SELECT RAISE(ABORT, 'location rows are append-only');
END;
