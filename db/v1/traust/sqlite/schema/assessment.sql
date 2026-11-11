-- What was examined: one run of one assessor over a repository_ref (or an
-- image), at a point in time.
--
-- Append-only: id, created_at and a reject-mutation trigger. kind and status
-- classify, so their values come from contracts (assessment-kind and
-- assessment-status, to add) - checked at intake, not database constraints.
-- status degraded = ran without a usable input (e.g. no scanner DB), never
-- read as clean. assessor is a principal id: skill:<name> | tool:<name> |
-- user:<id>. run_order_id: the order that produced it (ops namespace);
-- null = manual / imported. baseline_assessment_id: what a diff_scan
-- compared against.
CREATE TABLE IF NOT EXISTS assessment (
    id TEXT NOT NULL DEFAULT (uuid()),
    repository_ref_id TEXT NOT NULL REFERENCES repository_ref(id) ON DELETE RESTRICT,
    image_id TEXT REFERENCES image(id) ON DELETE RESTRICT,
    baseline_assessment_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT,
    run_order_id TEXT REFERENCES ops_run_order(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind <> ''),
    status TEXT NOT NULL CHECK (status <> ''),
    assessor TEXT NOT NULL CHECK (assessor <> ''),
    assessor_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- Latest assessment of a kind per ref (census, freshness,
-- default-branch cohort, artifact lane, LoC).
CREATE INDEX IF NOT EXISTS idx_assessment_ref_kind_occurred
    ON assessment (repository_ref_id, kind, occurred_at);

-- What an order produced (spend per scan, lane cost).
CREATE INDEX IF NOT EXISTS idx_assessment_run_order
    ON assessment (run_order_id)
    WHERE run_order_id IS NOT NULL;

-- The ops feed: assessments recorded after a (created_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_assessment_created
    ON assessment (created_at, id);

CREATE TRIGGER IF NOT EXISTS assessment_reject_update
BEFORE UPDATE ON assessment BEGIN
  SELECT RAISE(ABORT, 'assessment rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS assessment_reject_delete
BEFORE DELETE ON assessment BEGIN
  SELECT RAISE(ABORT, 'assessment rows are append-only');
END;
