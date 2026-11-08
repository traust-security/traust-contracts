-- One unit of work: which asset traust materialized, on what subject, and
-- (when routed) in which lane.
--
-- Mutable table. asset is the pack asset the order materializes (pack
-- vocabulary from assets.yaml, like run_batch.kind) - what it produces.
-- lane is the routing path the router chose (contracts work-lane) - why and
-- how it was routed; null when the asset is not routed (feeds, dashboards).
-- Routed by the router (rule set) or injected as an event
-- (event_source set, contracts rescan-event-source) - never both; both null
-- = manual. state values (planned | queued | leased | succeeded | degraded
-- | refused | withheld | failed) come from contracts, to add - checked at
-- intake; withheld = dropped by the budget guard. reason is a reason code
-- (contracts, to add); detail goes to structured logs. lease_holder is set
-- exactly when state = leased. priority: lower = sooner; ties by created_at.
-- The run manifest (config digests, progress, budget verdict, degraded
-- keys) is artifact_id - per-run detail is not table rows.
-- work_item_id is the remediation assessment (work item) an order runs, for
-- an asset that runs one named item (remediate_finding); null otherwise. It is
-- last so a database upgraded with ALTER TABLE has the same column order.
-- fork_url / fork_branch: the mirror an effort runs on and its fix branch
-- (remediate_finding only) - operational facts, write-once at scheduling,
-- read-once at claim; deliberately not a repository FK: mirrors are out of
-- band, never inventory, and the durable record lives in the run's
-- remediation artifact.
CREATE TABLE IF NOT EXISTS ops_run_order (
    id TEXT NOT NULL DEFAULT (uuid()),
    run_batch_id TEXT REFERENCES ops_run_batch(id) ON DELETE RESTRICT,
    repository_id TEXT REFERENCES repository(id) ON DELETE RESTRICT,
    artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    rule TEXT,
    event_source TEXT,
    asset TEXT NOT NULL CHECK (asset <> ''),
    lane TEXT CHECK (lane <> ''),
    state TEXT NOT NULL CHECK (state <> ''),
    priority INTEGER NOT NULL,
    reason TEXT,
    requested_by TEXT NOT NULL CHECK (requested_by <> ''),
    lease_holder TEXT,
    lease_expires_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    work_item_id TEXT REFERENCES assessment(id) ON DELETE RESTRICT,
    fork_url TEXT,
    fork_branch TEXT,
    PRIMARY KEY (id),
    CHECK (rule IS NULL OR event_source IS NULL),
    CHECK ((state = 'leased') = (lease_holder IS NOT NULL)),
    CHECK ((lease_holder IS NULL) = (lease_expires_at IS NULL)),
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

-- Claim the next queued order; weekly tranche selection.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_claim
    ON ops_run_order (state, priority, created_at);

-- Reap expired leases.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_lease
    ON ops_run_order (state, lease_expires_at);

-- A tranche's orders.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_batch
    ON ops_run_order (run_batch_id)
    WHERE run_batch_id IS NOT NULL;

-- The order running a work item (the runner's lookup; RESTRICT checks).
CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON ops_run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;

-- A repository's planned / running orders (router dedupe).
CREATE INDEX IF NOT EXISTS idx_ops_run_order_repository_state
    ON ops_run_order (repository_id, state)
    WHERE repository_id IS NOT NULL;

-- An asset's orders by state: open subjects, and subjects finished since a time (the engine's
-- open-order, freshness and re-route checks every tick). repository_id makes them index-only.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON ops_run_order (asset, state, finished_at, repository_id);

-- The ops feed: orders changed after an (updated_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_updated
    ON ops_run_order (updated_at, id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS ops_run_order_touch
AFTER UPDATE ON ops_run_order FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE ops_run_order SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;

-- An order runs a work item of its own repository: the work item's commit
-- (assessment -> repository_ref) is on the repository the order names.
CREATE TRIGGER IF NOT EXISTS ops_run_order_work_item_of_repository
BEFORE INSERT ON ops_run_order
WHEN NEW.work_item_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM assessment a JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id AND r.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_run_order.work_item_id is not a work item of its repository');
END;

CREATE TRIGGER IF NOT EXISTS ops_run_order_work_item_of_repository_update
BEFORE UPDATE OF work_item_id, repository_id ON ops_run_order
WHEN NEW.work_item_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM assessment a JOIN repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id AND r.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'ops_run_order.work_item_id is not a work item of its repository');
END;

-- An artifact names the order whose run recorded it only for an assessment
-- that order owns: the work item it runs, or an assessment it produced. An
-- imported artifact (no assessment) names none. Artifacts never change, so
-- the insert is checked.
CREATE TRIGGER IF NOT EXISTS ops_artifact_order_owns_its_assessment
BEFORE INSERT ON artifact
WHEN NEW.run_order_id IS NOT NULL
  AND (NEW.assessment_id IS NULL OR (
    NOT EXISTS (
      SELECT 1 FROM ops_run_order o
      WHERE o.id = NEW.run_order_id AND o.work_item_id = NEW.assessment_id)
    AND NOT EXISTS (
      SELECT 1 FROM assessment a
      WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id)))
BEGIN
  SELECT RAISE(ABORT, 'artifact.run_order_id owns neither its work item nor its assessment');
END;

-- ...and an order an artifact credits keeps the work item it ran.
CREATE TRIGGER IF NOT EXISTS ops_credited_order_keeps_its_work_item
BEFORE UPDATE OF work_item_id ON ops_run_order
WHEN NEW.work_item_id IS NOT OLD.work_item_id AND EXISTS (
    SELECT 1 FROM artifact r
    WHERE r.run_order_id = OLD.id AND r.assessment_id = OLD.work_item_id)
BEGIN
  SELECT RAISE(ABORT, 'a run_order credited with a report keeps its work item');
END;

-- ...and a commit whose work item an order runs stays on that repository:
-- assessments never change, so only the ref moving could break the pairing.
CREATE TRIGGER IF NOT EXISTS ops_ref_of_ordered_work_item_stays
BEFORE UPDATE OF repository_id ON repository_ref
WHEN EXISTS (
    SELECT 1 FROM ops_run_order o JOIN assessment a ON a.id = o.work_item_id
    WHERE a.repository_ref_id = NEW.id AND o.repository_id IS NOT NEW.repository_id)
BEGIN
  SELECT RAISE(ABORT, 'a repository_ref holding an ordered work item keeps its repository');
END;
