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
CREATE TABLE IF NOT EXISTS traust_ops.run_order (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_batch_id UUID REFERENCES traust_ops.run_batch(id) ON DELETE RESTRICT,
    repository_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    artifact_id UUID REFERENCES traust.artifact(id) ON DELETE RESTRICT,
    rule TEXT,
    event_source TEXT,
    asset TEXT NOT NULL CHECK (asset <> ''),
    lane TEXT CHECK (lane <> ''),
    state TEXT NOT NULL CHECK (state <> ''),
    priority INTEGER NOT NULL,
    reason TEXT,
    requested_by TEXT NOT NULL CHECK (requested_by <> ''),
    lease_holder TEXT,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    work_item_id UUID REFERENCES traust.assessment(id) ON DELETE RESTRICT,
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
    ON traust_ops.run_order (state, priority, created_at);

-- Reap expired leases.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_lease
    ON traust_ops.run_order (state, lease_expires_at);

-- A tranche's orders.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_batch
    ON traust_ops.run_order (run_batch_id)
    WHERE run_batch_id IS NOT NULL;

-- The order running a work item (the runner's lookup; RESTRICT checks).
CREATE INDEX IF NOT EXISTS idx_ops_run_order_work_item
    ON traust_ops.run_order (work_item_id)
    WHERE work_item_id IS NOT NULL;

-- A repository's planned / running orders (router dedupe).
CREATE INDEX IF NOT EXISTS idx_ops_run_order_repository_state
    ON traust_ops.run_order (repository_id, state)
    WHERE repository_id IS NOT NULL;

-- An asset's orders by state: open subjects, and subjects finished since a time (the engine's
-- open-order, freshness and re-route checks every tick). repository_id makes them index-only.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_asset_state
    ON traust_ops.run_order (asset, state, finished_at, repository_id);

-- The ops feed: orders changed after an (updated_at, id) cursor, oldest first.
CREATE INDEX IF NOT EXISTS idx_ops_run_order_updated
    ON traust_ops.run_order (updated_at, id);

-- Cross-namespace links, closing the cycle: assessment.run_order_id and
-- artifact.run_order_id -> traust_ops.run_order. SQLite carries this FK inline (parent existence is
-- not checked at CREATE); Postgres cannot, because run_order references
-- storage tables back (repository, artifact) - the namespaces are mutually
-- recursive, and storage bootstraps first.
ALTER TABLE traust.assessment DROP CONSTRAINT IF EXISTS assessment_run_order_id_fkey;
ALTER TABLE traust.assessment
    ADD CONSTRAINT assessment_run_order_id_fkey
    FOREIGN KEY (run_order_id) REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT;
ALTER TABLE traust.artifact DROP CONSTRAINT IF EXISTS artifact_run_order_id_fkey;
ALTER TABLE traust.artifact
    ADD CONSTRAINT artifact_run_order_id_fkey
    FOREIGN KEY (run_order_id) REFERENCES traust_ops.run_order(id) ON DELETE RESTRICT;

DROP TRIGGER IF EXISTS run_order_touch ON traust_ops.run_order;
CREATE TRIGGER run_order_touch
BEFORE UPDATE ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.touch_updated_at();

-- An order runs a work item of its own repository: the work item's commit
-- (assessment -> repository_ref) is on the repository the order names.
-- FOR SHARE on the ref makes a concurrent move of it wait for this order (and
-- this order wait for a move in flight, then read where it went).
CREATE OR REPLACE FUNCTION traust_ops.run_order_work_item_of_repository()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    owner UUID;
BEGIN
    IF NEW.work_item_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT r.repository_id INTO owner
    FROM traust.assessment a JOIN traust.repository_ref r ON r.id = a.repository_ref_id
    WHERE a.id = NEW.work_item_id
    FOR SHARE OF r;
    IF FOUND AND owner IS DISTINCT FROM NEW.repository_id THEN
        RAISE EXCEPTION 'run_order.work_item_id % is not a work item of repository %',
            NEW.work_item_id, NEW.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS run_order_work_item_of_repository ON traust_ops.run_order;
CREATE TRIGGER run_order_work_item_of_repository
BEFORE INSERT OR UPDATE OF work_item_id, repository_id ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.run_order_work_item_of_repository();

-- An artifact names the order whose run recorded it only for an assessment
-- that order owns: the work item it runs, or an assessment it produced. An
-- imported artifact (no assessment) names none. Artifacts never change, so
-- the insert is checked; the order's row is locked so a concurrent change of
-- its work item waits.
CREATE OR REPLACE FUNCTION traust_ops.artifact_order_owns_its_assessment()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.run_order_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.assessment_id IS NOT NULL AND (EXISTS (
        SELECT 1 FROM traust_ops.run_order o
        WHERE o.id = NEW.run_order_id AND o.work_item_id = NEW.assessment_id
        FOR SHARE
    ) OR EXISTS (
        SELECT 1 FROM traust.assessment a
        WHERE a.id = NEW.assessment_id AND a.run_order_id = NEW.run_order_id
    )) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'artifact.run_order_id % owns neither its work item nor assessment %',
        NEW.run_order_id, NEW.assessment_id USING ERRCODE = 'check_violation';
END $$;

DROP TRIGGER IF EXISTS artifact_order_owns_its_assessment ON traust.artifact;
CREATE TRIGGER artifact_order_owns_its_assessment
BEFORE INSERT ON traust.artifact
FOR EACH ROW EXECUTE FUNCTION traust_ops.artifact_order_owns_its_assessment();

-- ...and an order an artifact credits keeps the work item it ran.
CREATE OR REPLACE FUNCTION traust_ops.credited_order_keeps_its_work_item()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.work_item_id IS DISTINCT FROM OLD.work_item_id AND EXISTS (
        SELECT 1 FROM traust.artifact r
        WHERE r.run_order_id = OLD.id AND r.assessment_id = OLD.work_item_id
    ) THEN
        RAISE EXCEPTION 'run_order % is credited with a report on work item %',
            OLD.id, OLD.work_item_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS credited_order_keeps_its_work_item ON traust_ops.run_order;
CREATE TRIGGER credited_order_keeps_its_work_item
BEFORE UPDATE OF work_item_id ON traust_ops.run_order
FOR EACH ROW EXECUTE FUNCTION traust_ops.credited_order_keeps_its_work_item();

-- ...and a commit whose work item an order runs stays on that repository:
-- assessments never change, so only the ref moving could break the pairing.
-- This runs once the ref is locked, on a fresh snapshot, so it sees an order
-- committed while it waited.
CREATE OR REPLACE FUNCTION traust_ops.ref_of_ordered_work_item_stays()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM traust_ops.run_order o
        JOIN traust.assessment a ON a.id = o.work_item_id
        WHERE a.repository_ref_id = NEW.id AND o.repository_id IS DISTINCT FROM NEW.repository_id
    ) THEN
        RAISE EXCEPTION 'repository_ref % holds a work item ordered on repository %',
            NEW.id, OLD.repository_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ref_of_ordered_work_item_stays ON traust.repository_ref;
CREATE TRIGGER ref_of_ordered_work_item_stays
BEFORE UPDATE OF repository_id ON traust.repository_ref
FOR EACH ROW EXECUTE FUNCTION traust_ops.ref_of_ordered_work_item_stays();
