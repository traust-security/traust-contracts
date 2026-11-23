-- An order's inputs as a document: input_artifact_id is the artifact holding the parameters
-- its asset runs with (what to build, for which scope), written when the order is queued and
-- read when it is claimed; null for an asset that takes none. Asset parameters live in that
-- document, never as columns on this generic table. Identical inputs are one content-addressed
-- artifact, so an asset's latest order for the same inputs is one indexed lookup (a report's
-- last build, for instance).
ALTER TABLE ops_run_order
    ADD COLUMN input_artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_ops_run_order_input
    ON ops_run_order (input_artifact_id, created_at DESC)
    WHERE input_artifact_id IS NOT NULL;
