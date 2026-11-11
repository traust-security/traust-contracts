-- One append-only event: the signed proof of one decision, in its layer's
-- sequence. One event proves one decision; the library computes seq, the
-- unique key rejects races. event_payload is opaque to the database - the
-- library's canonical bytes, never parsed here.
CREATE TABLE IF NOT EXISTS traust_ledger.events (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    layer_id UUID NOT NULL REFERENCES traust_ledger.layers(id) ON DELETE RESTRICT,
    decision_id UUID NOT NULL REFERENCES traust.decision(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    event_payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (layer_id, seq),
    UNIQUE (decision_id)
);

DROP TRIGGER IF EXISTS ledger_events_reject_mutation ON traust_ledger.events;
CREATE TRIGGER ledger_events_reject_mutation
BEFORE UPDATE OR DELETE ON traust_ledger.events
FOR EACH ROW EXECUTE FUNCTION traust_ledger.reject_mutation();

DROP TRIGGER IF EXISTS ledger_events_reject_truncate ON traust_ledger.events;
CREATE TRIGGER ledger_events_reject_truncate
BEFORE TRUNCATE ON traust_ledger.events
FOR EACH STATEMENT EXECUTE FUNCTION traust_ledger.reject_mutation();
