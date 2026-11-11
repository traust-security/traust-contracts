-- One append-only event: the signed proof of one decision, in its layer's
-- sequence. One event proves one decision; the library computes seq, the
-- unique key rejects races. event_payload is opaque to the database - the
-- library's canonical bytes, never parsed here.
CREATE TABLE IF NOT EXISTS ledger_events (
    id TEXT NOT NULL DEFAULT (uuid()),
    layer_id TEXT NOT NULL REFERENCES ledger_layers(id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL REFERENCES decision(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    event_payload BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (layer_id, seq),
    UNIQUE (decision_id)
);

CREATE TRIGGER IF NOT EXISTS ledger_events_reject_update
BEFORE UPDATE ON ledger_events BEGIN
  SELECT RAISE(ABORT, 'ledger_events rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS ledger_events_reject_delete
BEFORE DELETE ON ledger_events BEGIN
  SELECT RAISE(ABORT, 'ledger_events rows are append-only');
END;
