-- Disposition views retired: traust-core's findings service folds the
-- decisions (one rule). Dropped here so existing databases lose them too.
DROP VIEW IF EXISTS traust.finding_clock;
DROP VIEW IF EXISTS traust.finding_status;
DROP VIEW IF EXISTS traust.current_resolution;
DROP VIEW IF EXISTS traust.current_decision;
DROP VIEW IF EXISTS traust.decision_at;
