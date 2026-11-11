-- Disposition views retired 2026-10-28: traust-core's findings service folds the
-- decisions (one rule). Dropped here so existing databases lose them too.
DROP VIEW IF EXISTS finding_clock;
DROP VIEW IF EXISTS finding_status;
DROP VIEW IF EXISTS current_resolution;
DROP VIEW IF EXISTS current_decision;
DROP VIEW IF EXISTS decision_at;
