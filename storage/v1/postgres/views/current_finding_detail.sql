-- Current findings at listing grain: the spine plus the columns a
-- cross-repo findings worklist filters and sorts by.
--
-- The spine stays free of per-artifact correlations; this view adds the two
-- a worklist needs and cannot derive from it:
--
--   TRIAGE. The verdict and triage-assessed severity of the newest triage
--   bound to the SAME scope, subject and run, matched per finding through
--   source_finding_id. Newest binding wins (bound_at DESC, binding_id DESC,
--   report_current's tie rule) so two independent triages of one context
--   cannot fan a finding out into duplicate rows; a context with no triage
--   reads as NULL, which is the untriaged signal, not an error.
--   EXPOSURE CLASS. The census classification, expressed per row with the
--   same CASE census_exposure aggregates, so a listing consumer FILTERS
--   rather than restates the disposition policy. Keep the two CASEs in
--   step: they must classify the same row the same way.
CREATE OR REPLACE VIEW traust_storage.current_finding_detail AS
SELECT f.scope_id,
       f.subject_id,
       f.run_id,
       f.finding_id,
       f.title,
       f.severity,
       f.fingerprint,
       f.validity,
       f.resolution,
       f.assurance,
       f.category,
       f.cwes,
       f.effective_severity,
       f.family,
       f.ownership,
       f.business_unit,
       f.tree,
       f.is_branch_audit,
       f.cvss_score,
       triage.verdict AS triage_verdict,
       triage.severity AS triage_severity,
       CASE
           WHEN COALESCE(f.validity, 'confirmed') = 'false_positive' THEN 'false_positive'
           WHEN COALESCE(f.validity, 'confirmed') = 'hardening' THEN 'hardening'
           WHEN COALESCE(f.resolution, 'open') IN ('resolved', 'risk_accepted') THEN 'closed'
           ELSE 'open'
       END AS exposure_class
FROM traust_storage.current_finding f
LEFT JOIN traust_storage.triage_verdict triage
  ON triage.binding_id = (SELECT triage_binding.binding_id
                            FROM traust_storage.current_binding triage_binding
                           WHERE triage_binding.scope_id = f.scope_id
                             AND triage_binding.subject_id = f.subject_id
                             AND triage_binding.run_id = f.run_id
                             AND triage_binding.artifact_name = 'triage'
                           ORDER BY triage_binding.bound_at DESC, triage_binding.binding_id DESC
                           LIMIT 1)
 AND triage.source_finding_id = f.finding_id;
