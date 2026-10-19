-- The dashboard spine: one row per CURRENT finding, with its owner.
--
-- Three things a dashboard must not have to rediscover, unified here so
-- every view above it inherits them:
--
--   1. BOTH finding families. Code findings project to report_finding and
--      policy findings to cloud_config_finding. A query that reads only the
--      first silently omits every cloud-config finding.
--   2. ONE report per subject. A repo's findings are restated across a plain
--      audit and a disposition-aware findings-current report, and both are
--      legitimately current -- counting report_finding directly inflates by
--      49% (measured across 155 real paired reports).
--   3. OWNERSHIP. The denominator every cut divides by, and it lives in
--      neither finding table.
--
--
-- category, cwes, effective_severity and cvss_score ride the spine.
-- They are the axes a pattern rollup groups by and a findings listing
-- sorts by, and a view above this one should not have to re-join the
-- finding tables to reach them. A policy
-- finding declares a single `cwe` rather than a list, so it is wrapped into
-- a one-element array: one column, one meaning, whichever family a row came
-- from. effective_severity is the severity AFTER disposition -- reading
-- `severity` alone reports a downgraded finding at its original rating.
-- cvss_score is lifted out of the report finding's cvss object; a policy
-- finding declares none, so the column is NULL for that family.
-- Deliberately UNFILTERED on disposition: open/hardening are policy and
-- belong in the views above, not in the spine.
CREATE OR REPLACE VIEW traust_storage.current_finding AS
SELECT binding.scope_id,
       binding.subject_id,
       binding.run_id,
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
       'code' AS family,
       owner.ownership,
       owner.business_unit,
       owner.tree,
       owner.is_branch_audit,
       (f.cvss ->> 'score')::double precision AS cvss_score
FROM traust_storage.report_finding f
JOIN traust_storage.report_current current_report
  ON current_report.binding_id = f.binding_id
JOIN traust_storage.artifact_binding binding
  ON binding.binding_id = f.binding_id
LEFT JOIN traust_storage.ownership_current owner
  ON owner.subject_id = binding.subject_id
UNION ALL
SELECT binding.scope_id,
       binding.subject_id,
       binding.run_id,
       f.finding_id,
       f.title,
       f.severity,
       f.fingerprint,
       f.validity,
       f.resolution,
       f.assurance,
       NULL AS category,
       CASE WHEN f.cwe IS NULL THEN NULL ELSE jsonb_build_array(f.cwe) END AS cwes,
       f.effective_severity,
       'policy' AS family,
       owner.ownership,
       owner.business_unit,
       owner.tree,
       owner.is_branch_audit,
       NULL::double precision AS cvss_score
FROM traust_storage.cloud_config_finding f
JOIN traust_storage.current_binding binding
  ON binding.binding_id = f.binding_id
LEFT JOIN traust_storage.ownership_current owner
  ON owner.subject_id = binding.subject_id;
