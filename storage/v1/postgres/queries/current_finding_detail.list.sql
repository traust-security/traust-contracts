SELECT scope_id,
       subject_id,
       run_id,
       finding_id,
       title,
       severity,
       fingerprint,
       validity,
       resolution,
       assurance,
       category,
       cwes,
       effective_severity,
       family,
       ownership,
       business_unit,
       tree,
       is_branch_audit,
       cvss_score,
       triage_verdict,
       triage_severity,
       exposure_class
FROM traust_storage.current_finding_detail
WHERE scope_id IN (
    SELECT jsonb_array_elements_text(%(scope_ids)s::jsonb)
)
ORDER BY scope_id, subject_id, run_id, finding_id, title;
