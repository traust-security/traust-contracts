SELECT b.binding_id,
       pr.product_repo_id,
       p.product_id,
       p.slug,
       pr.ref,
       COALESCE(p.segment, '')
FROM traust_storage.artifact_binding b
JOIN traust_storage.product_repo pr ON pr.product_repo_id = b.product_repo_id
JOIN traust_storage.product p ON p.product_id = pr.product_id
WHERE b.binding_id IN (
    SELECT jsonb_array_elements_text(%(binding_ids)s::jsonb)
);
