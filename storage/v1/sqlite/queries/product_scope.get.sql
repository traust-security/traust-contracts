SELECT b.binding_id,
       pr.product_repo_id,
       p.product_id,
       p.slug,
       pr.ref,
       COALESCE(p.segment, '')
FROM artifact_binding b
JOIN product_repo pr ON pr.product_repo_id = b.product_repo_id
JOIN product p ON p.product_id = pr.product_id
WHERE b.binding_id IN (SELECT value FROM json_each(:binding_ids));
