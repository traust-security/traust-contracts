SELECT pr.product_repo_id,
       p.slug,
       p.segment,
       r.repo_url,
       pr.ref,
       pr.sub_service,
       pr.resource_type,
       pr.registered_at
FROM product_repo pr
JOIN product p ON p.product_id = pr.product_id
JOIN repo r ON r.repo_id = pr.repo_id
WHERE (:slug_filter = '' OR p.slug = :slug)
  AND (:repo_url_filter = '' OR r.repo_url LIKE :repo_url_pattern)
ORDER BY p.slug, r.repo_url, pr.ref
LIMIT :limit OFFSET :offset;
