SELECT pr.product_repo_id,
       p.slug,
       p.segment,
       r.repo_url,
       pr.ref,
       pr.sub_service,
       pr.resource_type,
       pr.registered_at
FROM traust_storage.product_repo pr
JOIN traust_storage.product p ON p.product_id = pr.product_id
JOIN traust_storage.repo r ON r.repo_id = pr.repo_id
WHERE (%(slug_filter)s = '' OR p.slug = %(slug)s)
  AND (%(repo_url_filter)s = '' OR r.repo_url ILIKE %(repo_url_pattern)s)
ORDER BY p.slug, r.repo_url, pr.ref
LIMIT %(limit)s OFFSET %(offset)s;
