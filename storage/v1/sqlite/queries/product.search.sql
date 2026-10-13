SELECT product_id,
       slug,
       segment,
       registered_at
FROM product
WHERE (:slug_filter = '' OR slug = :slug)
ORDER BY slug
LIMIT :limit OFFSET :offset;
