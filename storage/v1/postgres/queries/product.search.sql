SELECT product_id,
       slug,
       segment,
       registered_at
FROM traust_storage.product
WHERE (%(slug_filter)s = '' OR slug = %(slug)s)
ORDER BY slug
LIMIT %(limit)s OFFSET %(offset)s;
