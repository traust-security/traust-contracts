SELECT name
FROM main.sqlite_schema
WHERE type = 'table' AND lower(name) = 'traust_storage_meta';
