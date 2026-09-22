INSERT INTO traust_storage.traust_storage_meta (
    id,
    contract_version,
    revision,
    baseline_id,
    applied_at
)
VALUES (
    1,
    %(contract_version)s,
    %(revision)s,
    %(baseline_id)s,
    %(applied_at)s
)
ON CONFLICT (id) DO NOTHING;
