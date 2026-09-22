INSERT INTO traust_storage_meta (
    id,
    contract_version,
    revision,
    baseline_id,
    applied_at
)
VALUES (
    1,
    :contract_version,
    :revision,
    :baseline_id,
    :applied_at
)
ON CONFLICT (id) DO NOTHING;
