# Changelog

All notable changes to traust-contracts are documented here.

## [0.54.0]

### Added

- Storage revision 2: `portfolio_forge_facts` in SQLite and PostgreSQL, with
  an explicit revision-1 migration that preserves existing records. Stores forge
  observations and their audit-baseline context; derived repository state is not
  stored. See [migration instructions](storage/v1/README.md#migrations).

## [0.53.0]

### Added

- **`ledger.yaml` config section** (`LedgerConfig`, `HarnessContext.ledger`,
  `config/v1/ledger.schema.json`). Optional, no environment overrides — the
  same rules as `storage.yaml`:
  - `dsn` (SQLAlchemy URL: `postgresql+psycopg://…`, `postgresql://…` or
    `sqlite:////…`; repr hidden): present, the Ledger database is the
    authority for disposition layers and layer files are read-only snapshots;
    absent, layer files are the ledger (`LedgerConfig.database`).
  - `signing` (`LedgerSigning`): `required`, `method` (`keypair` |
    `identity`), `key_path` (absolute; required for a required keypair), and
    the keyless `oidc_issuer`, `oidc_client_id`, `expected_identity`,
    `ca_url`, `tlog_url`.
  - `identity` (`LedgerIdentity`): `oidc_issuer`, `oidc_audience`, `jwks_url`,
    `directory_command`.
  - Secrets stay out: the keypair password, identity tokens and the caller's
    ledger token remain runner/caller credentials. Consumers read this from
    the injected context instead of `LAAS_*` / `LEDGER_*` environment
    variables; the verification key stays `ledger-signing-key.pub`.

## [0.52.0]

### Reverted — generated numeric identity (0.51.0)

- Reverts 0.51.0 (#37): `product`, `repo`, `product_repo` and database Ledger
  `layers` return to caller-selected TEXT IDs (`layers.layer_id` primary key,
  nullable `product_repo_id` unique when set). Schema content equals 0.50.0.
- Same v1 revision-1 stamp as 0.51.0: databases bootstrapped by 0.51.0 keep the
  numeric shape and are **not** converted. Recreate them (dev/test) before use.
- Numeric identity is backlogged, not abandoned.

## [0.51.0]

### Changed — pre-stable v1 revision-1 identity correction

- Database-generated numeric `id` primary keys on `product`, `repo`,
  `product_repo`, and database Ledger `layers` replace caller-selected TEXT IDs.
  Child references retain descriptive names (`product_id`, `repo_id`,
  `product_repo_id`, `layer_id`) and point to their parent `id`. Registry upserts
  omit IDs, return integers and retain natural unique keys; typed FKs propagate
  to Storage children and Ledger events/projections. Ledger database layers now
  require one registered `product_repo_id` (unique per owner).
- Authored **v1 revision 1** remains unchanged as a revision number: this is
  the explicitly approved pre-stable exception, not v2 or an automatic upgrade.
  Same-stamp old schemas are rejected by Storage's catalog checks and Ledger's
  `assert_identity_shape` preflight; existing databases need a separately
  reviewed manual old→new conversion on a copy, with signed-history proof.
  No production conversion or downstream pins are included in this change.
- Evidence digests, deterministic `binding_id`, authored event IDs and file
  layer names remain their own identities. See `storage/v1/README.md` for
  conversion stop conditions and audit requirements.

## [0.50.0]

### Added

- **Product -> repo registry.** New storage tables `product` (natural key
  `slug`), `repo` (`repo_url`) and `product_repo` (`(product_id, repo_id,
  ref)`, `ref` `''` = default branch). Products and repos are many-to-many.
  Primary keys are database identifiers (UUIDs); uniqueness lives on the natural
  keys. `Store.register_product`, `register_repo`, `register_product_repo`
  insert or refresh by natural key and return the stored id;
  `find_product_repo` looks one up without creating it.
- **`Binding.product_repo_id`.** Nullable `artifact_binding.product_repo_id`,
  a foreign key to `product_repo`: a binding to an unregistered owner writes
  nothing. Not part of the binding identity (`binding_id` is unchanged since
  0.48.0); must match across a supersession.
- **Inventory tables.** `product.segment`; `product_repo.sub_service` and
  `.resource_type`; new `product_repo_version` (which product versions ship a
  product_repo, with category, cluster operators, images) and `repo_owner`
  (owning teams per product_repo). Loaded from the inventory; descriptive
  columns refresh on re-register (`register_product_repo_version`,
  `register_repo_owner`), identity columns never change.
- **`Binding.commit_sha`.** Nullable `artifact_binding.commit_sha`: the commit
  the artifact describes. Not part of the binding identity; may change across a
  supersession.
- **One current findings-current per product_repo and run.** Unique index on
  the root of `report`/`cumulative` chains per `(scope_id, product_repo_id,
  run_id)`; a newer findings-current must supersede the current one.
- **Ledger `layers.product_repo_id`.** A foreign key to
  `traust_storage.product_repo`, unique when set (one layer per product_repo).
  The ledger depends on storage, never the reverse: its database backend must
  share the database with storage, initialized first. `layer_id` stays
  independent. `traust_contracts.v1.ledger.migration_files` locates future
  ledger deltas.
- **`Store.migrate()`.** Brings a database from its stamped revision to
  `REVISION` in one transaction; an empty database is bootstrapped. For an
  existing one: drop the views storage owns, create tables that do not exist
  yet, apply `<dialect>/migrations/NNN_to_NNN+1.sql` deltas, re-run every
  schema and view file, stamp the revision. Refuses a newer revision without
  writing anything.
### Changed

- **Schema rebaseline: storage and ledger revision 1.** The schema had not
  stabilized, so revisions collapse: storage revision 1 now includes the
  registry, `report_finding.blocked_external` (0.49.0's revision 3) and every
  earlier change; ledger revision 1 includes `layers.product_repo_id`.
  **Databases created before 0.50.0 must be recreated** -- an older database
  stamped revision 1 would otherwise pass the revision check with the wrong
  shape. Migrations hold deltas only (ALTER / DROP / UPDATE; a test rejects
  `CREATE`); each tree ships the `001_to_002.sql` placeholder. See
  storage/v1/README.md, "Compatibility" and "Migrations".
- **SQLite statement splitting** accepts a file whose trailing text is only
  comments (a placeholder delta), and still rejects an incomplete statement.

## [0.49.0]

Unreleased review candidate; no producer cutover or historical rewrite.

### Added

- Canonical effort sizes and roadmap priority labels, with an independent
  optional `blocked_external` boolean. Historical effort values, free-text
  roadmaps and open extra values remain valid in default schemas.
- Explicitly selected `canonical_write` fragments for report, adapter-result,
  validation, PQC blockers/readiness/decision-tree and threat-model artifacts.
  The validator's schema selector accepts a JSON Pointer fragment.
- Registry meanings and project-defined standard declarations. No duration,
  urgency or legacy-size replacement policy is introduced.

### Fixed

- Compatibility acceptance detects enum introduction, const-list narrowing,
  open-object closure and constrained additions to historical open properties.
  A preserved historical const-list alternative remains additive.

### Unchanged

- Effort remains required on mitigation and decision-tree rule objects.
  Unknown-size blocking policy awaits review; no size/null fallback is emitted.
- Default readers, writers, release pins, historical reports and ledger events.
  Reader/identity rollout gates and affected-contract review remain required.

### Storage revision 3

- Added only nullable `report_finding.blocked_external` and its upsert/projection
  on SQLite and PostgreSQL, using the existing INTEGER flag convention.
  True/false/absent remain 1/0/NULL, independent of effort; legacy effort labels
  do not fabricate the flag.
- Fresh stores stamp revision 3. Older revisions are refused before alteration;
  no automatic/live database migration or historical rewrite is performed.
  Removed the obsolete non-executing revision-2-to-3 migration placeholders;
  no replacement placeholder or fabricated migration is introduced.

## [0.48.1]

### Fixed

- **Storage revision 2.** 0.48.0 changed the storage/v1 DDL
  (`artifact_binding.artifact_role`, the `artifact_location` table) but left
  `REVISION` at 1, so a database created under the 0.47 schema passed the
  revision check on open and then failed its first read or write with
  `no such column: artifact_role`. `REVISION` is now 2: such a database is
  refused on open. No 1 -> 2 migration ships; recreate it. The migration
  placeholder moves to `002_to_003.sql`.

## [0.48.0]

### Added

- **Binding roles.** `Binding.role` names a lifecycle role within one context,
  so a `baseline` audit and its `cumulative` findings-current restatement --
  both `report`, same subject, same scanned commit -- are distinct bindings.
  `profiles.json` declares accepted roles per artifact (`report`: `baseline`,
  `cumulative`); undeclared roles are rejected. The role is part of the
  binding identity and must match across a supersession.
- **Artifact locations.** New `artifact_location` table keyed
  `(binding_id, reference)`. `Store.ingest(..., references=[...])` registers
  where the caller already wrote the exact bytes; a retry may add more.
  `get_binding()` returns them on `BindingRecord.references`. References are
  opaque, never fetched or verified, and scoped to the binding that wrote
  them. See `storage/v1/README.md`, "Artifact locations", for pinning.
- `BindingRecord.byte_size`: `get_binding()` returns the evidence size, so a
  consumer gets digest, size, and references from one call and can check the
  bytes it fetches. Reuses `artifact_evidence_size.get.sql`.
- `artifact_binding.artifact_role` column; `artifact_location.upsert.sql` and
  `artifact_location.get.sql` in both dialects.

### Unchanged

- Binding identity for bindings without a role: `role` is encoded trailing
  and present-only, so every existing `binding_id` is unchanged.

### Migration

- Storage revision stays 1. A database bootstrapped by an earlier release
  does not gain `artifact_role` or `artifact_location`; `init()` will not add
  them. Recreate pre-0.48 storage databases or apply the DDL by hand.

## [0.47.1]

### Changed

- `locations.schema.json`: `analysis_results` now documents its accepted
  forms. A path or `file://` URI is local disk; `s3://`, `gs://`/`gcs://` and
  `az://`/`abfs://` are object stores, each with the traust-engine extra it
  needs. Connection settings and credentials come from the environment, never
  this file. The bucket must enforce encryption at rest by its own policy,
  because the harness doesn't set encryption per object. Description only:
  no validation change.

## [0.47.0]

### Changed

- **The threat-model schema defines every section it declares.** `assets`,
  `entry_points`, `deprioritized`, `attack_scenarios` and `update_history` were
  `{"type": "object"}`, so any object passed: no field names, no required
  fields, and no check on asset `sensitivity`. They now have `$defs` (`asset`,
  `entry_point`, `deprioritized_threat`, `attack_scenario`, `history_entry`)
  with required fields and `additionalProperties: false`, transcribed from the
  threat-model skill's `schema.md`, which the Markdown linter already
  enforced. Asset `sensitivity` is `low|medium|high|critical`; `chain-severity`
  is now registered as used by this schema too. A scenario's `steps` are its
  prose paragraphs.
- Backward compatible for every existing artifact: all threat-model artifacts
  in the deployment that prompted this validate against the tightened schema
  unchanged.

## [0.46.0]

### Added

- **OWASP risk ratings reach storage.** The `threat` table, in both dialects,
  now carries:
  - `risk_rating`, the whole block with its factors and reasons
  - its derived values as typed columns: `severity`, `likelihood_score`,
    `likelihood_level`, `impact_score`, `impact_level`, `impact_basis`
  - a new `(status, severity)` index

  These columns are NULL on a threat not yet re-rated. Such a threat keeps its
  legacy `impact`, `likelihood` and `score`, which is now NULL on a rated
  threat because the rating orders by severity.
- `threat_current` exposes the new columns, appended after the existing ones
  so positional readers are unaffected. `threat_exposure` groups by
  `severity` (a rated threat and a legacy one never share a row), and its list
  query orders by severity, most severe first. The 0.45.0 `risk_rating`
  exemptions in the view-coverage test are gone.

### Compatibility

- The storage revision stays 1, following the convention for storage/v1
  before its first deployed migration (`sql.py`): the DDL is edited in place,
  as earlier storage/v1 changes were. A database initialised from an earlier
  0.x DDL must be recreated, not upgraded.

## [0.45.0]

### Added

- **Threat risk rating by the OWASP Risk Rating Methodology.** A threat can now
  carry `risk_rating`:
  - eight likelihood factors and four technical impact factors (plus four
    business ones when known), each scored 0–9
  - the likelihood and impact scores (means of their factors) and levels
    (low below 3, medium below 6, otherwise high)
  - the severity from the method's 3×3 table: `note`, `low`, `medium`,
    `high` or `critical`
  - an optional one-line reason per factor

  Source: OWASP Foundation,
  <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology> (CC BY-SA
  4.0), reimplemented in original wording and code.
- `traust_contracts.v1.risk_rating` is the one implementation of the method's
  arithmetic. `rate()` builds a rating from factor scores, and `problems()`
  rejects one whose scores, levels or severity don't follow from its factors.
  Tested against the methodology's own worked example.
- `enums/v1/owasp-impact-basis.json` (technical or business), with
  definitions.

### Changed

- A threat must now be rated **either** with `risk_rating` **or** with the
  legacy `impact`/`likelihood` labels. All existing threat models still
  validate; new ratings use `risk_rating`. The legacy labels are documented as
  such.
- The compatibility gate no longer flags an `anyOf` whose branches are plain
  `required` lists when one branch asks for nothing the old schema didn't
  already require. Every old artifact satisfies that branch. `oneOf` and
  branches with other constraints are still flagged, and tests pin the
  narrowing.

### Not yet projected

- The `threat` table and `threat_current` view don't carry `risk_rating` yet;
  that needs new columns, a storage decision still pending. An OWASP-rated
  threat projects with NULL `impact`, `likelihood` and `score`. The gap is
  recorded as an EXEMPT entry in `tests/test_view_contract_coverage.py`.

## [0.44.0]

### Added

- **Retired values.** A `deprecated` entry may carry `"retired": true`: the
  value was removed from `values` in a major release, so the schema rejects
  new writes, but its entry and `replaced_by` stay so readers can still
  normalise old ledger events, which keep their original strings for good.
  - A deprecated value that is still in `values` must not be marked retired.
  - A value missing from `values` must be marked retired.
  - Nothing may be replaced by a retired value.

  Before this, removing a value from `values` made its `deprecated` entry
  fail the check, which forced the reader mapping to be deleted with it.

## [0.43.0]

### Added

- **Optional `definitions`, `standard` and `deprecated` fields on `enums/v1`
  registry files.** They let the registry say what each value means, which
  standard a vocabulary follows, and which values are deprecated in favour of
  which (`replaced_by`: one or more `{enum, value}` targets, or none for a
  one-way drop). This lets vocabulary change in place, with no separate
  version tree. No existing registry file changes, and generators that read
  `name`/`description`/`values` are unaffected.
- `ci/enum_registry.py` checks the new fields:
  - `definitions` covers each value exactly once
  - an adapted standard has a note
  - deprecated keys are the file's own values
  - every replacement exists and is not itself deprecated
  - a split lands in each enum once
  - unknown top-level keys are rejected, which catches typos

  `tests/test_enum_registry.py` covers each rule against a synthetic registry
  and runs them on every real file.
- README section on the enum registry.

## [0.42.0]

### Changed

- **One `ecosystem` vocabulary.** `impact-analysis` `metadata.ecosystem` now
  accepts the distro ecosystems `rpm`, `deb` and `apk` that report
  `finding.dependency.ecosystem` already carried, so the two fields share one
  registry file, `enums/v1/ecosystem.json`. It replaces `impact-ecosystem.json`
  and `dependency-ecosystem.json`. The change is additive: every existing
  document still validates.
- `compliance-mapping-framework.json` is renamed `compliance-control-catalog.json`
  (`compliance_control_catalog`), because a control mapping names a control
  catalog. It deliberately differs from `compliance_framework`: FedRAMP High
  and Moderate are 800-53B baselines assessed over the `nist-800-53-rev5`
  catalog, so they are assessment targets, not catalogs. Both descriptions
  now say so.
- `isolation-check-result.json` describes what `na` means. Renaming the value
  to `not_applicable` would change stored reports, so it is left to the v2
  vocabulary.

## [0.41.0]

### Added

- **Every schema enum is now registered.** 101 value sets that were defined
  only inline in the schemas (127 sites) each get an `enums/v1` file, so
  `enums/v1` now covers every string enum in `schemas/v1` and `config/v1`.
  Nothing in any schema changes; each file's `source_schema` points at the
  first site and `used_in_schemas` is derived. Numeric enums
  (format-version switches) stay out of scope.
- `tests/test_enum_registry.py` now **fails** on any schema enum whose value
  set matches no registry file (previously a warning).

### Changed

- **SDK codegen impact.** Generators that emit one type per registry file and
  retype fields whose values match (as the Go SDK does) will produce new enum
  types and retype the matching fields on their next regeneration. One value
  (`source+runtime`, `pqc_readiness_assessment_basis`) is not a valid
  identifier fragment and needs sanitising by such generators.

## [0.40.0]

### Changed

- Restatement `before`/`after` are a DELTA for map-valued targets: only the
  entries being changed, never the whole map. An event's size now tracks the
  change rather than the layer (measured: 69% smaller for a one-entry change in
  a ten-artifact map, and ~158 KB → ~1 KB for a single claim on a
  1,000-finding layer). `before` is now required.
- Removed `finding_aliases` as a restatement target. A `rebaseline` event
  already records a rename inside the Merkle-covered event stream, so the
  metadata table is a rebuildable projection rather than authority.

## [0.39.0]

### Added

- `restatement` event vocabulary: `source_type` `restatement`,
  `$defs/event_restatement`, `RestatementTarget`, `RestatementReason`,
  `LayerRestatement`, `RestatementAuthority`, and a `layer_event.restatement`
  column in both dialects. An administrative restatement of signature-bound
  layer metadata (`claim_hashes`, `audit_report_sha256`, `artifact_digests`,
  `finding_aliases`), recording the prior value, the actor and a ticket. Like
  `rebaseline` it is not an evidence class and carries an empty disposition.
  Event content is not a target: events are immutable and are superseded by a
  later event.

### Fixed

- `LayerEvent` now declares `alias`, `finding`, and `restatement`.
  `ContractModel` ignores unknown keys, so a block declared only in the schema
  was silently dropped by every `from_dict`/`to_dict` round-trip — which is how
  `alias` and `finding` became unwritable through the typed path.
- `SourceType` gained `fuzz_report`, `rebaseline`, and `restatement`; a test now
  pins the enum against the schema.

## [0.37.1]

### Fixed

- **Enum registry metadata now matches the schemas.** `source_schema` in
  `threat-impact`, `threat-likelihood` and `threat-status` named
  `threat-register.schema.json`, which does not exist; they now point at
  `threat-model.schema.json#/$defs/threat/properties/*`. `impact-classification`
  and `ref-kind` pointed at paths that no longer resolve and now point at
  `impact-analysis.schema.json#/$defs/repo_entry/properties/classification` and
  `report.schema.json#/$defs/metadata/properties/ref_kind`.
- `used_in_schemas` is regenerated for every registered enum. Among the
  corrections, `verdict` no longer claims `verification.schema.json` (which
  defines its own, different `verdict`), and `ref-kind` no longer claims
  `isolation-review` or `vuln-findings`, neither of which carries `ref_kind`.
- `repo-scope-path` declares `"schema_enforced": false`: its values are
  documented on `report.schema.json#/$defs/location/properties/path` but are
  not a schema `enum`.

### Added

- `ci/enum_registry.py` derives `used_in_schemas` from the schemas (a schema
  uses an enum when validating it can reach a site with the enum's exact
  value set, following `$ref` chains across files) and checks every
  registered file: `source_schema` resolves to an enum with the same values,
  names and value sets are unique, and `used_in_schemas` equals the derived
  list. `--write` regenerates the lists.
- `tests/test_enum_registry.py` fails on any registry metadata drift and, for
  now, warns about schema enums that have no `enums/v1` file.

## [0.37.0]

### Changed

- **`artifact_evidence` no longer retains payload bytes.** The `payload`
  column (BYTEA/BLOB) is replaced by `byte_size` (BIGINT/INTEGER) recording
  the original artifact size. Artifact bytes live in the caller's object
  store; storage records the content-addressed digest and byte size only.
- Removed `Store.get_evidence()` and `Store.get()` — payload is not in the
  database. Consumers needing original bytes fetch from object store using
  the digest.
- Removed `artifact_evidence.get.sql` queries from both dialects.
- The post-insert evidence collision check is removed; the digest primary
  key makes it structurally unnecessary.
- **Removed `layer_metadata` table.** `findings_summary.repo` now reads from
  `ownership_current.repo_url` instead of joining through the layer binding
  chain. `layer_event` stays as the projection for the time dimension.
- Documented ledger integration: the ledger is optional, and the views it
  enables (`finding_timeline`, `exposure_trend`, `finding_sla`) degrade
  gracefully to report-date-only when no layer artifacts are ingested.

## [0.36.1]

### Added

- Append-only enforcement triggers are now shipped in the contracts SQL itself.
  SQLite `events.sql` installs `events_reject_update`, `events_reject_delete`,
  and `events_validate_append`; `layers.sql` installs `layers_reject_delete`.
  PostgreSQL `namespace.sql` defines `reject_authoritative_mutation()` and
  `validate_event_append()` functions; `events.sql` and `layers.sql` install
  mutation, truncation, and append-validation triggers.
  Consumers bootstrapping from contracts SQL alone now get the full
  append-only contract without needing the Ledger runtime.
- Added `test_sqlite_append_only_guards` — bootstraps from contracts SQL
  and proves UPDATE, DELETE, and out-of-order seq are rejected.
- Added `make db-up` / `make db-down` for local PostgreSQL container lifecycle.

## [0.36.0]

### Added

- Added optional SQL-first `ledger/v1` per-table PostgreSQL and SQLite DDL,
  and direct per-file bootstrap APIs (no packaged query files).
  The fresh Ledger baseline is `v1` / revision 1 with singleton metadata;
  existing mismatches require explicit handling rather than an implicit upgrade.
- Confirmed `schemas/v1/layer.schema.json` as the complete portable layer
  document across file and database backends, with a synthetic full-layer fixture.
- Added SQL resource, bootstrap, metadata, and packaging checks; baseline
  `storage/v1` remains independent of Ledger.

## [0.9.0]

## Changes

- **Reverted the storage REVISION 16 changes that shipped as 0.34.0.** The
  storage contract is exactly the 0.33.0 definition again (REVISION 15):
  the same tables, views, readers and schemas. 0.34.0 remains tagged but
  should not be pinned.

## [0.8.0]

## Changes

- **The five dashboards with no view now have six.** `pattern_exposure`,
  `compliance_posture`, `verification_current`,
  `verification_regression_current`, `remediation_current` and
  `attack_coverage`, over five new fan-out tables: `compliance_result`,
  `verification_finding`, `verification_regression`, `remediation_source`
  and `attack_chain`.

  Six rather than five because a verification fans out along TWO axes — what
  held and what it broke. Folding them would make "how many findings did this
  verification touch" ambiguous, and the regressions are the half a
  remediation review must not miss.

  Three judgements the views encode deliberately:

  - `pattern_exposure` fans `cwes[]` out rather than grouping by a *primary*
    CWE. A finding declaring two weaknesses is an instance of both, so
    `occurrences` sums to more than the finding count — which is why it is
    not named `findings`.
  - `compliance_posture` keeps `verdict_source` uncollapsed with an
    `assurance_tier` ordering it. Satisfied-by-check, satisfied-by-agent and
    satisfied-by-human-override are three different assurance claims.
  - `attack_coverage` RANKS evidence instead of unioning it: a chain
    confirmed end to end, a chain attempted, and a technique merely modelled
    are tiers 3, 2 and 1. Colouring a coverage map from the union of the
    three overstates the estate's evidence everywhere it matters most.

  `current_finding` gains `category`, `cwes` and `effective_severity` so a
  pattern rollup does not re-join the finding tables. A policy finding
  declares a single `cwe` rather than a list, so it is wrapped into a
  one-element array: one column, one meaning, whichever family the row
  came from.

  `verification_finding.evidence` is flattened into its four declared members
  rather than stored whole. The coverage gate required it, and correctly: a
  nested evidence block is exactly where declared fields go missing.

  `REVISION` 14 → 15. A store on 14 has neither the tables nor the views.

- **A family can now declare several fan-out tables.** The registry mapped
  one table per family, which could express neither validation's
  `attack_chain` beside `validation_finding` nor verification's two.

## [0.7.0]

## Changes

- **`validation_current` is reachable.** The view was authored in 0.25.0 and
  gated by the contract-coverage test from the start, and had no `.list.sql`
  in either dialect and no `Store.query_*` method — authored, enforced, and
  unreachable. `validation_exposure` aggregates it; a consumer asking what
  happened to one claimed finding needs the row, not the count.

- **A gate for it.** `test_every_consumption_view_has_a_query_and_a_reader`
  walks the view directory and requires a `.list.sql` in both dialects and a
  `Store.query_*` for every view not declared an intermediate. The six
  intermediates — `binding_current`, `current_finding`, `report_current`,
  `ownership_current`, `finding_first_seen`, `sla_clock` — are listed with
  the view each is composed into, so "no reader" is a recorded decision
  rather than an omission.

## [0.6.0]

## Changes

- **The three secondary projections now carry what their schemas declare.**
  `report_finding` held 6 of the 27 fields `report.schema.json` declares on
  `findings[]`, `cloud_config_finding` 9 of 22, `layer_event` 11 of 16. The
  earlier closure was scoped to DISPOSITION — validity, resolution,
  fingerprint, ownership — which is what the open/hardening/distinct views
  needed, and never reached the analytical columns.

  So `category`, `cwes`, `cvss`, `description`, `remediation`, `locations`,
  `effective_severity`, `asvs_references` and the rest were ingested and then
  invisible to SQL. Exact bytes were always retained in `artifact_evidence`,
  but a reader of the projection saw a finding as a title and a severity. A
  pattern rollup grouping by CWE could not be expressed at all.

  `layer_event` additionally flattens `risk_weight` into `risk_lambda` and its
  three companions, the way `source` and `disposition` were already flattened,
  and gains `rationale` — which `layer.schema.json` marks REQUIRED and which
  was dropped entirely, leaving an event stream that recorded that something
  changed and never why.

  `alias` and `finding` are kept whole rather than flattened: both are
  optional, both carry their own sub-shape, and no view cuts by them yet.

  `REVISION` 13 → 14, fail-closed. A store on 13 is missing columns, not just
  rows, and the upsert would simply stop filling them — the same silent shape
  as revisions 2 and 4.

- **The contract-coverage gate now covers projection TABLES, not only views.**
  A view can expose only what its table carries, so gating the views alone is
  what let `report_finding` sit at 6 of 27 unnoticed. `FAN_OUT_TABLES` checks
  each table's DDL against the schema of the item it fans out, in both
  dialects, and `FLATTENED` records the fields satisfied by split columns
  rather than one of their own name.

  The check also strips SQL comments before matching. It was not doing so, and
  the prose in these files names the very fields it explains: `layer_event`
  read as carrying `finding` and `disposition` because both words appear in
  comments, while neither was a column.

## [0.5.0]

## Changes

- **`evidence[]` now reaches the SQL projection.** The remediation and
  verification projection tables enumerated the pre-0.3.0 field list, so the
  typed base-vs-patch evidence added in 0.3.0/0.4.0 was ingested and then
  invisible to anything querying SQL. Exact bytes were always retained in
  `artifact_evidence`, so nothing was lost — but a reader of the projection
  saw every fix as though no evidence existed.

  Adds an optional `evidence` column to `remediation` and `verification` in
  both dialects, wires it through both upserts, and declares it once in
  `ONE_ROW_PROJECTIONS`. Nullable, mirroring `revalidation`: a report without
  evidence still projects.

  `REVISION` stays at 1 by review decision: nothing consumes the projection
  yet, so there is no existing database to protect from the added column.
  Bump it when a real consumer appears.

- PostgreSQL storage now owns the fixed `traust_storage` schema. Canonical DDL,
  queries, foreign keys, indexes, and views use qualified relation names, so
  storage cannot collide with or be redirected to application relations through
  `search_path`. Initialization creates the schema when absent; restricted
  deployments may provision it and grant access beforehand. SQLite continues to
  use the caller-selected database file as its physical namespace.

## [0.4.0]

## Changes

- **`evidence[]` on the verification family too.** Stage-8 verification
  reports can now carry the same typed base-versus-patch evidence as stage-7
  remediation reports, via a `$ref` to
  `remediation.schema.json#/$defs/patch_evidence` — one definition, so a
  `proves` claim means the same thing on both sides of a fix and the two
  cannot drift apart.

  Why it was needed: the block landed in 0.3.0 on the remediation family
  only, and in the estate that measured this, remediation reports are a
  small family while verification reports are a large one. Typed
  evidence that only the smaller family can carry reaches almost none of the
  corpus.

  Optional and additive: `evidence` is absent from `required`, so every
  existing verification report stays valid. A report carrying no evidence
  item is making an analysis-only claim, which is the honest default for a
  targeted re-audit — it reads two revisions and executes neither.

  The `patch_evidence_kind` enum registry entry now records both consumer
  schemas.

## [0.3.0]

## Changes

- **Typed base-versus-patch patch evidence.** New optional `evidence[]` on
  remediation reports, with `$defs/patch_evidence` and the
  `patch_evidence_kind` enum (`regression`, `mutation`, `property`,
  `scanner_differential`, `exploit`). Each item records what was observed on
  the unpatched and the patched revision.

  The load-bearing rule is a conditional: an item may claim
  `outcome: proves` or `fails_to_prove` **only if both observations are
  present**, so a check that never ran cannot be filed as evidence. Items that
  were not attempted carry their reason inline (`not_attempted: <reason>`),
  matching the existing `deterministic_steps` shape.

  Additive and optional — `evidence` is absent from `required`, so every
  existing remediation report stays valid. `revalidation` is untouched and
  remains the live-validation channel: its `method` values and the new
  evidence kinds are disjoint, so a mutation verdict can never be mistaken for
  a live-validation verdict. What each kind may legitimately conclude is
  bounded by the per-path evidence ceilings in the harness's
  `docs/disposition-ledger.md` section 8a.

- **The compatibility gate no longer reads a new optional sub-object as a
  breaking change.** `test_no_breaking_changes_vs_previous_tag` flagged any
  newly added conditional `required`, including one inside a brand-new `$def`
  that no artifact of the previous tag could reach. It now exempts a
  conditional only when EVERY reference chain from the schema root to its
  containing `$def` crosses a property absent from the old schema — under
  `additionalProperties: false`, an old artifact cannot carry such a property,
  so the rule cannot invalidate it. Four tests pin the limits of the
  exemption: a conditional tightened on an existing `$def`, a new `$def`
  swapped in behind a pre-existing property, and a `$def` reachable by both a
  new and an old path are all still reported.

## [0.2.0]

- Add SQL-first `storage/v1`: authored SQLite/PostgreSQL schema, upserts and
  dashboard views, with relational projections for all 27 artifact schemas.
- Export `traust_contracts.storage.Store`, `IngestResult` and `IngestError`:
  exact-byte evidence, atomic projections, race-safe digest idempotency and
  revision preflight. SQLite uses stdlib; PostgreSQL uses the optional existing
  `postgres` extra.
- Ship authored SQL in wheels/sdists. Tests use focused inputs, not packaged
  conformance snapshots or generated fixtures. An explicit PostgreSQL test target
  loads `storage.yaml` from an explicitly selected test config home; CI integration remains pending.
- Add optional `storage.yaml` to the canonical config manifest, schema and typed
  context. Runtime callers and tests share the loader; no per-setting environment overrides.
- Add a live, scoped PostgreSQL `findings_summary` view for the Security Posture
  dashboard instead of a materialized view. Storage revision checks reject mismatched databases rather than
  implying migrations.
- Keep evidence out of normal exception messages and tracebacks; explicit
  `IngestError.payload` access remains available for reject handling.
- Remove blanket SQL byte-pinning; SQL compatibility requires review, while the
  existing JSON Schema compatibility gate remains unchanged.

## [0.1.1]

## Changes

- **Timestamps are now enforced, not just declared.** New
  `traust_contracts.v1.timestamps` is the single definition of a valid ledger
  timestamp, shared by producers, models, and migrations: `is_rfc3339`
  (predicate), `to_rfc3339` (transform), and `IsoTimestamp` (model gate).
  Validation delegates to `rfc3339-validator` rather than
  `datetime.fromisoformat`, which is looser than RFC 3339 and accepts bare
  dates and naive datetimes the schemas forbid.

- **`jsonschema[format-nongpl]` is now a declared dependency.** The schemas
  have always declared `format: date-time`, but jsonschema only asserts that
  format when an assertor is installed — an unregistered format passes
  everything, so `FormatChecker().conforms('TrueT00:00:00+00:00', 'date-time')`
  returned `True`. The `format-nongpl` extra pulls MIT `rfc3339-validator`
  rather than GPL `strict-rfc3339`.

- **`LayerEvent.recorded_at`, `LayerEvent.occurred_at`, and
  `ReviewItem.recorded_at` are typed `IsoTimestamp`.** Previously bare `str`,
  so nothing checked them at either layer. Values are validated but never
  rewritten: `event_id` and the Merkle leaf are computed over the serialized
  event, so normalizing `+00:00` to `Z` (as `AwareDatetime` does) would
  re-root every layer and void every signature.

- **`ContractModel` sets `validate_assignment=True`.** Field constraints were
  only applied at construction, so `event.recorded_at = "banana"` was
  accepted afterwards. Applies to every contract model, not just timestamps.

### Breaking

Events whose `recorded_at` or `occurred_at` is not RFC 3339 now fail
validation on read as well as write. Corpora holding such values must be
migrated before adopting this release
(`traust.migrations.fix_event_timestamps` converts bare dates and drops
unrepairable optional values).

## [0.1.0]

Source of truth for JSON schemas and enums shared across the Traust
ecosystem, plus generated Python bindings and the configuration contract —
the authoritative manifest of what config exists and how it loads.
