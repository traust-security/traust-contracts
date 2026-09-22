# Changelog

All notable changes to traust-contracts are documented here.

## [0.36.0]

### Changed

- Reset storage numbering to revision 1 under the new `traust-storage-20260922`
  baseline. Canonical packaged metadata supplies the format, revision and baseline
  to Python and SDK generators; artifact schemas are unchanged.
- Existing stores require an explicit rebuild or reviewed migration. Initialization
  rejects legacy/mismatched metadata, empty stamps, and unstamped storage objects
  without rewriting them. Bootstrap metadata is insert-only.
- This is a pre-GA compatibility boundary, not an automatic reset. Fence old clients
  before recreating storage; see storage/v1/README.md for the coordinated procedure.

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
