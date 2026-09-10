# Changelog

All notable changes to traust-contracts are documented here.

## [0.2.0]

Add two optional per-profile fields to the safe-exec profiles config
schema: `keep_env_heads` and `curl_allowed_hosts`. Additive; existing
configs validate unchanged.

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
