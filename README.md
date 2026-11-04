# Traust Contracts

Source of truth for JSON schemas and enums shared across the Traust ecosystem,
plus generated Python bindings, **the configuration contract** (the one place
that knows what config exists and how it loads), and **storage/v1** (the SQL-first
relational contract for the one-owner data model).

## Configuration contract

Contracts owns the configuration *mechanism* for the whole stack — mechanism
only, never estate data:

- **MANIFEST** — the authoritative list of config files (name, required/optional,
  schema, typed model). The single source of truth for “what config exists.”
- **Schemas** — `config/v1/*.schema.json`, applied at load time (versioned
  separately from the `artifacts_schema/v1` schemas).
- **Typed sections + `HarnessContext`** — each file parses into a typed model;
  `HarnessContext` is the frozen bundle of them all.
- **The loader** — `load_context()` (resolve the whole context at an entry point)
  and `load_section()` (one file, for narrow feature-gated readers). Resolution is
  `$TRAUST_CONFIG_HOME`, else the documented default `~/.traust/config` — no env
  overrides, no cwd scanning, no second root.

The config home holds two files: `traust.yaml` (`config/v1/traust.schema.json`:
everything an adopter sets: database, artifacts, identity, ledger key paths,
budgets, forge hosts and tokens, `locations`, `feeds.osv_access`,
`execution.sandbox`, logging outputs, `remediation`, `campaign`, `overrides`; secrets only by the
name of an environment variable) and `model-registry.yaml`. An absent
`traust.yaml` keeps traust-core's zero-config defaults. traust-core's `Config`
is the typed reader of `traust.yaml`; product data (tool pins, safe-exec
profiles, feeds, rule packs) ships with traust and is checked against its
`config/v1` schema where it is read. `config_completeness_audit()` checks the
two files.
End-to-end architecture: `traust/docs/architecture.md` → *Configuration & context*.

`compliance.docs_targets` binds registered product UUIDs to explicit official
documentation slugs, versions and optional guide names. These are adopter facts,
not values inferred from product labels. Omitted guides use the provider's actual
landing-page discovery; missing product coordinates are an explicit refusal.

## Install

```bash
uv add "traust-contracts @ git+https://github.com/traust-security/traust-contracts.git"
```

Go SDK: see [traust-sdk](https://github.com/traust-security/traust-sdk).

## Versioning

Two axes:

- **Data-contract version** (`v1`, `v2`, ...) — the shape of schemas/enums
  and everything generated from them. Lives as a real directory; `v2` sits
  beside `v1` once it exists.
- **Commit SHA** — the only release identifier. No package versions or tags:
  traust-core pins this repo by commit (`[tool.uv.sources] rev = "<sha>"`).

`traust_contracts.models` / `.enums` / `.paths` alias the current major
(`v1` today). Pin to `traust_contracts.v1.*` directly if the shape must
never move under you.

Finding DTO serialization preserves schema-valid classifier aliases, dependency
provenance and `fingerprint_algo`. Absent, empty defaults for the optional
nonempty-only isolation/PEACH lists stay omitted; explicit values remain
available to the final schema gate, including invalid explicit nulls. These
models are not a new-write admission policy: core validates the final artifact
bytes and owns canonical persistence.

Layer DTO construction and field reassignment require lowercase 64-character
hexadecimal values in root `baseline_claims`, and at least one character in each
event `evidence_refs` item. Absent empty collections remain omitted; explicitly
empty maps and lists remain valid and present. The root map stays independent of
`metadata.claim_hashes`. Final artifact schema validation is still required,
including after in-place edits to mutable collections; semantic preservation is
not a byte-identical reserialization guarantee for signed historical payloads.

`adapter-result` carries scanner observations, not authored audit findings.
Its adapter-local finding schema preserves shared field validation while
allowing unreported CWEs, description and remediation, and opaque native IDs.
It does not invent classifications or verdicts. `report.schema.json` keeps its
full authored-finding requirements unchanged.

## Manifest SBOM coverage

`manifest-coverage.schema.json` binds a checkout's unresolved manifests to native
`sbom_id` and `assessment_id` UUIDs. The assessment identifies the scan, independently
of deduplicated SBOM package content. Core records the SBOM, coverage and
`repository_ref.manifest_sbom_assessment_id` pointer atomically; readers verify both
IDs against the current reference and owning assessment, never a timestamp-selected
historical document. A direct SBOM replacement clears the scan pointer, including
when its normalized package content is unchanged.

`unresolved` is keyed by ecosystem, then canonical repository-relative manifest
path, with one `manifest-coverage-reason` value per path. Duplicate JSON members
are rejected before decoding can discard an identical or conflicting declaration.
An empty object is a complete read only for the matching scan. Missing coverage is
unknown, not complete; mismatched bindings are rejected.

Existing databases need the explicit additive
`storage.sql.manifest_sbom_binding_upgrade(dialect)` before using this contract.
Inspect the reference table first and apply it only when the new column is absent.
The authored SQL preserves existing rows and leaves their scan pointers null;
no timestamps, historical assessments or deduplicated SBOM artifacts are used to
invent bindings. Core exposes the upgrade through its contracts facade.

## Pack spec

`config/v1/pack.schema.json` is the shape of a workload pack's `assets.yaml` (the
security pack lives in traust as `packs/security/assets.yaml`). traust-engine plans and
admits from `deps`, `partitions`, `trigger`, `priority`, `freshness` and `admission`;
runners execute from `run`, `params`, `runner`, `model`, `writes`, `riders` and
`outcomes` in their pinned copy. The schema is strict, so a key one reader doesn't know
fails for both.

## Run manifest

`artifacts_schema/v1/run-manifest.schema.json` is the per-order detail that
`run_order.artifact_id` points at: config digests in force (the pack file's digest is the
pack version), the budget verdict at admission, the approval, progress and degraded keys.
Each change is a new artifact; the manifest doesn't name its order, so orders in the same
state share one artifact.

## Artifact-only sessions

`artifacts_schema/v1/session-task.schema.json` declares a runner's staged input files,
resolved models and one schema-named output. All paths are relative to the task directory;
`run_id` is the order UUID, or null for a manual session. The executor's identity, measured
usage and optional error use `artifacts_schema/v1/session-result.schema.json`.

The run manifest's optional `sessions` list records runner-computed task and input digests,
input sizes, and the declared output's digest and recorded artifact UUID. Missing output has
a null digest; unrecorded output has a null artifact UUID. A recorded output always has a
digest. Orders without sessions retain their existing manifest shape. The operational
`session-output-invalid` reason identifies missing output or failed schema/recording lint.
The recording boundary checks unique input paths in linear time; object-level array
uniqueness is deliberately not a schema check for potentially large staged source trees.

## Validation plan

`artifacts_schema/v1/validation-plan.schema.json` is a strict structural contract for the
`validate-findings` plan emitted by `plan.py`: target, scope-binding mode, ordered steps and
chains. Its allowed keys come from `Step.to_dict()`, `Chain.to_dict()` and `write_plan()`;
techniques, adapters, classifications and scope modes reuse the validation report's vocabularies.
Unknown fields and invalid types fail, including agent-supplied approval or scope grants.

This schema **does not authorize execution**. A caller must bind the approved artifact digest
to a verified principal and current scope, classify each command against its actual operands,
and re-check the target immediately before dispatch. Browser plans use a different envelope and
object-valued payloads; they are not accepted by this initial contract. Duplicate step IDs,
precondition references and chain links also need service checks: JSON Schema validates each
item, not relationships among items. An edited or recon-extended plan is a new artifact and
needs a new authorization decision.

## Complete impact preparation snapshots

`impact-analysis` metadata may name a `preparation_scope`: a content digest and
the complete ecosystem/module/installed-version member set prepared for one
advisory and commit. Every package packet carries that same scope. Core validates
membership and consistent member sets, then promotes a replacement only after all
members have recorded evidence. A partial newer run cannot clear a prior affected
snapshot; a complete corrected snapshot can replace obsolete package versions.
Historical queries use the latest complete snapshot at their cutoff. The field
remains optional so historical single-packet reports retain their defined meaning.

## Below-range packets and verdicts

`artifacts_schema/v1/below-range-packets.schema.json` is one commit's below-range evidence:
installed versions an advisory's stated ranges leave out, each as a packet (the advisory, the
chosen fix and why, the installed source's registry URL and sha256, per-hunk presence) or a
coverage gap with its reason. An `impact` assessment of the commit holds it (not `tool_scan`,
whose latest document readers take to be `code-facts`). Source trees are
not stored: review refetches each by URL and checks the digest.

`artifacts_schema/v1/below-range-verdicts.schema.json` is the review of one packets document,
held by a second `impact` assessment of the same commit: two blind reviews per packet, a judge on a
split or an `undetermined` review, the final verdict, and the coverage gaps carried unchanged.
Only `applicable` becomes a finding. Row consistency (every packet reviewed once, the judge
exactly when needed, the verdict the agreed one or the judge's) is checked by the recording
service, not the schema.

## Fuzz report

`artifacts_schema/v1/fuzz-report.schema.json` is the document a `fuzz` assessment holds
(run-bound: the assessment owns repository, commit, producer and time). It records the
target's harnesses (engine, duration, execs, outcome), every crasher that is a candidate
finding (signature, reproducer sha256, sanitizer, CWEs, proposed severity, optionally the
existing finding it confirms), measured coverage (null when not measured) and the surfaces
left unfuzzed with a reason. Crashers enter the finding lane through intake; static or
grep-sweep confirmations are not fuzz crashers and a clean run records none. Run counts
derive from the harness outcomes. Harness-name references are checked by the recording
service, not the schema.

Optional batch and tested-pattern associations preserve per-target measurements;
unknown outcomes stay null. Per-crasher analysis carries supplied narratives,
fixes, priorities and negative-control references without changing intake validity.
`fuzz-campaign.schema.json` is a separate supplied scope reference: it preserves
legacy aggregate counts and analyst Markdown verbatim, not fabricated run evidence
or target-level associations. The content gate enforces vulnerable counts no
greater than tested counts.

`repo-liveness.schema.json` is the forge observation owner's latest reference
snapshot keyed by registered repository UUID. It records availability, observation
time and the start of an unchanged status without inventing a commit for a missing
repository. Unqueried has no entry; unknown is not evidence of deletion. No new
database table is introduced.

## PQC vendor claims

`artifacts_schema/v1/pqc-vendor-claims.schema.json` is a declared reference document
(scope-ref, like `sla-policy` or `org-parameters`): curated, dated claims about the
post-quantum roadmap of vendors and dependencies the fleet cannot fix locally. Each claim
names its vendor class, the packages that carry it, a status, at least one source URL,
`last_reviewed` and the reviewer. It is imported whole with no assessment; a review is a
successor version with a higher `version`, and readers take the latest. Fleet counts are
derived by the reader, never stored.

## Storage contract

`artifacts_schema/v1/code-facts.schema.json` defines recorded symbols, measured
language/LoC counters, package module/import/export facts and service-interface
observations for `tool_scan` assessments. The assessment identifies the scanned ref
and producer. Null sections are unmeasured; empty collections are measured empty
results. Locations stay relative to the scanned ref. These artifacts add no
database tables or columns.

`db/v1/traust` is the one-owner data model (XWING-2363): readable, authored
SQLite/PostgreSQL SQL — each concept one owner, database-generated UUID v4
identity (`gen_random_uuid()` / SQLite's `uuid()`), real constraints. Namespaces:
`traust` (domain), `traust_ops` (operations), `traust_ledger` (ledger)
— each owns its top-level directory
(`db/v1/traust`, `db/v1/traust_ops`, `db/v1/traust_ledger`) and loader, with Postgres schemas and
cross-schema FKs, and SQLite table prefixes in one database file. See the
[model README](db/v1/traust/README.md).

```python
import sqlite3

from traust_contracts.v1.storage.sql import bootstrap_files, bootstrap_statements

conn = sqlite3.connect("traust.db")
conn.execute("PRAGMA foreign_keys = ON")
for path in bootstrap_files("sqlite"):
    for statement in bootstrap_statements("sqlite", path):
        conn.execute(statement)
```

SQLite is complete with stdlib; the caller-selected database file is its
physical namespace. PostgreSQL >=14 uses the optional `postgres` extra
(`psycopg>=3`, requiring libpq or separately installed `psycopg[binary]`).

The model lands part by part (see the [status table](db/v1/traust/README.md));
queries, views and the write protocol (Store) follow once the DDL has landed.
The previous projection model was removed with this revision — databases
created under it are recreated, not migrated.

## Ledger relational contract

`db/v1/traust_ledger` is the `traust_ledger` namespace of the one-owner data model:
append-only proof of decisions. `layers` — one per repository, or one per
branch line — carry the Merkle root, epoch, size and signature; `events` —
one per decision, `UNIQUE (decision_id)` — carry the opaque, signed payload
and the layer sequence. The traust-ledger library computes and signs; the
app stores. Optional: off means no proof, never broken queries.

Contracts owns the authored DDL — tables, constraints, indexes and
append-only enforcement triggers — plus deterministic bootstrap order.
Bootstraps after `db/v1/traust`: layers and events reference `repository`,
`repository_ref` and `decision` there. SQLite: `ledger_` table prefixes in
the same database file. `CONTRACT_VERSION = "v1"`, `REVISION = 1`;
databases created under the earlier ledger are recreated, not migrated.

## Enum registry

`enums/v1/` holds one file per controlled vocabulary. Every string `enum` in
`artifacts_schema/v1` and `config/v1` must match a registry file by its exact set of
values; `tests/test_enum_registry.py` enforces this. `ci/enum_registry.py
--write` derives each file's `used_in_schemas`, and `--check` verifies the
rest.

Operational DDL vocabularies are registered in `run-order-state`, `run-order-reason`,
`work-lane` and `rescan-event-source`. Their existing registry representation uses an
empty `source_schema`, `schema_enforced: false` and `used_in_schemas: []`: the values
classify live `traust_ops.run_order` columns, not a JSON Schema site. Core loads these
files and checks new writes; historical rows are not rewritten. Asset names remain
pack vocabulary rather than work lanes. Reason codes are stored on orders; diagnostic
detail belongs in structured logs.

`degraded-key` binds the run manifest's key node without closing historical JSON
over an incomplete set of subjects. It declares common comparison/database causes
and ledger counters; registered feed and view identifiers retain their own names
and counts. Core enforces new completion keys against those owners before manifest
publication. The schema keeps its existing lowercase key shape and positive-integer
counts so imported manifests remain readable; no serialized namespace or version
field is introduced.

A registry file has `name`, `source_schema`, `description`, `values` and
`used_in_schemas`, plus these optional fields:

| Field | Meaning |
|---|---|
| `definitions` | What each value means; one entry per value |
| `standard` | The standard followed: `name`, `relationship` (`exact` or `adapted`, where adapted needs a `note`) and an optional `url`. Or `{"none": "<why>"}` |
| `deprecated` | For each deprecated value, `replaced_by`: the registry values (`{enum, value}`) that replace it. Several entries split a value across vocabularies; an empty list is a one-way drop, where readers keep the original string. A replacement is never itself deprecated. `"retired": true` marks a value that a major release removed from `values`. |

Vocabulary changes are made in place: new values are added (a minor
release). An old value then goes through two stages:

1. **Deprecated.** It stays in `values`, so the schema still accepts it.
   Readers normalise it to its replacement, and writers stop emitting it.
2. **Retired**, in a major release. It is removed from `values`, so the
   schema rejects new writes. Its `deprecated` entry stays, with
   `"retired": true`, because ledger events keep their original strings for
   good and readers must always be able to normalise them. Rules that depend on other fields, and moves
between fields, are not registry data; they belong in the code or schema
change that needs them.

### Historical classifier mappings

`mappings/v1/classifiers.json` records field-specific historical projections for
classifier plan 04. It ships as package data; `enums/v1` still owns the vocabulary.
The table does not change schemas, activate writers, migrate a database or rewrite
historical reports. Core's registry normalizer remains unchanged.

The offline audit consumes typed observations rather than guessing JSON types from
the old tally's string keys:

```json
{"fields":{"security-audit|finding.severity":{"total":2,"raw_values":[{"raw":"HIGH","count":1},{"raw":"urgent","count":1}]}}}
```

```bash
python ci/classifier_mappings.py --inventory typed-inventory.json --out coverage.json
python ci/classifier_mappings.py --inventory typed-inventory.json --out coverage.json --check
```

Exit 0 means the audit ran successfully; `--check` instead exits 1 when observations
remain explicitly unmapped. Malformed input, incomplete declared totals or invalid
mapping targets exit 2. Output includes every typed observation, its disposition,
counts and source/mapping/registry hashes. Inventory examples and coverage can
contain private portfolio data: keep them with their source, not in this repository.

Aliases are exact and field-specific. Approved severity/size/priority spellings
project to existing values; durations, deadlines and ordinal priorities are not
guessed. Legacy effort with no approved size projects to null; only explicit
external-blocking evidence sets `blocked_external`, independently of size.
`not_verified` supplies no validity answer; `corrected` remains an operation, not
a verdict. A target is not a complete Decision or Assessment import payload.
Target-free `unmapped` aliases can block unconditional registry fallthrough:
historical review status `rejected` needs the individual `resolution_note` to
distinguish an actual rejection from `bulk-closed` → `closed_unreviewed`.
The scalar inventory and aggregate note cross-tab cannot supply that context.
Inventory `nullable` permits observed null/absence, not schema or write acceptance;
the string `"null"` remains distinct. Existing OWASP ratings are preserved.

## Validate an artifact

```bash
python validate.py --schema report myreport.json
python validate.py --list
```

Report `validation_status` remains optional and non-null. Newly authored unjudged
findings omit it; Core's new-report admission checks any explicit value against
the canonical members of the installed validity registry. The base schema keeps
historical members readable and does not rewrite stored artifacts. Revision
context is not a validity answer, and finding kind does not establish proof.

Triage findings may carry the same optional, non-null `kind` as report findings:
`vulnerability` or `weakness`. Omission keeps the kind unknown; it never defaults
to vulnerability. A verified defense-in-depth gap is `verdict: true_positive`
with `kind: weakness`, not `verdict: confirmed`. Kind alone does not establish
confirmation. Historical `verdict: hardening` remains readable without rewriting
stored reports; the triage `#/$defs/canonical_write` profile rejects it for new writes.
That profile also retains the existing claimed-severity vocabulary/null constraint.
For true-positive weaknesses it requires exclusion rule `13` (integer or string)
and rejects non-null severity; omitted severity remains valid. Conversely, a true
positive carrying rule `13` must explicitly declare `kind: weakness`. These
cross-field constraints apply only to canonical writes, not historical reads.

Summary keys and verifier vote counters are unchanged. `summary.hardening` counts
historical hardening verdicts or true positives with kind weakness;
`summary.true_positives` counts the remaining true positives. The buckets are
disjoint, and `summary.by_severity` includes only actionable non-weakness true
positives. Confirmed weaknesses have null severity and exclusion rule 13.
Legacy `hardening` verifier vote labels/counters remain valid; they are not a new
final triage verdict.

### Canonical-write review candidate

Default schemas preserve historical effort values, free-text roadmap fields
and open extra-property values. The optional `blocked_external` fact is
independent of effort size. Canonical sizes and priority labels are defined in
[`effort`](enums/v1/effort.json) and
[`roadmap_priority`](enums/v1/roadmap-priority.json); no duration thresholds,
urgency policy or automatic legacy-size mappings are defined.

Explicitly select the stricter contract without adding serialized fields:

```bash
python validate.py --schema 'report#/$defs/canonical_write' myreport.json
```

The same `#/$defs/canonical_write` selector exists for `adapter-result`,
`validation`, `pqc-blockers`, `pqc-readiness`, `threat-model`, `triage` and
`refuted-register`.
The decision tree follows its existing definitions convention:
`pqc-decision-tree#/definitions/canonical_write`.
These fragments preserve existing requiredness and permit only actual boolean
blocking flags, not strings or null. On formerly open objects the default reader
properties remain unconstrained so historical extra values stay readable.
Mitigation and decision-tree rule effort remains required even when blocked;
unknown-size omission is not an approved policy.

This is an unreleased, known-size review candidate, not a producer switch.
Default validator selection is unchanged. Reader normalization, event-identity
gates and affected-contract review still precede writer activation/publication.
Existing report, baseline and event bytes are never rewritten.

## Test

```bash
make setup    # uv sync + enable .githooks
make test     # SQLite + schema tests; PG tests included when db-up
```

PostgreSQL e2e:

```bash
make db-up    # start local Postgres container
make test     # includes PG storage + ledger schema tests
make db-down
```

`make schema-diff` reports schema changes vs `origin/development` that traust-core may need to absorb.
PostgreSQL tests run automatically when `psycopg` and the database are available;
otherwise they skip.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
