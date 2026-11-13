# Traust Contracts

Source of truth for JSON schemas and enums shared across the Traust ecosystem,
plus generated Python bindings, **the configuration contract** (the one place
that knows what config exists and how it loads), and **storage/v1** (the SQL-first
relational contract for the one-owner data model).

## Before adding anything to the data model

Six questions gate every change to this repo's schemas, enums and DDL. If a
change can't answer all six, it isn't ready — reviewers will ask, so answer
them in the PR description:

1. **Is it a fact or a derivation?** If a value can be computed from what's
   already stored (e.g. `publication_revision` = `ORDER BY kind, created_at`),
   it doesn't get a column. Derivations live in the services that read them.
2. **Is there a named producer?** A concept exists when a producer emits it —
   a merged producer, not a planned one. If the only producer is an unmerged
   PR, the column waits (`schema-concepts-need-producers`).
3. **Does core already do this work?** Check before modeling: if traust-core's
   service layer already derives it (e.g. `SqlSpendEventRepository`
   `.sum_by(REPOSITORY)` joins `run_order` for repository attribution), a
   stored copy needs a *hot-path reader* to justify itself — a dashboard
   query is not one.
4. **Is this the smallest additive change?** It should land as additive
   bootstrap statements only. If the change needs to mutate existing rows,
   rewrite history, disable append-only guards, or reach into
   already-bootstrapped databases in-place — stop: that is a mechanism to
   design, not a script to write.
5. **Where does the invariant live?** Triggers are for what only the database
   can enforce — append-only guards, mutation rejection, and consistency that
   must hold for every concurrent writer (the existing
   `spend_event_lane_of_order` and `run_order_work_item_of_repository` guards
   are the precedent). A join predicate between two stored columns, written
   by a single service, is an `EXISTS` check in that service's write path.
   Every *new* trigger must answer: "why can't the sole writer enforce
   this?"
6. **What's the blast radius?** One PR = one contract change. If a change
   touches artifact ordering, spend attribution, tracker scoping, evidence
   schemas, and views at once, it's several changes — split it, and review
   each against the six questions above on its own.

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

## Database bootstrap boundary

`bootstrap_files()` / `bootstrap_statements()` define the static starting DDL.
New schema changes are additive bootstrap statements only: they do not upgrade
an already-bootstrapped database. No versioned migration runner or applied-state
ledger exists yet. Existing `*_upgrade` helpers are deprecated legacy territory;
do not extend that pattern. Reaching existing databases requires the separately
designed upgrade feature, not conditional scripts or historical backfills.

## Stored census observations

`insight-builds` requires a fresh `built_at` observation timestamp, a nullable
pre-fold `folded_after` decision watermark and the view documents. Reobserving
unchanged or returning views must publish a new document; serving age still uses
the artifact row's database `created_at`, not either document timestamp.
The additive `idx_decision_nonmachine_recorded` index covers actor-bearing
statements outside the canonical `machine:` namespace, including legacy spellings.
This is conservative cache invalidation, not identity verification or decision authority.

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

## Scheduled fork facts

`run_order.fork_scheduled_at` records when the scheduling door set an order's
fork facts, after its fork-policy and branch checks: the order's own proof that
they were checked, so a later policy change never unvouches them. A stamp
vouches only with both `fork_url` and `fork_branch` set. Older orders carry no
stamp and are checked against the current policy. Existing databases apply
`ops.sql.run_order_fork_scheduled_upgrade(dialect)` when the column is absent.

## Artifact recording order

`artifact.run_order_id` names the order whose run recorded the document, so a run
can tell its own report from an earlier one on the same assessment; null means it
was recorded outside an order or imported. An insert guard requires the order to
own the artifact's assessment: the work item it runs, or an assessment it
produced. Existing databases apply `storage.sql.artifact_run_order_upgrade(dialect)`
when the column is absent; existing artifacts name no order.

## Spend declaration attribution

`spend_event` retains nullable `repository_id`, raw `repository_label`, nonnegative integer
`loc`, `batch` and `note`. Canonical repository identity is a foreign key, not a slug inferred
from a label. Historical metadata stays null; unresolvable labels still retain their cost.
`repository_id` is only for order-less imported declarations: a CHECK rejects
storing it alongside `run_order_id`, even when both would name the same repository.
Ordered spend derives its repository by joining `run_order`; a repository-less
order stays unattributed. The existing lane/order guard remains unchanged.

## Reviewed claim and advisory replay artifacts

`finding-claim` pins the finding, repository, source assessment and label, retained replacement
claim, prior fingerprint/title/accepted decision and complete original occurrence-ID set.
Core verifies the snapshot under review; acceptance appends decisions, not rewritten occurrences.
`finding-intake` retains native scanner label/fingerprint bindings for the exact repository
and commit. Unretained historical sources cannot authorize a correction by guessed label.

`cve-replay` snapshots bind one real audit and its exact report artifact, per-audit watermark,
revision and advisory checks. Structural validation is not authority: only a verified human
with evidence can confirm historical presence. Discovery alone never establishes a missed
vulnerability or admits benchmark truth. A `detected` advisory can retain unknown presence
when named in the original report, but cannot contradict human-confirmed absence.
`not_applicable` requires human-confirmed absence or recorded source withdrawal.
A `detected` verdict names at least one advisory matched in the bound report; a `missed`
verdict names none - verdicts never contradict the report's own matches.
Candidates retain the source `withdrawn` boolean (optional, default false) so withdrawal
does not invent historical absence or require fabricated human presence evidence.


## Default-head naming time

`repository_ref.default_named_at` records when the row was last named the default
head (an import or an observation). A line is immutable once recorded, so the
row's creation time cannot order competing namings: a re-import of a previously
recorded head must still win over an earlier observation. Existing databases
apply `storage.sql.default_named_at_upgrade(dialect)` when the column is absent;
already-flagged rows keep an unknown naming time until the line is named again.

## Algorithm-free finding identity

Exact finding reads that omit `fingerprint_algo` use the schema-owned
`idx_finding_repository_fingerprint` index on `(repository_id, fingerprint)`,
on both SQLite and PostgreSQL. The existing unique `(repository_id,
fingerprint_algo, fingerprint)` constraint remains the identity owner; multiple
matching recipes remain ambiguous, not merged or ranked.

## Attempt-scoped external references

`finding_external_ref.assessment_id` optionally attributes an external link to one
assessment, including a remediation work item's PR. Finding-wide historical Jira
links remain null; the contract does not infer an attempt from a shared finding.
Core's write boundary validates pairing on inserts and scope changes, including
remediation assessments with no occurrence, and keeps a finding's repository
identity immutable. These are Core-owned invariants, not promises that independent
foreign keys reject arbitrary SQL writes. The schema's one scope guard rejects
repository-ref moves that invalidate existing links. Existing
`(system, ref, finding_id)` identity remains unchanged.

## Pack spec

`config/v1/pack.schema.json` is the shape of a workload pack's `assets.yaml` (the
security pack lives in traust as `packs/security/assets.yaml`). traust-engine plans and
admits from `deps`, `partitions`, `trigger`, `priority`, `freshness` and `admission`;
runners execute from `run`, `params`, `runner`, `model`, `writes`, `riders` and
`outcomes` in their pinned copy. The schema is strict, so a key one reader doesn't know
fails for both.

## Insight view contracts

`views_schema/v1/` contains data-only JSON Schemas for ephemeral, derived
Insight `ViewModel` output. This category is separate from persisted
`artifacts_schema/v1` documents and SQL storage: it introduces no artifact
discriminator, stored projection, table, migration or generated model binding.
The schemas ship as package data in wheels and source distributions.

`views_schema/v1/critical-misses.schema.json` is the Draft 2020-12 contract for
the critical-misses view. It requires an explicit `window` (`start` and `end`
RFC3339 timestamps) and a `misses` array, including when that array is empty.
Each row preserves the existing finding and repository IDs, raw untrusted title,
discovering and missed producer IDs, discovery time, reason and nullable validity.
`missed` denotes an actual miss; `area_reported` requires adjudication. Validity
remains an arbitrary historical string or null, not a newly closed vocabulary.
Empty output does not establish clean coverage or a detection rate.

Traust-core is the consumer and owns the typed `ViewModel`, the schema-validation
facade, timezone-aware increasing-window checks, Insight registration and
structured human-readable rendering. The producer remains
`DetectionQualityService.critical_misses(TimeWindow)` using current recorded
dispositions, not a historical `as_of` claim. Consumers reach this contract
through Core; they do not add detection logic or import rendering internals.
Use JSON Schema format checking to enforce UUID and date-time fields; the schema
does not compare window endpoints. The legacy CLI JSON array remains a consumer
compatibility surface, separate from this `{window, misses}` view contract.

`views_schema/v1/pqc-worklist.schema.json` is the Draft 2020-12 contract for
Core's ephemeral PQC worklist. Its required wrapper fields are `product_id`,
`repository_ref_ids`, `chokepoints` and `entries`. A null ref scope means all
refs in scope; an empty array means none. Core intersects explicit ref scope
with the selected product's shipped refs. Chokepoints are caller-supplied URL
fragments, not persisted configuration.

Entries preserve the legacy repository/ref IDs, raw repository and SHA strings,
priority tier (`chokepoint`, `crypto-cwe`, `tail`), route (`source`, `sbom-only`,
`access-request`), nested liveness, reason, nullable scan state and cursor.
Liveness requires `status` from the artifact liveness vocabulary, including `unknown`;
register the local artifact schemas alongside the view schema to resolve this reference offline.
Liveness preserves nullable observations, optional nullable `status_since` and `canonical_url`,
and historical `pushed_at`, `unobserved` and reason strings. Scan currency and liveness
booleans distinguish unknown null from measured false; neither establishes readiness.
Objects are strict and all other serialized fields are required, including nullable fields.
Use format checking for UUIDs and observation/status timestamps; raw repository, SHA,
scope and historical strings have no invented URL, hash or markup restrictions.

Core owns `PqcService.worklist`, scope intersection, representative-ref choice,
ranking, routing, cursor ordering, validation and safe human-readable rendering.
Building this view uses recorded state only: it does not scan, check out code
or write storage. The legacy CLI JSON array remains separate from this canonical
wrapper, and raw untrusted strings remain data rather than authored Markdown
or HTML.

`views_schema/v1/compliance-precision.schema.json` wraps the native
`DetectionQualityService.calibrate_compliance(framework, gate=...)` result as
`{calibration: {framework, assessments, checks, gate}}`. Framework IDs reuse the
packaged compliance-assessment schema's framework-id vocabulary via `$ref`;
validators must provide a local artifact-schema registry, not fetch the reference
over the network. Each check contains the raw untrusted `check_id`, nonnegative
`fired` and `dismissed` counts, `gate`, nullable `precision` and boolean `flagged`.
Gates and measured precision are numbers in [0, 1]. Unknown fields are rejected
at the view, calibration and check boundaries.

This is review precision for recorded automatic `not_satisfied` compliance check
firings and attributed human dismissals, **not evaluator calibration**, a
compliance score or a coverage claim. The producer considers recorded assessment
documents deduplicated by digest for the requested framework; `assessments` is
not a coverage denominator. With no firings, precision is null (unmeasured), not
perfect; an empty population likewise establishes no precision or coverage.
Core derives `(fired - dismissed) / fired` and flags measured precision
`<= gate`, inclusively, for review only. JSON Schema checks structure and ranges,
not arbitrary count arithmetic, derived flag correctness or cross-field gate
equality. No check demotion, evaluator mutation, scan or persistence is implied.
Core owns the typed wrapper, validation, Insight registration and shared human
rendering. The CLI's flat native calibration JSON remains a separate compatibility
surface rather than this canonical wrapper.

`views_schema/v1/benchmark-scorecards.schema.json` is the contract for the
benchmark-scorecards view: a `scorecards` array, oldest auditor version first and
empty when no benchmark audit is recorded. Each scorecard carries overall recall,
recall by CWE, severity, target provenance, language and split, near misses (review-tier
matches, counted here; identities live in the run's Expected-finding matches table, and
they never count as detected), the injection summary, mean run-to-run stability, targets
scored and skipped, and its auditor versions. A recall is `detected` over `expected`,
`null` when nothing was expected
(never 0). The producer is `DetectionQualityService.scorecards` over the recorded
benchmark audits against the newest answer key; held-out targets are release scoring
and never in this view. Scoring a directory of unrecorded runs stays a Core door,
not a view.

`views_schema/v1/inventory-export.schema.json` defines the ephemeral global inventory
view as `{rows: [...]}`. Each row requires the eight existing inventory columns:
`Repository`, `URL`, `Host`, `Organization/Group`, `Repo Name`, `Owner Team`,
`Products` and `Accountable Contacts`. The first five are strings; the last three
are string arrays, including empty arrays. Unknown fields and null lists are refused.
Raw text has no new URL or markup restrictions; Core owns safe rendering, bounded
composition and ordering. No inventory declaration, stored projection or new artifact
kind is introduced. The CLI retains its legacy bare JSON array separately from this
canonical wrapper, with CSV produced by Core's shared renderer.

`views_schema/v1/findings-rollup.schema.json` is the contract for Core's findings-rollup
view: disposition-aware finding counts for a scope at a point in time. It requires every
serialized field, nullable ones included (`as_of` null means current recorded state). `total`
counts each finding in scope once. `products` has one row per product the filter names, and a
finding in a repository several products ship counts under each, so product rows can sum to
more than `total`. `repositories` has one row per repository in scope, including those with
no findings. A tally separates `open` (exposure, by severity) from hardening, resolved,
risk-accepted and false-positive findings; `tracked` is everything but false positives.
`top` lists the open critical and high findings. `cvss_score` is an exact decimal string from
0 to 10 in its shortest fixed-point form (compare as decimals), or null when unscored. `categories` counts findings per category label (null key =
unlabelled); its `open_by_severity` always carries the five rated keys and carries `unrated`
only when counted. `attack_scenarios` is filled only for a product or team scope. Severity keys
match the `scanner-severity` registry. JSON Schema checks structure and ranges, not count
arithmetic. Core owns the typed `FindingsRollup` model, the scoping and disposition fold,
validation and rendering; titles, URLs, labels and narrative steps are raw untrusted data.

`views_schema/v1/findings-trend.schema.json` is the contract for Core's findings-trend view:
the scope's findings replayed bucket by bucket to `as_of` and summed over its repositories,
each metric's direction, and the accepted-risk register. Every serialized field is required,
nullable ones included. A point's open counts, accepted, hardening and risk indexes stand at
the bucket's end; new, resolved, regressions, false positives and decisions happened within
it. A risk index is the CVSS sum (else severity-band midpoints) and is null, unknown, when any
standing finding has neither; a metric unknown in the compared buckets has no direction,
because unknown is not zero. `open_by_severity` carries the five rated keys and `unrated` only
when counted. A direction with no baseline has no change and no rising/falling, and a flat one
is never worsening. The register's severity is null for an unrated finding, which ranks last;
a CVSS score of 0 still ranks above an unscored one, and `cvss_score` is an exact decimal
string in its shortest fixed-point form. JSON Schema checks structure and ranges, not
arithmetic across fields. Core owns the replay, policy and rendering; titles, URLs,
principals and rationales are raw untrusted data.

`views_schema/v1/coverage.schema.json` is the contract for Core's coverage view (the census):
for a scope, what each repository had assessed by `population.as_of` (one row per repository
and kind, with the newest default-line assessment, or null when every one ran on another
branch, and the default-line and branch run counts), the repositories never assessed, and the
coverage gaps the latest default-line secure-code audits report. Every serialized field is
required, nullable ones included. An embedded assessment is a recorded row (`id`,
`created_at` and times always present). `kind` is served in its canonical spelling and
`status` is any non-empty recorded value: the `assessment-kind` registry is named, not
enforced, because historical stored values are preserved, and `assessment-status` has no
registry yet. The gap figures are read from the latest audits as currently recorded, not as
of `population.as_of`. A gap family counts at least one repository, at least one recording
signal (`structured`, `steps`, `text`) and up to eight unique example repositories. JSON
Schema checks structure and ranges, not arithmetic across fields. Core owns the census, gap
extraction and rendering; tools, systems and assessors are raw untrusted data.

`views_schema/v1/remediation-index.schema.json` is the contract for Core's remediation-index
view: every remediation work item of the scope's repositories as it stands now (there is no
`as_of`), grouped per named product in the filter's order or in one group whose `product` is
null, repositories by URL and each repository's items oldest first. A row carries the
product slug, repository URL, work item ID, status, covered finding count, HTTPS fork URL,
fix branch and tracker reference, the last three null until they exist. Statuses come from
the `remediation-status` registry, tied by test. `by_status` counts rows per status seen, so
a work item under several products counts once per product. Core owns the work-item fold and
rendering; URLs, branches and tracker references are raw untrusted data.

`views_schema/v1/census.schema.json` is the contract for Core's census view, the denominator
authority: for a scope as of `as_of`, the repository counts (in scope, reported,
dispositioned, never assessed), one cut per corpus ownership class present (registry order,
then the unregistered cut whose `ownership` is null; at most one each), the scope's products
by slug, and the declared-IaC and container findings counted apart from the cuts. A cut's
distinct vulnerabilities are default-line findings that are neither false positives nor
hardening; `occurrences`, `hardening`, `false_positives`, `branch_confirmed` and `branch_only`
say how the rest were counted. Severity counts always carry all six keys, `unrated` included.
Ownership classes use the `ownership` registry, tied by test. Every serialized field is
required. JSON Schema checks structure and ranges, not arithmetic across fields. Core owns the
corpus registry, the population and the fold; product names, business units and URLs are raw
untrusted data.

`views_schema/v1/attack-coverage.schema.json` is the contract for Core's attack-coverage
view: the scope's MITRE ATT&CK coverage as of `as_of` against the pinned ATT&CK release, with
modeled evidence (techniques the latest threat models cite) and weakness-derived candidates
(finding categories through the pack's category map) counted apart, never blended. Each
technique has at least one piece of evidence and a score: exactly 2 when modeled, else 1; 3
(observed) is refused until confirmed validation chains are recorded. Technique ids are ATT&CK
technique or sub-technique ids; `dropped` counts the raw citations that are not live in the
release, malformed references included.
`navigator_layer` is an ATT&CK Navigator layer (format 4.5): this contract checks its
envelope, MITRE's own schema governs the rest. Every serialized field is required. Core owns
the catalog, the category map and rendering.

`views_schema/v1/sla.schema.json` is the contract for Core's sla view: owner-response SLA
clocks over the scope's findings (false positives and hardening excluded) as of `as_of`, one
block per profile of the deployment's SLA policy, default first. Every serialized field is
required, nullable ones included. Each profile's nine counts place every in-scope finding in
exactly one bucket. Compliance is a 0–100 percentage or null when nothing resolved was
clocked. `overdue_by_severity` and `median_days_to_resolve` carry only the severities seen;
a median can be negative when a finding was resolved before its clock started. Team rows have
at least one overdue finding. The escalation digest holds at most 100 overdue findings, with
a null severity for an unrated one in scope through the CVSS floor and a title truncated to
120 characters. `clock_start` uses the `sla-clock-start` registry, tied by test. JSON Schema
checks structure and ranges, not arithmetic across fields. Core owns the policy resolution,
the clock ladder and rendering; names, titles and URLs are raw untrusted data.

`views_schema/v1/pqc-portfolio.schema.json` is the contract for Core's pqc-portfolio view:
post-quantum readiness worklists as recorded now (no `as_of`), one scope per named product or
a single scope with a null `product_id`, and a product index (worst first) when no product is
named. A scope lists its assessed commits worst first with their readiness records, the crypto
decision sites with their facts, the crypto packages in its manifest SBOMs, and the commits
without an SBOM. Readiness records and facts are Core's projections of the `pqc-readiness` and
`pqc-facts` documents with every optional field present (null when absent), so they are
defined here rather than referenced. Scores are 0–100; every PQC vocabulary is tied to its
registry by test. Every serialized field is required; lists are never null. Named products
mean every scope is a product's and the index is empty. Core owns the readiness projection,
ranking and rendering; URLs, actions, primitives and file paths are raw untrusted data.

`views_schema/v1/threat-register.schema.json` is the contract for Core's threat-register view:
the scope's threats from each repository's latest completed threat model as of `as_of`,
ranked by band then status, with class-closing xs/s quick wins over unmitigated critical and
high threats, tenant boundaries weakest first and the open doc variances. Threats,
mitigations and boundaries are Core's projections of the threat-model documents. Fields Core
types (status, actor, bands, legacy likelihood and impact, isolation dimensions, interface
complexity, variance kind) are tied to their registries by test; fields Core serves as the
model states them (mitigation size and class closure, boundary kind, exposure and dimension
results, cited technique ids) stay raw. Every serialized field is required; lists are never
null. Core owns the ranking, the rating crosswalk and rendering; titles, URLs, claims and
evidence anchors are raw untrusted data.

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

`make schema-diff` reports artifact, configuration and derived-view schema changes vs
`origin/development` that traust-core may need to absorb.
PostgreSQL tests run automatically when `psycopg` and the database are available;
otherwise they skip.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
