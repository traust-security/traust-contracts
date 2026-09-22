"""Reference storage/v1 protocol: sqlite3 complete; optional psycopg>=3 for PostgreSQL."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from traust_contracts.paths import schema_dir, storage_dir
from traust_contracts.v1.storage.sql import (
    BASELINE_ID,
    CONTRACT_VERSION,
    REVISION,
    Dialect,
    bootstrap_files,
    bootstrap_statements,
    query,
    reserved_objects,
)

SQLValue = str | int | float | bytes | None
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
BINDING_DOMAIN = b"traust-binding-v1\x00"


ONE_ROW_PROJECTIONS: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {
    "adapter-result": (
        "adapter_result",
        (
            ("target", "scalar"),
            ("scanned_at", "scalar"),
            ("metadata", "json"),
            ("findings", "json"),
            ("summary", "json"),
            ("focus_areas", "json"),
        ),
    ),
    "adr-registry": (
        "adr_registry",
        (("version", "integer"), ("note", "scalar"), ("registers", "json")),
    ),
    "attack-mapping": (
        "attack_mapping",
        (
            ("mapping_version", "scalar"),
            ("attack_version", "scalar"),
            ("source", "scalar"),
            ("documentation", "scalar"),
            ("schema", "scalar"),
            ("attribution", "scalar"),
            ("capability_map", "json"),
            ("category_map", "json"),
        ),
    ),
    "benchmark-target": (
        "benchmark_target",
        (("version", "integer"), ("updated", "scalar"), ("targets", "json")),
    ),
    "cloud-config-audit": (
        "cloud_config_audit",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("summary", "json"),
            ("findings", "json"),
            ("gaps", "json"),
        ),
    ),
    "cloud-config-findings-current": (
        "cloud_config_findings_current",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("summary", "json"),
            ("findings", "json"),
            ("gaps", "json"),
            ("disposition_summary", "json"),
        ),
    ),
    "compliance-assessment": (
        "compliance_assessment",
        (("metadata", "json"), ("coverage", "json"), ("results", "json")),
    ),
    "compliance-mapping": (
        "compliance_mapping",
        (("version", "integer"), ("note", "scalar"), ("controls", "json"), ("checks", "json")),
    ),
    "compliance-scope": (
        "compliance_scope",
        (("version", "integer"), ("updated", "scalar"), ("boundaries", "json")),
    ),
    "doc-variance": ("doc_variance", (("metadata", "json"), ("records", "json"))),
    "fleet-fix": (
        "fleet_fix",
        (
            ("id", "scalar"),
            ("pattern_ref", "scalar"),
            ("description", "scalar"),
            ("matcher", "json"),
            ("resolver", "json"),
            ("rewrite", "json"),
            ("guards", "json"),
            ("tests", "json"),
        ),
    ),
    "impact-analysis": (
        "impact_analysis",
        (("metadata", "json"), ("summary", "json"), ("repos", "json")),
    ),
    "isolation-review": (
        "isolation_review",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("interfaces", "json"),
            ("gaps", "json"),
            ("posture", "json"),
            ("notes", "scalar"),
        ),
    ),
    "org-parameters": (
        "org_parameters",
        (
            ("version", "integer"),
            ("declared_by", "scalar"),
            ("declared_on", "scalar"),
            ("note", "scalar"),
            ("parameters", "json"),
        ),
    ),
    "pqc-blockers": (
        "pqc_blockers",
        (
            ("artifact", "scalar"),
            ("title", "scalar"),
            ("metadata", "json"),
            ("executive_summary", "json"),
            ("severity_criteria", "json"),
            ("findings", "json"),
            ("findings_summary", "json"),
            ("remediation_roadmap", "json"),
        ),
    ),
    "pqc-decision-tree": (
        "pqc_decision_tree",
        (
            ("tree_version", "scalar"),
            ("plan", "scalar"),
            ("schema", "scalar"),
            ("provenance_tree", "json"),
            ("remediation_effort", "json"),
            ("readiness_buckets", "json"),
            ("tls_control_crosswalk", "json"),
            ("fips_interaction", "json"),
            ("pqc_classification_map", "json"),
            ("server_side_caveat", "json"),
        ),
    ),
    "pqc-facts": (
        "pqc_facts",
        (
            ("artifact", "scalar"),
            ("repository", "scalar"),
            ("stamps", "json"),
            ("coverage", "json"),
            ("summary", "json"),
            ("facts", "json"),
        ),
    ),
    "pqc-readiness": (
        "pqc_readiness",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("scores", "json"),
            ("flags", "json"),
            ("provenance_summary", "json"),
            ("clock_items", "json"),
            ("readiness_bucket", "scalar"),
            ("fips_interaction", "json"),
            ("runtime_evidence", "json"),
            ("server_side_caveats", "json"),
            ("notes", "scalar"),
            ("remediations", "json"),
        ),
    ),
    "remediation": (
        "remediation",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("source_findings", "json"),
            ("fork", "json"),
            ("patch", "json"),
            ("checks", "json"),
            ("evidence", "json"),
            ("revalidation", "json"),
            ("pull_request", "json"),
            ("summary", "json"),
            ("notes", "scalar"),
            ("footer", "scalar"),
        ),
    ),
    "report": (
        "report",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("executive_summary", "json"),
            ("severity_criteria", "json"),
            ("findings", "json"),
            ("findings_summary", "json"),
            ("remediation_roadmap", "json"),
            ("dependency_audit", "json"),
            ("negative_results", "json"),
            ("asvs_coverage", "json"),
            ("scanner_correlation", "json"),
            ("peach_isolation_review", "json"),
            ("disposition_summary", "json"),
            ("footer", "scalar"),
        ),
    ),
    "risk-rating-methodology": (
        "risk_rating_methodology",
        (
            ("methodology", "scalar"),
            ("methodology_version", "scalar"),
            ("source", "scalar"),
            ("documentation", "scalar"),
            ("schema", "scalar"),
            ("bands", "json"),
            ("bucket_thresholds", "json"),
            ("likelihood_factors", "json"),
            ("impact_factors", "json"),
            ("matrix", "json"),
            ("fallback", "json"),
            ("threat_intel_factor", "json"),
        ),
    ),
    "sla-policy": (
        "sla_policy",
        (
            ("policy_name", "scalar"),
            ("source", "json"),
            ("severity_mapping", "json"),
            ("clock_start", "scalar"),
            ("profiles", "json"),
        ),
    ),
    "validation": (
        "validation",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("source_reports", "json"),
            ("summary", "json"),
            ("validated_findings", "json"),
            ("attack_chains", "json"),
            ("novel_findings", "json"),
            ("negative_results", "json"),
            ("execution_log_ref", "scalar"),
            ("execution_log_sha256", "scalar"),
            ("footer", "scalar"),
        ),
    ),
    "verification": (
        "verification",
        (
            ("title", "scalar"),
            ("metadata", "json"),
            ("summary", "json"),
            ("verified_findings", "json"),
            ("regressions", "json"),
            ("commit_timeline", "json"),
            ("evidence", "json"),
            ("recommendations", "json"),
            ("notes", "scalar"),
            ("footer", "scalar"),
        ),
    ),
}


@dataclass(frozen=True)
class Binding:
    scope_id: str = "local"
    subject_id: str | None = None
    run_id: str | None = None
    layer_id: str | None = None
    supersedes_binding_id: str | None = None


@dataclass(frozen=True)
class BindingRecord:
    binding_id: str
    artifact_digest: str
    artifact_name: str
    binding: Binding
    bound_at: str


@dataclass(frozen=True)
class IngestResult:
    digest: str
    binding_id: str
    already_bound: bool = False


class IngestError(ValueError):
    """Log-safe failure; original bytes require explicit access through payload."""

    def __init__(self, message: str, *, artifact: str = "", payload: bytes = b"") -> None:
        super().__init__(message)
        self.artifact = artifact
        self.payload = payload


def _error_detail(error: Exception) -> str:
    """Driver/validator messages and chained tracebacks can contain artifact contents."""
    if isinstance(error, IngestError):
        return str(error)
    if isinstance(error, ValidationError):
        path = "/".join(str(token) for token in error.absolute_schema_path)
        return f"schema rule {error.validator} at /{path}"
    if isinstance(error, json.JSONDecodeError):
        return f"invalid JSON at line {error.lineno}, column {error.colno}"
    code = getattr(error, "sqlite_errorname", None) or getattr(error, "sqlstate", None)
    return type(error).__name__ + (f" [{code}]" if code else "")


@cache
def validators() -> dict[str, Draft202012Validator]:
    schemas = {
        path.name.removesuffix(".schema.json"): json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(schema_dir().glob("*.schema.json"))
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    return {
        name: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }


@cache
def storage_profiles() -> dict[str, dict[str, Any]]:
    document = json.loads((storage_dir() / "profiles.json").read_text(encoding="utf-8"))
    profiles = document["artifacts"]
    if set(profiles) != set(validators()):
        raise ValueError("storage profiles must cover every artifact schema exactly")
    tables = {
        **{name: table for name, (table, _) in ONE_ROW_PROJECTIONS.items()},
        # Families that fan out to a differently-named table rather than
        # taking the one-row default.
        "layer": "layer_metadata",
        "triage": "triage_verdict",
        "vuln-findings": "finding",
        "corpus-registry": "subject_ownership",
        "threat-model": "threat",
        "operator-priv-profile": "priv_profile",
    }
    for name, profile in profiles.items():
        if profile.get("projection") != tables[name]:
            raise ValueError(f"storage profile {name} has the wrong projection table")
    return profiles


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _integer(value: int | float | None) -> int | None:
    """JSON Schema accepts integral floats; drivers need actual integers."""
    if value is None:
        return None
    if type(value) is int or (type(value) is float and value.is_integer()):
        return int(value)
    raise ValueError(f"expected int, got {type(value).__name__}")


def _boolean(value: bool | None) -> int | None:
    """Store a flag as 0/1 in an INTEGER column on BOTH dialects.

    storage/v1 has no BOOLEAN anywhere -- even traust_storage_meta uses
    INTEGER on PostgreSQL -- and the Go generator refuses a table whose
    column types differ between dialects, which is how the first attempt
    at this was caught.

    Absent stays absent: a disposition flag that was never set is NULL, not
    False. "Nobody overrode this false positive" and "we have no record
    either way" are different claims, and the two-person rule depends on the
    difference.
    """
    if value is None:
        return None
    if type(value) is not bool:
        raise ValueError(f"expected bool, got {type(value).__name__}")
    return int(value)


#: Ordinal weights for the threat rank score. The score is DERIVED here and
#: is deliberately not a schema field: `$defs/threat` sets
#: `additionalProperties: false`, so a producer that wrote one would emit an
#: invalid artifact, and reading a field the schema forbids is how
#: `threat.score` came to be NULL on every row. The product is a TRIAGE
#: ORDER only -- never a calibrated risk value and never comparable to CVSS.
_IMPACT_WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8, "existential": 16}
_LIKELIHOOD_WEIGHT = {
    "very_rare": 1,
    "rare": 2,
    "possible": 4,
    "likely": 8,
    "almost_certain": 16,
}


def _threat_score(impact: Any, likelihood: Any) -> int | None:
    """impact weight x likelihood weight, or None when either is unrateable.

    Zero would claim "rated, and it came out lowest"; the two enums are
    required, so an unrecognised value means the model is off-contract and
    the ordering has nothing to say about it.
    """
    left = _IMPACT_WEIGHT.get(impact if isinstance(impact, str) else "")
    right = _LIKELIHOOD_WEIGHT.get(likelihood if isinstance(likelihood, str) else "")
    if left is None or right is None:
        return None
    return left * right


#: Verdicts that mean nothing was executed, so a reason is owed. Any other
#: verdict was ATTEMPTED and has no skip to explain.
_UNATTEMPTED = frozenset({"not_attempted", "blocked_by_scope"})


def _skip_reason(finding: dict[str, Any]) -> str | None:
    """Why nothing was attempted, from wherever the producer records it.

    The reason is NOT a top-level property. `validated_findings[]`
    declares `not_attempted_reason`, but measured across the live corpus
    that field is empty on every row; what the lane writes is
    `steps[].scope_reason` -- `triage-false-positive`,
    `no-poc-no-adapter`, `wrong-surface:ci-build`. Reading the top-level
    key returned None on every not_attempted and blocked_by_scope
    rows, so the column separating "triage already ruled this out" from
    "we have no adapter for this surface" was NULL corpus-wide.

    GATED ON THE VERDICT, and the first cut was not. A finding has many
    steps and some may be scoped out while the finding as a whole is
    still proven; reading any step's reason put a skip reason on 945
    CONFIRMED findings, which reads as "we declined to test this" for
    something that was tested and held. A reason belongs only where
    nothing ran.

    Declared field first, then the step, so a producer that starts
    honouring the schema wins without another change here.
    """
    if finding.get("verdict") not in _UNATTEMPTED:
        return None
    declared = finding.get("not_attempted_reason") or finding.get("skip_reason")
    if declared:
        return str(declared)
    for step in finding.get("steps") or []:
        if isinstance(step, dict) and step.get("scope_reason"):
            return str(step["scope_reason"])
    return None


def _json_or_none(value: Any) -> str | None:
    """Encode a nested block for a JSON column, canonically. None stays None."""
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _identifier_bytes(field: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise IngestError(f"{field}: expected string")
    if "\x00" in value:
        raise IngestError(f"{field}: NUL is not allowed")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise IngestError(f"{field}: invalid Unicode") from None


def binding_id(artifact_digest: str, artifact_name: str, binding: Binding) -> str:
    """Return the storage/v1 binding identity over the specified byte tuple."""
    required = (artifact_digest, artifact_name, binding.scope_id)
    encoded = bytearray(BINDING_DOMAIN)
    for field, value in zip(
        ("artifact_digest", "artifact_name", "scope_id"), required, strict=True
    ):
        encoded.extend(_identifier_bytes(field, value))
        encoded.append(0)
    for field, value in (
        ("subject_id", binding.subject_id),
        ("run_id", binding.run_id),
        ("layer_id", binding.layer_id),
    ):
        if value is None:
            encoded.append(0)
        else:
            encoded.append(1)
            encoded.extend(_identifier_bytes(field, value))
            encoded.append(0)
    return hashlib.sha256(encoded).hexdigest()


class Store:
    """Caller-owned idle connection, tuple rows; never closes it or owns caller work."""

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.dialect: Dialect
        if isinstance(conn, sqlite3.Connection):
            self.dialect = "sqlite"
            conn.execute("PRAGMA foreign_keys = ON")
        else:
            try:
                import psycopg
            except ImportError as error:
                raise ValueError(
                    "expected sqlite3.Connection or install traust-contracts[postgres]"
                ) from error
            if not isinstance(conn, psycopg.Connection):
                raise ValueError("expected sqlite3.Connection or psycopg.Connection")
            if conn.info.server_version < 140000:
                raise ValueError("storage requires PostgreSQL >=14")
            self.dialect = "postgres"

    def _active(self) -> bool:
        return (
            self.conn.in_transaction
            if self.dialect == "sqlite"
            else self.conn.info.transaction_status != 0
        )

    def _rollback(self) -> str:
        try:
            if self._active():
                self.conn.execute("ROLLBACK")
        except Exception as error:
            return f"; rollback failed: {_error_detail(error)}"
        return ""

    def _idle(self, artifact: str = "", payload: bytes = b"") -> None:
        if self._active():
            raise IngestError(
                "storage requires an idle connection; caller transaction is untouched",
                artifact=artifact,
                payload=payload,
            )

    def _execute(self, sql: str, values: Mapping[str, SQLValue] | None = None) -> Any:
        return self.conn.execute(sql, values) if values is not None else self.conn.execute(sql)

    def _begin(self, artifact: str = "", payload: bytes = b"") -> None:
        try:
            self.conn.execute(
                "BEGIN IMMEDIATE"
                if self.dialect == "sqlite"
                else "BEGIN ISOLATION LEVEL READ COMMITTED"
            )
        except Exception as error:
            raise IngestError(
                f"artifact {artifact}: begin transaction: {_error_detail(error)}",
                artifact=artifact,
                payload=payload,
            ) from None

    def init(self) -> None:
        """Initialize a fresh database or verify its exact version; never imply a migration."""
        self._idle()
        self._begin()
        try:
            if self.dialect == "postgres":
                self._execute(query(self.dialect, "traust_storage_meta.lock.sql"))
            else:
                reserved = reserved_objects("sqlite")
                if any(
                    name.lower() in reserved or table.lower() in reserved
                    for name, table in self._execute(
                        "SELECT name, tbl_name FROM temp.sqlite_schema"
                    ).fetchall()
                ):
                    raise IngestError("temporary storage objects; explicit migration required")
            exists = self._execute(query(self.dialect, "traust_storage_meta.exists.sql")).fetchone()
            row = (
                self._execute(query(self.dialect, "traust_storage_meta.get.sql")).fetchone()
                if exists and exists[0]
                else None
            )
            if exists and exists[0] and not row:
                raise IngestError("empty storage metadata; explicit migration required")
            if row and tuple(row) != (CONTRACT_VERSION, REVISION, BASELINE_ID):
                raise IngestError(
                    f"database storage {row[0]} revision {row[1]}; "
                    f"package {CONTRACT_VERSION} revision {REVISION}: "
                    "explicit migration required; automatic upgrades/downgrades are not supported"
                )
            if not row:
                if self.dialect == "postgres":
                    occupied = self._execute(
                        "SELECT 1 FROM pg_catalog.pg_class c "
                        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'traust_storage' LIMIT 1"
                    ).fetchone()
                else:
                    reserved = reserved_objects("sqlite")
                    occupied = any(
                        name.lower() in reserved or table.lower() in reserved
                        for name, table in self._execute(
                            "SELECT name, tbl_name FROM main.sqlite_schema "
                            "UNION ALL SELECT name, tbl_name FROM temp.sqlite_schema"
                        ).fetchall()
                    )
                if occupied:
                    raise IngestError("unstamped storage objects; explicit migration required")
                for path in bootstrap_files(self.dialect):
                    for statement in bootstrap_statements(self.dialect, path):
                        self._execute(statement)
                self._execute(
                    query(self.dialect, "traust_storage_meta.upsert.sql"),
                    {
                        "contract_version": CONTRACT_VERSION,
                        "revision": REVISION,
                        "baseline_id": BASELINE_ID,
                        "applied_at": datetime.now(UTC).isoformat(),
                    },
                )
            self.conn.execute("COMMIT")
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(f"storage init: {_error_detail(error)}{rollback_error}") from None

    def get_evidence(self, digest: str) -> bytes:
        """Return exact evidence bytes without making a schema claim."""
        self._idle()
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            raise IngestError("artifact not found")
        self._begin()
        try:
            payload = self._evidence(digest)
            self.conn.execute("COMMIT")
            return payload
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"storage evidence read: {_error_detail(error)}{rollback_error}"
            ) from None

    def get_binding(self, binding_id_value: str) -> BindingRecord:
        """Return one binding without interpreting its evidence."""
        self._idle()
        if not isinstance(binding_id_value, str) or not DIGEST_PATTERN.fullmatch(binding_id_value):
            raise IngestError("artifact binding not found")
        self._begin()
        try:
            row = self._binding_row(binding_id_value)
            if row is None:
                raise IngestError("artifact binding not found")
            record = self._binding_record(binding_id_value, row)
            self.conn.execute("COMMIT")
            return record
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"storage binding read: {_error_detail(error)}{rollback_error}"
            ) from None

    def get(self, artifact: str, binding_id_value: str) -> bytes:
        """Return exact validated evidence through a type-checked binding."""
        self._idle(artifact)
        validator = validators().get(artifact) if isinstance(artifact, str) else None
        if validator is None:
            raise IngestError("unknown artifact schema", artifact=artifact)
        if not isinstance(binding_id_value, str) or not DIGEST_PATTERN.fullmatch(binding_id_value):
            raise IngestError("artifact binding not found", artifact=artifact)
        self._begin(artifact)
        try:
            row = self._binding_row(binding_id_value)
            if row is None:
                raise IngestError("artifact binding not found")
            record = self._binding_record(binding_id_value, row)
            if record.artifact_name != artifact:
                raise IngestError("artifact type mismatch")
            payload = self._evidence(record.artifact_digest)
            document = json.loads(payload, parse_constant=_reject_constant)
            validator.validate(document)
            self.conn.execute("COMMIT")
            return payload
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"storage read {artifact}: {_error_detail(error)}{rollback_error}",
                artifact=artifact,
            ) from None

    def ingest(
        self,
        artifact: str,
        payload: bytes,
        binding: Binding | None = None,
    ) -> IngestResult:
        """Validate exact bytes, bind context, and project atomically, or write nothing."""
        self._idle(artifact, payload)
        binding = binding or Binding()
        validator = None
        try:
            validator = validators().get(artifact) if isinstance(artifact, str) else None
            if validator is None:
                raise IngestError("unknown artifact schema")
            if not isinstance(payload, bytes):
                raise IngestError("payload must be bytes")
            document = json.loads(payload, parse_constant=_reject_constant)
            validator.validate(document)
            self._validate_binding(artifact, binding)
        except Exception as error:
            label = artifact if validator is not None else "<unknown>"
            raise IngestError(
                f"artifact {label}: validation: {_error_detail(error)}",
                artifact=artifact,
                payload=payload,
            ) from None

        digest = hashlib.sha256(payload).hexdigest()
        binding_id_value = binding_id(digest, artifact, binding)
        self._begin(artifact, payload)
        context = f"artifact {artifact}"
        try:
            if self.dialect == "postgres":
                self._execute(
                    query(self.dialect, "artifact.lock.sql"),
                    {"lock_key": int.from_bytes(bytes.fromhex(digest)[:8], signed=True)},
                )
            existing = self._binding_row(binding_id_value)
            if existing is not None:
                self._require_same_binding(binding_id_value, artifact, digest, binding, existing)
                self.conn.execute("COMMIT")
                return IngestResult(digest, binding_id_value, already_bound=True)
            if binding.supersedes_binding_id is not None:
                self._require_predecessor(artifact, binding_id_value, binding)

            context = f"artifact {artifact}, table artifact_evidence"
            self._execute(
                query(self.dialect, "artifact_evidence.upsert.sql"),
                {
                    "digest": digest,
                    "payload": payload,
                    "first_ingested_at": datetime.now(UTC).isoformat(),
                },
            )
            if self._evidence(digest) != payload:
                raise IngestError("artifact evidence digest collision")
            context = f"artifact {artifact}, table artifact_binding"
            self._execute(
                query(self.dialect, "artifact_binding.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "artifact_name": artifact,
                    "scope_id": binding.scope_id,
                    "subject_id": binding.subject_id,
                    "run_id": binding.run_id,
                    "layer_id": binding.layer_id,
                    "supersedes_binding_id": binding.supersedes_binding_id,
                    "bound_at": datetime.now(UTC).isoformat(),
                },
            )
            projection = storage_profiles()[artifact].get("projection")
            if projection is not None:
                context = f"artifact {artifact}, table {projection}"
            self._project(artifact, document, digest, binding_id_value)
            self.conn.execute("COMMIT")
            return IngestResult(digest, binding_id_value)
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"{context}: {_error_detail(error)}{rollback_error}",
                artifact=artifact,
                payload=payload,
            ) from None

    def query_findings_summary(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Return findings summary rows visible to the explicit scope list."""
        self._idle()
        if not scope_ids:
            raise IngestError("storage scope is required")
        for scope_id in scope_ids:
            _identifier_bytes("scope_id", scope_id)
        encoded = json.dumps(list(scope_ids), ensure_ascii=False, separators=(",", ":"))
        self._begin()
        try:
            if self.dialect == "postgres":
                self._execute(query(self.dialect, "scope.set.sql"), {"scope_ids": encoded})
            rows = self._execute(
                query(self.dialect, "findings_summary.list.sql"), {"scope_ids": encoded}
            ).fetchall()
            self.conn.execute("COMMIT")
            return rows
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"storage findings summary read: {_error_detail(error)}{rollback_error}"
            ) from None

    def _query_view(self, view: str, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Read a scope-gated dashboard view. One implementation, not four.

        Every dashboard read goes through here so the scope contract is
        stated once: PostgreSQL fails CLOSED, returning zero rows rather
        than erroring when no scope is set, which reads as "no findings"
        when it means "misconfigured". An empty list is refused for the
        same reason.
        """
        self._idle()
        if not scope_ids:
            raise IngestError("storage scope is required")
        for scope_id in scope_ids:
            _identifier_bytes("scope_id", scope_id)
        encoded = json.dumps(list(scope_ids), ensure_ascii=False, separators=(",", ":"))
        self._begin()
        try:
            if self.dialect == "postgres":
                self._execute(query(self.dialect, "scope.set.sql"), {"scope_ids": encoded})
            rows = self._execute(
                query(self.dialect, f"{view}.list.sql"), {"scope_ids": encoded}
            ).fetchall()
            self.conn.execute("COMMIT")
            return rows
        except Exception as error:
            rollback_error = self._rollback()
            raise IngestError(
                f"storage {view} read: {_error_detail(error)}{rollback_error}"
            ) from None

    def query_open_findings(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Open exposure: not affirmatively closed, not FP, not hardening."""
        return self._query_view("open_findings", scope_ids)

    def query_hardening_findings(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Posture debt, kept out of open exposure so the two never blend."""
        return self._query_view("hardening_findings", scope_ids)

    def query_distinct_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Lens 2: distinct problems over owned HEAD audits, not row counts."""
        return self._query_view("distinct_exposure", scope_ids)

    def query_census_population(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """The denominator, per tree -- counted from ownership, not findings.

        `with_report` is the coverage numerator. A subject with no finding
        is still coverage; a denominator built from findings silently drops
        it and overstates every percentage computed against it.
        """
        return self._query_view("census_population", scope_ids)

    def query_finding_timeline(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Per-finding clock: born, adjudicated, closed, and the durations.

        days_to_resolve is NULL while open -- a mean taken over closed
        findings alone is CENSORED and reads faster than reality, so the
        open ones must stay visible rather than vanish into a zero.
        """
        return self._query_view("finding_timeline", scope_ids)

    def query_exposure_trend(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Findings opened and closed per month, each identity counted once."""
        return self._query_view("exposure_trend", scope_ids)

    def query_sla_threshold(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """The deployment's own per-severity SLA thresholds, default profile.

        Exposed separately so a consumer can show what the policy IS, not
        only who breached it -- and so "which policy were we judged
        against" is answerable alongside the trend.
        """
        return self._query_view("sla_threshold", scope_ids)

    def query_finding_sla(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Age of every open finding, clock starting at FIRST OBSERVED.

        Includes still-open findings on purpose: the breaches are exactly
        the ones that never closed, so a closed-only view inverts the metric.
        """
        return self._query_view("finding_sla", scope_ids)

    def query_pqc_posture(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Post-quantum readiness per subject, with its owner."""
        return self._query_view("pqc_posture", scope_ids)

    def query_pqc_readiness_rollup(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """PQC readiness by bucket, counting SUBJECTS rather than assessments.

        A repo re-assessed five times is one repo in a bucket; counting
        assessments would inflate the portfolio by rescan frequency.
        """
        return self._query_view("pqc_readiness_rollup", scope_ids)

    def query_threat_current(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Modelled threats from the current register, with their owner."""
        return self._query_view("threat_current", scope_ids)

    def query_threat_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Threats aggregated by impact/likelihood/status, and whether evidenced.

        status stays UNCOLLAPSED: partially_mitigated is the largest bucket
        in practice, so folding it into mitigated overstates threat coverage
        more than any other choice available here.
        """
        return self._query_view("threat_exposure", scope_ids)

    def query_advisory_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Which repositories one advisory reaches, and on what evidence.

        EVIDENCE STRENGTH IS CARRIED, NOT COLLAPSED. "the symbol is
        reachable at a call site" and "the package is named in a
        manifest" are different claims; a rollup that blends them reads
        as though every hit needed the same urgency. `direct` likewise
        separates a first-order dependency from a transitive one -- the
        same advisory is a different remediation job depending on which.
        """
        return self._query_view("advisory_exposure", scope_ids)

    def query_validation_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """What happened when each claimed finding was ATTEMPTED live.

        The evidence lens. A finding confirmed by execution and a finding
        believed by inspection are different claims; this is the view that
        separates them.

        `verdict` stays uncollapsed and `attempted` is derived rather than
        filtered: `not_attempted` dominates the corpus, so reporting only
        attempts would describe a fraction of the lane's work and read as
        though the rest had been refuted.
        """
        return self._query_view("validation_exposure", scope_ids)

    def query_validation_current(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """One row per claimed finding, at the grain the evidence lens works.

        `validation_exposure` aggregates this; a consumer asking "what
        happened to THIS finding when it was attempted" needs the row, not
        the count. The view existed and was gated by the coverage test from
        the start, and had no query and no read method in either language --
        authored, enforced, and unreachable.
        """
        return self._query_view("validation_current", scope_ids)

    def query_attack_coverage(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """ATT&CK techniques with the strongest evidence the estate has.

        `evidence_tier` separates a technique somebody WROTE DOWN from one
        somebody PROVED: 3 a chain confirmed end to end, 2 a chain
        attempted and not confirmed, 1 modelled only. A Navigator layer
        coloured from the union of the two overstates coverage exactly
        where it matters most.
        """
        return self._query_view("attack_coverage", scope_ids)

    def query_verification_current(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Did each fix hold, per re-audited finding of the current run.

        `verdict` keeps all seven contract values; `held` is the derived
        binary beside it and is deliberately narrow -- only `resolved`.
        A false_positive means the finding was never real and
        risk_accepted means nobody fixed it; neither is evidence a fix
        worked, which is the one question `held` answers.
        """
        return self._query_view("verification_current", scope_ids)

    def query_verification_regression_current(
        self, scope_ids: Sequence[str]
    ) -> list[tuple[Any, ...]]:
        """What each fix BROKE. New findings, not restatements.

        Separate from verification_current on purpose: folding the two
        makes "how many findings did this verification touch" ambiguous,
        and this is the half a remediation review must not miss.
        """
        return self._query_view("verification_regression_current", scope_ids)

    def query_remediation_current(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """The findings each current remediation set out to fix.

        `validation_verdict` is the state AT REMEDIATION TIME, not now --
        the finding's current disposition is on current_finding.
        """
        return self._query_view("remediation_current", scope_ids)

    def query_compliance_posture(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Control verdicts of the current assessment, with their owner.

        One row per control per framework, never a percentage: a posture
        that reports a satisfied ratio and cannot name the unsatisfied
        controls is not an assessment. `verdict_source` stays uncollapsed
        and `assurance_tier` orders it, so satisfied-by-check and
        satisfied-by-human-override never read as the same claim.
        """
        return self._query_view("compliance_posture", scope_ids)

    def query_pattern_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Recurring weakness patterns, one row per CWE per cut.

        Fanned out of `cwes[]`, so a finding declaring two weaknesses counts
        under both. The dashboard this replaces grouped by the FIRST entry
        of the list and understated every weakness that was not listed
        first. `occurrences` therefore sums to more than the finding count,
        which is the correct reading of "how many findings involve this
        weakness" and the reason it is not named `findings`.
        """
        return self._query_view("pattern_exposure", scope_ids)

    def query_operator_privilege(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Privilege each operator ASKS FOR, parsed from shipped manifests.

        Declared state only -- never a live cluster read. Read as a runtime
        grant it is simply wrong.
        """
        return self._query_view("operator_privilege", scope_ids)

    def query_census_exposure(self, scope_ids: Sequence[str]) -> list[tuple[Any, ...]]:
        """Every finding classified once into an exhaustive exposure_class.

        The census asks several questions of one population -- owned,
        upstream, external-bu, cloud-config, branch re-audits -- and each is
        this data filtered differently. Consumers FILTER this; they do not
        restate the disposition policy, which is where the numbers drifted.
        """
        return self._query_view("census_exposure", scope_ids)

    def _validate_binding(self, artifact: str, binding: Binding) -> None:
        if not isinstance(binding, Binding):
            raise IngestError("binding: expected Binding")
        if binding.scope_id == "":
            raise IngestError("scope_id: required value missing")
        _identifier_bytes("scope_id", binding.scope_id)
        for field in ("subject_id", "run_id", "layer_id", "supersedes_binding_id"):
            value = getattr(binding, field)
            if value is not None:
                _identifier_bytes(field, value)
        for field in storage_profiles()[artifact]["required"]:
            if getattr(binding, field) is None:
                raise IngestError(f"{field}: required value missing")

    def _evidence(self, digest: str) -> bytes:
        row = self._execute(
            query(self.dialect, "artifact_evidence.get.sql"), {"digest": digest}
        ).fetchone()
        if row is None:
            raise IngestError("artifact not found")
        payload = row[0]
        if hashlib.sha256(payload).hexdigest() != digest:
            raise IngestError("artifact evidence digest mismatch")
        return payload

    def _binding_row(self, binding_id_value: str) -> tuple[Any, ...] | None:
        return self._execute(
            query(self.dialect, "artifact_binding.get.sql"), {"binding_id": binding_id_value}
        ).fetchone()

    @staticmethod
    def _binding_record(binding_id_value: str, row: tuple[Any, ...]) -> BindingRecord:
        digest, name, scope, subject, run, layer, supersedes, bound_at = row
        return BindingRecord(
            binding_id_value,
            digest,
            name,
            Binding(scope, subject, run, layer, supersedes),
            str(bound_at),
        )

    def _require_same_binding(
        self,
        binding_id_value: str,
        artifact: str,
        digest: str,
        binding: Binding,
        row: tuple[Any, ...],
    ) -> None:
        record = self._binding_record(binding_id_value, row)
        if (
            record.artifact_digest != digest
            or record.artifact_name != artifact
            or record.binding != binding
        ):
            raise IngestError("artifact binding identity collision")

    def _require_predecessor(self, artifact: str, binding_id_value: str, binding: Binding) -> None:
        predecessor_id = binding.supersedes_binding_id
        if predecessor_id == binding_id_value:
            raise IngestError("artifact binding cannot supersede itself")
        row = self._binding_row(predecessor_id or "")
        if row is None:
            raise IngestError("superseded artifact binding not found")
        predecessor = self._binding_record(predecessor_id or "", row)
        expected = (
            artifact,
            binding.scope_id,
            binding.subject_id,
            binding.run_id,
            binding.layer_id,
        )
        actual = (
            predecessor.artifact_name,
            predecessor.binding.scope_id,
            predecessor.binding.subject_id,
            predecessor.binding.run_id,
            predecessor.binding.layer_id,
        )
        if actual != expected:
            raise IngestError("superseded artifact binding context mismatch")

    def _project(
        self, artifact: str, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        if artifact == "layer":
            metadata = document["metadata"]
            self._execute(
                query(self.dialect, "layer_metadata.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "repo": metadata.get("repository"),
                    "created_at": metadata.get("created"),
                    "merkle_root": metadata.get("merkle_root"),
                    "merkle_epoch": _integer(metadata.get("merkle_epoch")),
                },
            )
            self._project_layer_events(document, digest, binding_id_value)
        elif artifact == "vuln-findings":
            for finding in document["findings"]:
                self._execute(
                    query(self.dialect, "finding.upsert.sql"),
                    {
                        "binding_id": binding_id_value,
                        "artifact_digest": digest,
                        "finding_id": finding["id"],
                        "target": document["target"],
                        "scanned_at": document["scanned_at"],
                        "title": finding["title"],
                        "severity": finding["severity"],
                        "description": finding["description"],
                        "category": finding.get("category"),
                        "file": finding["file"],
                        "line": _integer(finding.get("line")),
                        "cwe": finding.get("cwe"),
                        "recommendation": finding["recommendation"],
                        "confidence": finding["confidence"],
                    },
                )
        elif artifact == "triage":
            for finding in document["findings"]:
                votes = finding.get("vote_breakdown")
                self._execute(
                    query(self.dialect, "triage_verdict.upsert.sql"),
                    {
                        "binding_id": binding_id_value,
                        "artifact_digest": digest,
                        "finding_id": finding["id"],
                        "source_finding_id": finding.get("orig_id"),
                        "triage_completed": document["triage_completed"],
                        "verdict": finding["verdict"],
                        "severity": finding.get("severity"),
                        "vote_breakdown": (
                            json.dumps(
                                votes,
                                ensure_ascii=False,
                                separators=(",", ":"),
                                allow_nan=False,
                            )
                            if votes is not None
                            else None
                        ),
                        "rationale": finding.get("rationale"),
                    },
                )
        elif artifact == "cloud-config-findings-current":
            self._project_one_row(artifact, document, digest, binding_id_value)
            self._project_cloud_config_findings(document, digest, binding_id_value)
        elif artifact == "threat-model":
            self._project_threats(document, digest, binding_id_value)
        elif artifact == "operator-priv-profile":
            self._project_priv_profile(document, digest, binding_id_value)
        elif artifact == "corpus-registry":
            for subject in document.get("subjects") or []:
                self._execute(
                    query(self.dialect, "subject_ownership.upsert.sql"),
                    {
                        "binding_id": binding_id_value,
                        "artifact_digest": digest,
                        "subject_id": subject["subject_id"],
                        "tree": subject["tree"],
                        "ownership": subject["ownership"],
                        "business_unit": subject["business_unit"],
                        "label": subject.get("label"),
                        "product": subject.get("product"),
                        "repo_url": subject.get("repo_url"),
                        "ref": subject.get("ref"),
                        "ref_kind": subject.get("ref_kind"),
                        "is_branch_audit": _boolean(subject.get("is_branch_audit")),
                    },
                )
        else:
            self._project_one_row(artifact, document, digest, binding_id_value)
            if artifact == "report":
                self._project_report_findings(document, digest, binding_id_value)
            elif artifact == "validation":
                self._project_validation_findings(document, digest, binding_id_value)
            elif artifact == "compliance-assessment":
                self._project_compliance_results(document, digest, binding_id_value)
            elif artifact == "verification":
                self._project_verification(document, digest, binding_id_value)
            elif artifact == "remediation":
                self._project_remediation_sources(document, digest, binding_id_value)

    def _project_one_row(
        self, artifact: str, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        table, fields = ONE_ROW_PROJECTIONS[artifact]
        values: dict[str, SQLValue] = {
            "binding_id": binding_id_value,
            "artifact_digest": digest,
        }
        for name, kind in fields:
            value = document.get(name)
            if kind == "json" and value is not None:
                value = json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            elif kind == "integer":
                value = _integer(value)
            values[name] = value
        self._execute(query(self.dialect, f"{table}.upsert.sql"), values)

    def _project_threats(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a threat model's threats out of the JSON blob.

        threat_key is derived as `<subject>:<id>`, NOT taken from the
        document: an in-model id is unique only within its own model --
        every model numbers from T1 -- so a projection keyed on it alone
        would keep one threat per number across the whole estate.
        """
        subject = self._binding_row(binding_id_value)
        subject_id = subject[3] if subject else None
        provenance = document.get("provenance") or {}
        for threat in document.get("threats") or []:
            threat_id = threat.get("id")
            if not threat_id:
                continue
            self._execute(
                query(self.dialect, "threat.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "threat_key": f"{subject_id or document.get('system')}:{threat_id}",
                    "threat_id": threat_id,
                    "model": provenance.get("target") or document.get("system") or "",
                    "subject_id": subject_id or document.get("subject_id"),
                    "product": document.get("system"),
                    "statement": threat.get("threat"),
                    "surface": threat.get("surface"),
                    "asset": threat.get("asset"),
                    "impact": threat.get("impact"),
                    "likelihood": threat.get("likelihood"),
                    "status": threat.get("status"),
                    "controls": threat.get("controls"),
                    "actors": _json_or_none(threat.get("actor")),
                    "evidence": _json_or_none(threat.get("evidence")),
                    "linddun": _boolean(
                        str(threat.get("threat", "")).lower().startswith("linddun:")
                    ),
                    "score": _threat_score(threat.get("impact"), threat.get("likelihood")),
                    "attack_refs": _json_or_none(threat.get("attack_refs")),
                    "isolation_dimensions": _json_or_none(threat.get("isolation_dimensions")),
                    "isolation_boundaries": _json_or_none(threat.get("isolation_boundaries")),
                },
            )

    def _project_priv_profile(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """One column per ROOT property, which is the one-row invariant here.

        The summary counts a dashboard cuts by are DERIVED, and the
        operator_privilege view extracts them rather than storing a second
        copy. Not a plain _project_one_row only because `repo` is required
        and the rest are nested blocks that all encode identically.
        """
        self._execute(
            query(self.dialect, "priv_profile.upsert.sql"),
            {
                "binding_id": binding_id_value,
                "artifact_digest": digest,
                "repo": document["repo"],
                "tier": document.get("tier"),
                **{
                    field: _json_or_none(document.get(field))
                    for field in (
                        "workloads",
                        "rbac_rules",
                        "rbac_flags",
                        "scc_requests",
                        "sccs_shipped",
                        "namespaces",
                        "install_modes",
                        "operatorgroups",
                        "tier2_required_vs_granted",
                        "example_or_test_manifests_excluded",
                        "summary",
                    )
                },
            },
        )

    def _project_layer_events(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan the ledger's dated transitions out of the layer blob.

        This is the whole time dimension. Without it storage/v1 can answer
        what is open NOW and nothing about when it opened, how long it took
        to close, or what the estate looked like on any past date.
        """
        for event in document.get("events") or []:
            source = event.get("source") or {}
            actor = source.get("actor") or {}
            disposition = event.get("disposition") or {}
            risk = event.get("risk_weight") or {}
            self._execute(
                query(self.dialect, "layer_event.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "event_id": event["event_id"],
                    "finding_ref": event["finding_ref"],
                    "fingerprint": event.get("fingerprint"),
                    "fingerprint_algo": event.get("fingerprint_algo"),
                    "recorded_at": event["recorded_at"],
                    "occurred_at": event.get("occurred_at"),
                    "source_type": source.get("type"),
                    "source_ref": source.get("ref"),
                    "actor_kind": actor.get("kind"),
                    "validity": disposition.get("validity"),
                    "resolution": disposition.get("resolution"),
                    "evidence_grade": event.get("evidence_grade"),
                    "auto_accept_tier": _boolean(event.get("auto_accept_tier")),
                    # rationale is REQUIRED by layer.schema.json: without it
                    # the stream records that something changed and never why.
                    "rationale": event.get("rationale"),
                    "harness_version": event.get("harness_version"),
                    "evidence_refs": _json_or_none(event.get("evidence_refs")),
                    "source_reported_by": source.get("reported_by"),
                    # disposition asserts a severity and an embargo state too;
                    # keeping only validity/resolution loses every severity
                    # change the history recorded.
                    "severity": disposition.get("severity"),
                    "embargo": disposition.get("embargo"),
                    # risk_weight flattened the way source and disposition
                    # already are -- `lambda` is what a risk index multiplies.
                    "risk_lambda": risk.get("lambda"),
                    "risk_weights_version": risk.get("weights_version"),
                    "risk_tenancy_profile": risk.get("tenancy_profile"),
                    "risk_profile_source": risk.get("profile_source"),
                    "alias": _json_or_none(event.get("alias")),
                    "finding": _json_or_none(event.get("finding")),
                },
            )

    def _project_validation_findings(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a live-validation run's outcomes out of the JSON blob.

        `source_id` is `<product>:<repo>/<finding_id>`; the tail is the
        scan-scoped finding id report_finding is keyed on, so splitting it
        here turns "was this ever proven against a running system" into a
        join instead of a separate spreadsheet.
        """
        for chain in document.get("attack_chains") or []:
            chain_id = chain.get("chain_id")
            if not chain_id:
                continue
            self._execute(
                query(self.dialect, "attack_chain.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "chain_id": chain_id,
                    "name": chain.get("name"),
                    "entry_point": chain.get("entry_point"),
                    "terminal_asset": chain.get("terminal_asset"),
                    "mitre_attack_refs": _json_or_none(chain.get("mitre_attack_refs")),
                    "steps": _json_or_none(chain.get("steps")),
                    "verdict": chain.get("verdict"),
                    "narrative": chain.get("narrative"),
                },
            )
        for finding in document.get("validated_findings") or []:
            source_id = finding.get("source_id")
            if not source_id:
                continue
            self._execute(
                query(self.dialect, "validation_finding.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "source_id": source_id,
                    "source_finding_id": source_id.rsplit("/", 1)[-1] or None,
                    "title": finding.get("title"),
                    "claimed_severity": finding.get("claimed_severity"),
                    "surface": finding.get("surface"),
                    "verdict": finding.get("verdict"),
                    "skip_reason": _skip_reason(finding),
                    "technique": finding.get("technique"),
                    "observed_impact": finding.get("observed_impact"),
                    # The rest of what validated_findings[] declares.
                    # evidence_grade (E0-E3) and soundness_flag are the
                    # two that say how far a verdict can be trusted.
                    "evidence_grade": finding.get("evidence_grade"),
                    "grade_rationale": finding.get("grade_rationale"),
                    "soundness_flag": finding.get("soundness_flag"),
                    "severity_validation": _json_or_none(finding.get("severity_validation")),
                    "deviation_from_claim": finding.get("deviation_from_claim"),
                    "rollback_performed": _boolean(finding.get("rollback_performed")),
                    "chain_context": _json_or_none(finding.get("chain_context")),
                    "not_attempted_reason": finding.get("not_attempted_reason"),
                },
            )

    def _project_verification(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a verification out: did each fix hold, and what did it break.

        Two tables, not one. A regression is a NEW finding the fix
        introduced, not a restatement of the one it closed, and folding
        them would make "how many findings did this verification touch"
        ambiguous. The regressions are the half a remediation review must
        not miss.
        """
        for finding in document.get("verified_findings") or []:
            original_id = finding.get("original_id")
            if not original_id:
                continue
            evidence = finding.get("evidence") or {}
            self._execute(
                query(self.dialect, "verification_finding.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "original_id": original_id,
                    "original_title": finding.get("original_title"),
                    "original_severity": finding.get("original_severity"),
                    "verdict": finding.get("verdict"),
                    "remediation_commits": _json_or_none(finding.get("remediation_commits")),
                    # Evidence ABOUT the evidence: a fix nobody could tie to
                    # a commit. Dropping it lets an unexplained pass read
                    # exactly like a demonstrated one.
                    "unattributed": _boolean(finding.get("unattributed")),
                    # Flattened, not stored whole: a nested evidence block is
                    # exactly where declared fields go missing unnoticed.
                    "evidence_explanation": evidence.get("explanation"),
                    "evidence_framework_reference": evidence.get("framework_reference"),
                    "evidence_original_code": evidence.get("original_code"),
                    "evidence_patched_code": evidence.get("patched_code"),
                    "disposition_rationale": finding.get("disposition_rationale"),
                    "residual_risk": finding.get("residual_risk"),
                    "residual_severity": finding.get("residual_severity"),
                    "cross_repo": _json_or_none(finding.get("cross_repo")),
                },
            )
        for regression in document.get("regressions") or []:
            regression_id = regression.get("id")
            if not regression_id:
                continue
            self._execute(
                query(self.dialect, "verification_regression.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "regression_id": regression_id,
                    "title": regression.get("title"),
                    "severity": regression.get("severity"),
                    "cwes": _json_or_none(regression.get("cwes")),
                    "cvss": _json_or_none(regression.get("cvss")),
                    "locations": _json_or_none(regression.get("locations")),
                    "description": regression.get("description"),
                    "remediation": regression.get("remediation"),
                    "evidence": _json_or_none(regression.get("evidence")),
                    "attack_pattern": regression.get("attack_pattern"),
                    "category": regression.get("category"),
                    "introduced_by": regression.get("introduced_by"),
                    "routed_id": regression.get("routed_id"),
                    "fingerprint": regression.get("fingerprint"),
                    "fingerprint_algo": regression.get("fingerprint_algo"),
                },
            )

    def _project_remediation_sources(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a remediation out to the findings that justified it.

        `validation_verdict` is the state AT REMEDIATION TIME. It says why
        the work was started and must not be read as the finding's current
        disposition, which lives on current_finding.
        """
        for source in document.get("source_findings") or []:
            finding_ref = source.get("finding_ref")
            if not finding_ref:
                continue
            self._execute(
                query(self.dialect, "remediation_source.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "finding_ref": finding_ref,
                    "title": source.get("title"),
                    "severity": source.get("severity"),
                    "cwes": _json_or_none(source.get("cwes")),
                    "locations": _json_or_none(source.get("locations")),
                    "triage_confidence": source.get("triage_confidence"),
                    "validation_verdict": source.get("validation_verdict"),
                    "audit_report_path": source.get("audit_report_path"),
                    "triage_report_path": source.get("triage_report_path"),
                    "validation_report_path": source.get("validation_report_path"),
                },
            )

    def _project_compliance_results(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan an assessment out to one row per control per framework.

        `verdict_source` travels with the verdict. A control satisfied by a
        deterministic check, by an agent reading evidence, and by a human
        override are three different claims about assurance, and a posture
        reporting only the verdict erases the distinction an auditor is
        there to examine.
        """
        for result in document.get("results") or []:
            framework = result.get("framework")
            control_id = result.get("control_id")
            if not framework or not control_id:
                continue
            self._execute(
                query(self.dialect, "compliance_result.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "framework": framework,
                    "control_id": control_id,
                    "title": result.get("title"),
                    "classification": result.get("classification"),
                    "verdict": result.get("verdict"),
                    "verdict_source": result.get("verdict_source"),
                    "check_id": result.get("check_id"),
                    "reason": result.get("reason"),
                    "narrative": result.get("narrative"),
                    "evidence": _json_or_none(result.get("evidence")),
                    "override": _json_or_none(result.get("override")),
                    "n_pass_agreement": _json_or_none(result.get("n_pass_agreement")),
                },
            )

    def _project_cloud_config_findings(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a policy report's findings out of the JSON blob.

        Same shape and same reason as _project_report_findings: the blob
        stays authoritative and this is an index over it. Carries the IaC
        columns a policy finding is cut by -- check_id separates two
        findings on one resource, framework and provider slice a compliance
        view.
        """
        for finding in document.get("findings") or []:
            disposition = finding.get("disposition") or {}
            override = disposition.get("severity_override")
            self._execute(
                query(self.dialect, "cloud_config_finding.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "finding_id": finding["id"],
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "fingerprint": finding.get("fingerprint"),
                    "validation_status": finding.get("validation_status"),
                    "check_id": finding.get("check_id"),
                    "framework": finding.get("framework"),
                    "provider": finding.get("provider"),
                    "status": finding.get("status"),
                    "scanner_severity": finding.get("scanner_severity"),
                    "validity": disposition.get("validity"),
                    "resolution": disposition.get("resolution"),
                    "assurance": disposition.get("assurance"),
                    "last_updated": disposition.get("last_updated"),
                    "conflict": _boolean(disposition.get("conflict")),
                    "fp_overridden": _boolean(disposition.get("fp_overridden")),
                    "fp_reassertion_blocked": _boolean(disposition.get("fp_reassertion_blocked")),
                    "refuted_awaiting_signoff": _boolean(
                        disposition.get("refuted_awaiting_signoff")
                    ),
                    "severity_override": (
                        json.dumps(
                            override, ensure_ascii=False, separators=(",", ":"), allow_nan=False
                        )
                        if override is not None
                        else None
                    ),
                    # The rest of what cloud-config-findings-current declares.
                    # cwe and control_refs are how a compliance view cuts a
                    # policy finding; fact_ids is its link back to the scan.
                    "rationale": finding.get("rationale"),
                    "remediation": finding.get("remediation"),
                    "cwe": finding.get("cwe"),
                    "control_refs": _json_or_none(finding.get("control_refs")),
                    "locations": _json_or_none(finding.get("locations")),
                    "fact_ids": _json_or_none(finding.get("fact_ids")),
                    "external_correlation": _json_or_none(finding.get("external_correlation")),
                    "effective_severity": finding.get("effective_severity"),
                    "fingerprint_algo": finding.get("fingerprint_algo"),
                    "isolation_boundary": finding.get("isolation_boundary"),
                    "isolation_dimensions": _json_or_none(finding.get("isolation_dimensions")),
                },
            )

    def _project_report_findings(
        self, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        """Fan a report's findings out of the JSON blob into queryable rows.

        The blob stays: `report.findings` remains the faithful projection of
        the artifact. This is an index over it, so `validity`/`resolution`
        can be filtered and `fingerprint` grouped without parsing every row.

        Disposition is optional on the artifact -- only cumulative reports
        carry it -- so a finding without one still projects, with its
        identity and NULL disposition.
        """
        for finding in document.get("findings") or []:
            disposition = finding.get("disposition") or {}
            override = disposition.get("severity_override")
            self._execute(
                query(self.dialect, "report_finding.upsert.sql"),
                {
                    "binding_id": binding_id_value,
                    "artifact_digest": digest,
                    "finding_id": finding["id"],
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "fingerprint": finding.get("fingerprint"),
                    "validation_status": finding.get("validation_status"),
                    "validity": disposition.get("validity"),
                    "resolution": disposition.get("resolution"),
                    "assurance": disposition.get("assurance"),
                    "last_updated": disposition.get("last_updated"),
                    "conflict": _boolean(disposition.get("conflict")),
                    "fp_overridden": _boolean(disposition.get("fp_overridden")),
                    "fp_reassertion_blocked": _boolean(disposition.get("fp_reassertion_blocked")),
                    "refuted_awaiting_signoff": _boolean(
                        disposition.get("refuted_awaiting_signoff")
                    ),
                    "severity_override": (
                        json.dumps(
                            override,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        if override is not None
                        else None
                    ),
                    # The rest of what report.schema.json declares on a
                    # finding. description and remediation are REQUIRED by
                    # the contract; category and cwes are the axes the
                    # pattern rollup groups by and could not reach.
                    "description": finding.get("description"),
                    "remediation": finding.get("remediation"),
                    "category": finding.get("category"),
                    "cwes": _json_or_none(finding.get("cwes")),
                    "locations": _json_or_none(finding.get("locations")),
                    "asvs_references": _json_or_none(finding.get("asvs_references")),
                    "peach_references": _json_or_none(finding.get("peach_references")),
                    "capec": _json_or_none(finding.get("capec")),
                    "attack_pattern": finding.get("attack_pattern"),
                    "cvss": _json_or_none(finding.get("cvss")),
                    "evidence": _json_or_none(finding.get("evidence")),
                    "effective_severity": finding.get("effective_severity"),
                    "origin": finding.get("origin"),
                    "source_findings": _json_or_none(finding.get("source_findings")),
                    "passes": _json_or_none(finding.get("passes")),
                    "remediation_effort": finding.get("remediation_effort"),
                    "pqc_classification": finding.get("pqc_classification"),
                    "fingerprint_algo": finding.get("fingerprint_algo"),
                    "isolation_boundary": finding.get("isolation_boundary"),
                    "isolation_dimensions": _json_or_none(finding.get("isolation_dimensions")),
                    "dependency": _json_or_none(finding.get("dependency")),
                },
            )
