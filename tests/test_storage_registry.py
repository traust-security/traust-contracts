"""Product -> repo registry: identity, registration, and what it constrains."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from dataclasses import replace

import pytest
from storage_samples import REGISTRY_TABLES, encode, sample

from traust_contracts.paths import storage_dir
from traust_contracts.v1.storage import Binding, IngestError, Store, binding_id
from traust_contracts.v1.storage.sql import REVISION

ACM_CLI = "https://github.com/stolostron/acm-cli"
UNREGISTERED = "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def store() -> Iterator[Store]:
    conn = sqlite3.connect(":memory:")
    storage = Store(conn)
    storage.init()
    yield storage
    conn.close()


def register(store: Store, product: str = "rhacm", ref: str = "") -> str:
    return store.register_product_repo(
        store.register_product(product), store.register_repo(ACM_CLI), ref
    )


def report_binding(product_repo_id: str, role: str = "cumulative", **kwargs: str) -> Binding:
    return Binding(
        subject_id="findings/rhacm/acm-cli",
        run_id="corpus:run:findings/rhacm/acm-cli",
        role=role,
        product_repo_id=product_repo_id,
        **kwargs,
    )


@pytest.mark.parametrize(
    "call",
    [
        lambda store: store.register_product(""),
        lambda store: store.register_repo(""),
        lambda store: store.register_product("bad\x00slug"),
        lambda store: store.register_repo("https://example.test/\x00"),
        lambda store: store.register_product_repo("", "r"),
        lambda store: store.register_product_repo("p", "r", None),
    ],
)
def test_registration_rejects_empty_and_nul(store: Store, call: Callable[[Store], str]) -> None:
    with pytest.raises(IngestError):
        call(store)


def test_product_repo_is_not_part_of_binding_identity() -> None:
    """binding_id keeps its 0.48.0 bytes; product_repo_id is a constrained attribute."""
    digest = hashlib.sha256(b"").hexdigest()
    roled = Binding(subject_id="sci:inventory-item:42", role="baseline")
    assert binding_id(digest, "report", roled) == (
        "d0da85a98aa803d79ba2fed07a8f991c706f2fbb44f3692cbd3ad8662961cb0b"
    )
    owned = replace(roled, product_repo_id=str(uuid.uuid4()), commit_sha="a" * 40)
    assert binding_id(digest, "report", owned) == binding_id(digest, "report", roled)


def test_registration_is_idempotent_and_returns_stored_ids(store: Store) -> None:
    first = register(store)
    assert register(store) == first
    assert str(uuid.UUID(first)) == first
    product = store.register_product("rhacm")
    repo = store.register_repo(ACM_CLI)
    assert store.conn.execute(
        "SELECT product_id, repo_id FROM product_repo WHERE product_repo_id = ?", (first,)
    ).fetchone() == (product, repo)
    for table in REGISTRY_TABLES:
        assert store.conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (1,)


def test_one_repo_many_products(store: Store) -> None:
    ids = {register(store, product) for product in ("rhacm", "advanced-cluster-management")}
    ids.add(register(store, "rhacm", "release-5.0"))
    assert len(ids) == 3
    assert store.conn.execute("SELECT count(*) FROM repo").fetchone() == (1,)
    assert store.conn.execute(
        "SELECT count(*) FROM product_repo WHERE repo_id = ?", (store.register_repo(ACM_CLI),)
    ).fetchone() == (3,)


def test_product_repo_requires_registered_parents(store: Store) -> None:
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.register_product_repo(UNREGISTERED, UNREGISTERED)
    assert store.conn.execute("SELECT count(*) FROM product_repo").fetchone() == (0,)


def test_product_repo_key_is_product_repo_and_ref(store: Store) -> None:
    default, release = register(store), register(store, ref="release-5.0")
    assert default != release
    product, repo = store.register_product("rhacm"), store.register_repo(ACM_CLI)
    assert store.conn.execute(
        "SELECT product_id, repo_id, ref, product_repo_id FROM product_repo ORDER BY ref"
    ).fetchall() == [(product, repo, "", default), (product, repo, "release-5.0", release)]
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        store.conn.execute(
            "INSERT INTO product_repo (product_repo_id, product_id, repo_id, ref, registered_at) "
            "VALUES ('other-id', ?, ?, '', 'now')",
            (product, repo),
        )
    store.conn.rollback()


def test_find_product_repo_reads_without_creating(store: Store) -> None:
    owner = register(store, ref="release-5.0")
    assert store.find_product_repo("rhacm", ACM_CLI, "release-5.0") == owner
    assert store.find_product_repo("rhacm", ACM_CLI) is None
    assert store.find_product_repo("unknown", ACM_CLI, "release-5.0") is None
    assert store.conn.execute("SELECT count(*) FROM product_repo").fetchone() == (1,)


def test_commit_is_recorded_but_not_identity(store: Store) -> None:
    owner = register(store)
    payload, _ = sample("report")
    first = store.ingest("report", payload, report_binding(owner, commit_sha="a" * 40))
    assert store.get_binding(first.binding_id).binding.commit_sha == "a" * 40
    with pytest.raises(IngestError, match="identity collision"):
        store.ingest("report", payload, report_binding(owner, commit_sha="b" * 40))
    changed = json.loads(payload)
    changed["remediation_roadmap"].append(dict(changed["remediation_roadmap"][0]))
    newer = store.ingest(
        "report",
        encode(changed),
        report_binding(owner, commit_sha="b" * 40, supersedes_binding_id=first.binding_id),
    )
    assert store.get_binding(newer.binding_id).binding.commit_sha == "b" * 40


def test_inventory_attributes_refresh_identity_does_not(store: Store) -> None:
    product = store.register_product("rhacm", segment="operator-catalog")
    assert store.register_product("rhacm", segment="adhoc") == product
    assert store.conn.execute("SELECT slug, segment FROM product").fetchall() == [
        ("rhacm", "adhoc")
    ]
    repo = store.register_repo(ACM_CLI)
    owner = store.register_product_repo(product, repo, sub_service="acm", resource_type="upstream")
    store.register_product_repo(product, repo, sub_service="acm-cli", resource_type="adhoc")
    assert store.conn.execute(
        "SELECT product_repo_id, sub_service, resource_type FROM product_repo"
    ).fetchall() == [(owner, "acm-cli", "adhoc")]


def test_product_repo_versions_record_what_each_version_ships(store: Store) -> None:
    owner = register(store, ref="release-5.0")
    store.register_product_repo_version(owner, "2.15", "Operator", ["storage"], ["acm-cli"])
    store.register_product_repo_version(owner, "2.15", "ClusterOperator", None, ["a", "b"])
    store.register_product_repo_version(owner, "2.16")
    assert store.conn.execute(
        "SELECT version, category, cluster_operators, images FROM product_repo_version "
        "ORDER BY version"
    ).fetchall() == [
        ("2.15", "ClusterOperator", None, '["a","b"]'),
        ("2.16", None, None, None),
    ]
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.register_product_repo_version(UNREGISTERED, "2.15")
    with pytest.raises(IngestError, match="version"):
        store.register_product_repo_version(owner, "")
    with pytest.raises(IngestError, match="list of strings"):
        store.register_product_repo_version(owner, "2.15", images="acm-cli")  # type: ignore[arg-type]


def test_repo_owners_allow_several_teams_and_refresh(store: Store) -> None:
    owner = register(store)
    store.register_repo_owner(owner, "Stolostron / ACM", "jdoe", ["a", "b"], "owners.csv")
    store.register_repo_owner(owner, "Stolostron / ACM", "msmith", ["c"], "owners.csv", "ACM")
    store.register_repo_owner(owner, "Server Foundation")
    assert store.conn.execute(
        "SELECT team, manager, individuals, jira_project FROM repo_owner ORDER BY team"
    ).fetchall() == [
        ("Server Foundation", None, None, None),
        ("Stolostron / ACM", "msmith", '["c"]', "ACM"),
    ]
    with pytest.raises(IngestError, match="team"):
        store.register_repo_owner(owner, "")
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.register_repo_owner(UNREGISTERED, "team")


def test_inventory_answers_release_contents_and_coverage(store: Store) -> None:
    scanned = register(store, "openshift", ref="release-4.21")
    unscanned = store.register_product_repo(
        store.register_product("openshift"),
        store.register_repo("https://github.com/o/r"),
        "release-4.21",
    )
    for owner in (scanned, unscanned):
        store.register_product_repo_version(owner, "4.21", "ClusterOperator")
    payload, _ = sample("report")
    store.ingest("report", payload, report_binding(scanned, role="baseline"))
    shipped = store.conn.execute(
        "SELECT r.repo_url FROM product_repo_version v "
        "JOIN product_repo pr ON pr.product_repo_id = v.product_repo_id "
        "JOIN repo r ON r.repo_id = pr.repo_id WHERE v.version = '4.21' ORDER BY 1"
    ).fetchall()
    assert shipped == [("https://github.com/o/r",), (ACM_CLI,)]
    never_scanned = store.conn.execute(
        "SELECT pr.product_repo_id FROM product_repo pr WHERE NOT EXISTS "
        "(SELECT 1 FROM artifact_binding b WHERE b.product_repo_id = pr.product_repo_id)"
    ).fetchall()
    assert never_scanned == [(unscanned,)]


def test_binding_to_unregistered_product_repo_writes_nothing(store: Store) -> None:
    payload, _ = sample("report")
    with pytest.raises(IngestError, match=r"(?i)foreign_?key"):
        store.ingest("report", payload, report_binding(UNREGISTERED))
    assert store.conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (0,)
    assert store.conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (0,)


def test_binding_round_trips_product_repo(store: Store) -> None:
    owner = register(store)
    payload, _ = sample("report")
    result = store.ingest("report", payload, report_binding(owner, role="baseline"))
    assert store.get_binding(result.binding_id).binding.product_repo_id == owner
    assert store.conn.execute(
        "SELECT product_repo_id FROM current_binding WHERE binding_id = ?", (result.binding_id,)
    ).fetchone() == (owner,)


def test_same_bytes_in_two_products_store_once_bind_twice(store: Store) -> None:
    payload, _ = sample("report")
    for product in ("rhacm", "advanced-cluster-management"):
        owner = register(store, product)
        context = Binding(
            subject_id=f"findings/{product}/acm-cli",
            run_id=f"corpus:run:findings/{product}/acm-cli",
            role="baseline",
            product_repo_id=owner,
        )
        store.ingest("report", payload, context)
    assert store.conn.execute("SELECT count(*) FROM artifact_evidence").fetchone() == (1,)
    assert store.conn.execute("SELECT count(*) FROM artifact_binding").fetchone() == (2,)


def test_same_context_under_another_product_repo_is_a_collision(store: Store) -> None:
    payload, _ = sample("report")
    store.ingest("report", payload, report_binding(register(store), role="baseline"))
    other = register(store, "advanced-cluster-management")
    with pytest.raises(IngestError, match="identity collision"):
        store.ingest("report", payload, report_binding(other, role="baseline"))


def test_one_current_findings_current_per_product_repo(store: Store) -> None:
    owner = register(store)
    payload, _ = sample("report")
    first = store.ingest("report", payload, report_binding(owner))
    changed = json.loads(payload)
    changed["remediation_roadmap"].append(dict(changed["remediation_roadmap"][0]))
    with pytest.raises(IngestError, match=r"(?i)unique"):
        store.ingest("report", encode(changed), report_binding(owner))
    second = store.ingest(
        "report", encode(changed), report_binding(owner, supersedes_binding_id=first.binding_id)
    )
    assert store.conn.execute(
        "SELECT binding_id FROM current_binding WHERE artifact_role = 'cumulative'"
    ).fetchall() == [(second.binding_id,)]
    # Baseline audits are not constrained; the rule is findings-current only.
    store.ingest("report", payload, report_binding(owner, role="baseline"))
    store.ingest("report", encode(changed), report_binding(owner, role="baseline"))


def test_supersession_must_keep_product_repo(store: Store) -> None:
    owner, other = register(store), register(store, "advanced-cluster-management")
    payload, _ = sample("report")
    first = store.ingest("report", payload, report_binding(owner))
    changed = json.loads(payload)
    changed["remediation_roadmap"].append(dict(changed["remediation_roadmap"][0]))
    with pytest.raises(IngestError, match="context mismatch"):
        store.ingest(
            "report", encode(changed), report_binding(other, supersedes_binding_id=first.binding_id)
        )


def _schema(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    """Columns (by name, not position), foreign keys, indexes and views."""
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    shape: dict[str, list[tuple[object, ...]]] = {}
    for table in sorted(tables):
        shape[f"{table}.columns"] = sorted(
            row[1:] for row in conn.execute(f"PRAGMA table_info({table})")
        )
        shape[f"{table}.foreign_keys"] = sorted(
            row[2:] for row in conn.execute(f"PRAGMA foreign_key_list({table})")
        )
    shape["indexes"] = sorted(
        conn.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql NOT NULL"
        )
    )
    shape["views"] = sorted(conn.execute("SELECT name, sql FROM sqlite_master WHERE type='view'"))
    return shape


def _fresh() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    Store(conn).init()
    return conn


def test_migrate_bootstraps_an_empty_database() -> None:
    conn = sqlite3.connect(":memory:")
    assert Store(conn).migrate() == 0
    Store(conn).init()
    assert _schema(conn) == _schema(_fresh())


def test_migrate_runs_a_step_through_its_delta_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """With REVISION one ahead, migrate applies the 001_to_002 delta and re-runs the files."""
    conn = _fresh()
    store = Store(conn)
    owner = register(store)
    conn.execute("DROP VIEW current_binding")
    conn.execute("CREATE VIEW current_binding AS SELECT binding_id FROM artifact_binding")
    conn.commit()
    for module in ("traust_contracts.v1.storage.store", "traust_contracts.v1.storage.sql"):
        monkeypatch.setattr(f"{module}.REVISION", REVISION + 1)
    with pytest.raises(IngestError, match="explicit migration"):
        store.init()
    assert store.migrate() == REVISION
    store.init()
    assert conn.execute("SELECT revision FROM traust_storage_meta").fetchone() == (REVISION + 1,)
    assert _schema(conn) == _schema(_fresh())
    assert store.find_product_repo("rhacm", ACM_CLI) == owner


def test_migrate_is_a_noop_at_the_current_revision(store: Store) -> None:
    before = _schema(store.conn)
    assert store.migrate() == REVISION
    assert _schema(store.conn) == before


def test_migrate_refuses_a_newer_revision_and_writes_nothing() -> None:
    conn = _fresh()
    conn.execute("UPDATE traust_storage_meta SET revision = ?", (REVISION + 1,))
    conn.commit()
    before = _schema(conn)
    with pytest.raises(IngestError, match="newer"):
        Store(conn).migrate()
    assert _schema(conn) == before


def test_migration_files_hold_deltas_only() -> None:
    """New tables, indexes and views belong in schema/ and views/, which re-run."""
    for dialect in ("sqlite", "postgres"):
        for path in (storage_dir() / dialect / "migrations").glob("*.sql"):
            code = "\n".join(
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("--")
            )
            assert "CREATE " not in code.upper(), f"{dialect}/{path.name} creates; edit schema/"


def test_migrate_syncs_the_revision_five_views() -> None:
    """A revision-4 database must pick the new views up by migrating.

    Revision 5 changes only views (the current_finding_detail view and the
    spine's cvss_score column), and Store.init() verifies a revision
    without syncing files: the revision bump is what makes an existing
    database re-run the bootstrap files at all. Build a revision-4 shape
    (old spine without cvss_score, no detail view), then migrate and
    compare against a fresh init.
    """
    conn = _fresh()
    conn.execute("DROP VIEW current_finding_detail")
    conn.execute("DROP VIEW current_finding")
    conn.execute(
        "CREATE VIEW current_finding AS "
        "SELECT scope_id, subject_id, run_id, finding_id FROM report_finding"
    )
    conn.execute("UPDATE traust_storage_meta SET revision = 4")
    conn.commit()

    # init() refuses the older revision rather than silently syncing.
    with pytest.raises(IngestError, match="explicit migration"):
        Store(conn).init()

    assert Store(conn).migrate() == 4
    Store(conn).init()
    assert conn.execute("SELECT revision FROM traust_storage_meta").fetchone() == (REVISION,)
    assert _schema(conn) == _schema(_fresh())
    # The migrated database carries the revision-5 shape: the spine's new
    # column is queryable and the detail view exists.
    conn.execute("SELECT cvss_score FROM current_finding LIMIT 0")
    conn.execute("SELECT count(*) FROM current_finding_detail")
