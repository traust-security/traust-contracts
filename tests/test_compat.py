"""Compatibility gates for schema versioning.

Breaking-change gate: property/required guards, finite-domain narrowing,
and restrictions on previously open values versus the change's base on main:
the merge-base with origin/main on a branch, the previous commit on main
itself, or any ref named by CONTRACTS_COMPAT_BASE. It used to compare against
the latest git tag; tags stopped at v0.48.1 when CI moved off GitLab, so every
approved change since then read as "breaking" and the gate was bypassed on
every push (2026-10-22).

The vector-hash gate that pinned the golden-vector suite to a deterministic
digest was removed with the suite itself on 2026-08-18 (only the harness computes
identity, so there is no second-language port for a shared oracle to hold). The
recipe's regression fixtures now live in the ledger package, beside the
implementation they guard.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"


class TestBreakingChangeDetection:
    """Detect schema evolution breaking backward compatibility."""

    @staticmethod
    def _git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
        return result.stdout.strip() or None

    @classmethod
    def _compat_base(cls) -> tuple[str | None, str]:
        """(git ref, how it was chosen) that the gate compares against.

        - CONTRACTS_COMPAT_BASE, when set: any ref (a tag, a SHA, a branch).
        - On a branch: the merge-base with origin/main (or main), so the gate
          reports only what this change introduces.
        - On main itself: the previous commit (first parent), so a post-merge
          run checks the change that just landed.
        """
        override = os.getenv("CONTRACTS_COMPAT_BASE")
        if override:
            return override, f"CONTRACTS_COMPAT_BASE={override}"
        head = cls._git("rev-parse", "HEAD")
        for upstream in ("origin/main", "main"):
            base = cls._git("merge-base", "HEAD", upstream)
            if not base:
                continue
            if base != head:
                return base, f"merge-base with {upstream}"
            parent = cls._git("rev-parse", "--verify", "--quiet", "HEAD^1")
            return parent, "the previous commit on main"
        return None, "no main branch to compare against"

    @staticmethod
    def _extract_json_pointer_path(path_list: list) -> str:
        """Convert a path list to JSON pointer notation."""
        return "/" + "/".join(str(p) for p in path_list)

    @staticmethod
    def _walk_schema(schema: dict, path: list) -> list:
        """Yield (json_pointer, schema_node) for all nodes in schema."""
        results = []

        def walk(node: Any, current_path: list):
            if isinstance(node, dict):
                pointer = "/" + "/".join(str(p) for p in current_path) if current_path else ""
                results.append((pointer, node))
                for key, value in node.items():
                    if key not in (
                        "$schema",
                        "$id",
                        "title",
                        "description",
                        "examples",
                        "const",
                        "enum",
                        "default",
                    ):
                        walk(value, [*current_path, key])
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*current_path, i])

        walk(schema, path)
        return results

    @staticmethod
    def _collect_properties(node: dict) -> set:
        """Collect all property names from a schema node."""
        if "properties" in node and isinstance(node["properties"], dict):
            return set(node["properties"].keys())
        return set()

    @staticmethod
    def _finite_values(node: dict) -> list | None:
        """Keep JSON values intact: arrays/objects are valid const/enum members."""
        if "const" in node:
            return [node["const"]]
        if isinstance(node.get("enum"), list):
            return node["enum"]
        return None

    @staticmethod
    def _value_restrictions(old, current, old_schema: dict, current_schema: dict) -> list[str]:
        """Compare local value constraints, not arbitrary JSON Schema containment.

        Finite old domains can be checked exactly, including const lists and
        const -> enum/anyOf widening. Other changed constraints on formerly
        open values require review; combinators/refs need their enclosing context.
        """
        old_validator = Draft202012Validator(old_schema).evolve(schema=old)
        new_validator = Draft202012Validator(current_schema).evolve(schema=current)
        finite = TestBreakingChangeDetection._finite_values(old) if isinstance(old, dict) else None
        if finite is not None:
            rejected = [
                value
                for value in finite
                if old_validator.is_valid(value) and not new_validator.is_valid(value)
            ]
            return [f"previously allowed finite values rejected: {rejected!r}"] if rejected else []
        if old is False or current is True or current == {}:
            return []
        if current is False:
            return ["previously open values prohibited (review required for enclosing constraints)"]
        annotations = {
            "$schema",
            "$id",
            "$defs",
            "title",
            "description",
            "examples",
            "default",
            "deprecated",
            "readOnly",
            "writeOnly",
            "$comment",
        }
        old_constraints = {
            key: value
            for key, value in (old if isinstance(old, dict) else {}).items()
            if key not in annotations
        }
        new_constraints = {key: value for key, value in current.items() if key not in annotations}
        changed = [
            key
            for key, value in new_constraints.items()
            if key not in old_constraints or old_constraints[key] != value
        ]
        if not changed:
            return []
        return [
            f"changed constraints on previously open values: {sorted(changed)} "
            "(review required: local comparison cannot prove containment through refs/combinators)"
        ]

    @staticmethod
    def _collect_conditional_required(schema: dict) -> set:
        """Collect (json_pointer, frozenset[fields]) for every `required` that sits
        under a conditional construct — the paths the node-by-node diff cannot see
        when the whole construct is new."""
        found = set()
        # Only branches that IMPOSE obligations count. A requirement inside `if`
        # narrows which artifacts the rule applies to, so it can never invalidate
        # one — including it would bury the real signal in noise.
        enter = ("then", "else", "allOf", "anyOf", "oneOf", "dependentRequired", "dependentSchemas")

        def walk(node, path, under_conditional):
            if isinstance(node, dict):
                if under_conditional and isinstance(node.get("required"), list):
                    found.add(("/" + "/".join(str(p) for p in path), frozenset(node["required"])))
                for key, value in node.items():
                    if key == "if":
                        continue
                    walk(value, [*path, key], under_conditional or key in enter)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*path, i], under_conditional)

        walk(schema, [], False)
        return found

    @staticmethod
    def _anyof_satisfied_by_old_required(current: dict, old: dict, pointer: str) -> bool:
        """True when `pointer` is a branch of an anyOf that every OLD artifact satisfies.

        An anyOf rejects only artifacts matching none of its branches. When
        every branch is a bare `{"required": [...]}` and one branch asks for
        nothing beyond what the OLD schema already required at the same node,
        every old artifact matches that branch, so the anyOf cannot invalidate
        one. Deliberately narrow: oneOf is excluded (matching two branches
        fails it), and so is any branch carrying more than `required`.
        """
        parts = pointer.strip("/").split("/")
        if len(parts) < 2 or parts[-2] != "anyOf":
            return False

        def resolve(schema: dict, segments: list[str]):
            node = schema
            for segment in segments:
                if isinstance(node, list) and segment.isdigit():
                    node = node[int(segment)]
                elif isinstance(node, dict) and segment in node:
                    node = node[segment]
                else:
                    return None
            return node

        parent_path = parts[:-2]
        branches = resolve(current, [*parent_path, "anyOf"])
        old_parent = resolve(old, parent_path)
        if not isinstance(branches, list) or not isinstance(old_parent, dict):
            return False
        if not all(isinstance(b, dict) and set(b) == {"required"} for b in branches):
            return False
        old_required = set(old_parent.get("required") or [])
        return any(set(b["required"]) <= old_required for b in branches)

    @staticmethod
    def _defs_reachable_only_via_new_properties(current: dict, old: dict) -> set:
        """Names of `$defs` that no artifact of the OLD schema could reach.

        A `$def` qualifies when unreferenced, or when EVERY reference chain
        from the root crosses a property forbidden by the OLD parent:
        `additionalProperties: false` with no patternProperties. Absence
        from `properties` alone does not forbid a value on an open object.

        Deliberately strict: reachable via even one pre-existing property (even
        an optional one, since an old artifact may well have populated it) and
        the def does not qualify.
        """

        def property_pointers(schema: dict) -> set:
            found = set()

            def walk(node, path):
                if isinstance(node, dict):
                    props = node.get("properties")
                    if isinstance(props, dict):
                        for name in props:
                            found.add("/" + "/".join([*path, "properties", name]))
                    for key, value in node.items():
                        walk(value, [*path, str(key)])
                elif isinstance(node, list):
                    for i, item in enumerate(node):
                        walk(item, [*path, str(i)])

            walk(schema, [])
            return found

        old_props = property_pointers(old)
        old_nodes = dict(TestBreakingChangeDetection._walk_schema(old, []))
        # (def_name -> set of bools: did this reference chain cross a new property?)
        arrivals: dict[str, set] = {}

        def walk(node, path, crossed_new, seen):
            if isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str) and ref.startswith("#/$defs/"):
                    name = ref[len("#/$defs/") :]
                    arrivals.setdefault(name, set()).add(crossed_new)
                    if name not in seen:
                        target = (current.get("$defs") or {}).get(name)
                        if isinstance(target, dict):
                            walk(target, ["$defs", name], crossed_new, seen | {name})
                for key, value in node.items():
                    if key == "$defs":
                        continue  # defs are visited through their refs only
                    if key == "properties" and isinstance(value, dict):
                        for name, sub in value.items():
                            sub_path = [*path, "properties", name]
                            ptr = "/" + "/".join(sub_path)
                            parent_pointer = "/" + "/".join(path) if path else ""
                            old_parent = old_nodes.get(parent_pointer, {})
                            impossible_before = (
                                ptr not in old_props
                                and old_parent.get("additionalProperties") is False
                                and not old_parent.get("patternProperties")
                            )
                            is_new = crossed_new or impossible_before
                            walk(sub, sub_path, is_new, seen)
                        continue
                    walk(value, [*path, str(key)], crossed_new, seen)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*path, str(i)], crossed_new, seen)

        walk(current, [], False, frozenset())
        return {
            name
            for name in (current.get("$defs") or {})
            if name not in arrivals or all(arrivals[name])
        }

    @staticmethod
    def _collect_required(node: dict) -> set:
        """Collect required field names."""
        if "required" in node and isinstance(node["required"], list):
            return set(node["required"])
        return set()

    @classmethod
    def _compare_schemas(cls, old_schema: dict, current_schema: dict, schema_name: str) -> list:
        """Return restrictions/review findings consumed by the CI breaking-change gate."""
        breaking_changes = []
        old_nodes = dict(cls._walk_schema(old_schema, []))
        current_nodes = dict(cls._walk_schema(current_schema, []))
        unreachable = cls._defs_reachable_only_via_new_properties(current_schema, old_schema)
        unreachable_properties = {
            f"{path}/properties/{name}"
            for path, node in old_nodes.items()
            if node.get("additionalProperties") is False and not node.get("patternProperties")
            for name in (
                cls._collect_properties(current_nodes.get(path, {})) - cls._collect_properties(node)
            )
        }

        def exempt(path):
            return "if" in path.strip("/").split("/") or any(
                path == prefix or path.startswith(f"{prefix}/")
                for prefix in [
                    *(f"/$defs/{name}" for name in unreachable),
                    *unreachable_properties,
                ]
            )

        for path, old_node in old_nodes.items():
            current_node = current_nodes.get(path)
            if current_node is None or exempt(path):
                continue
            old_props = cls._collect_properties(old_node)
            new_props = cls._collect_properties(current_node)
            removed = old_props - new_props
            if removed:
                breaking_changes.append(f"{schema_name}{path}: removed properties: {removed}")

            finite_old = cls._finite_values(old_node)
            if finite_old is not None or cls._finite_values(current_node) is not None:
                restrictions = cls._value_restrictions(
                    old_node, current_node, old_schema, current_schema
                )
            else:
                restrictions = []
            for restriction in restrictions:
                breaking_changes.append(f"{schema_name}{path}: {restriction}")

            old_extra = old_node.get("additionalProperties", True)
            new_extra = current_node.get("additionalProperties", True)
            old_type = old_node.get("type")
            object_possible = (
                old_type is None
                or old_type == "object"
                or (isinstance(old_type, list) and "object" in old_type)
            )
            compare_open_object = finite_old is None and object_possible
            if compare_open_object and old_extra != new_extra:
                for restriction in cls._value_restrictions(
                    old_extra, new_extra, old_schema, current_schema
                ):
                    breaking_changes.append(
                        f"{schema_name}{path}/additionalProperties: {restriction}"
                    )
            # A newly declared optional property is additive only when old
            # artifacts could not carry it, or its old value domain is retained.
            for name in sorted(new_props - old_props) if compare_open_object else []:
                if old_extra is False and not old_node.get("patternProperties"):
                    continue
                if old_node.get("patternProperties"):
                    if not cls._value_restrictions(
                        True, current_node["properties"][name], old_schema, current_schema
                    ):
                        continue
                    breaking_changes.append(
                        f"{schema_name}{path}/properties/{name}: review required: "
                        "old patternProperties may constrain this newly declared property"
                    )
                    continue
                for restriction in cls._value_restrictions(
                    old_extra, current_node["properties"][name], old_schema, current_schema
                ):
                    breaking_changes.append(f"{schema_name}{path}/properties/{name}: {restriction}")

            new_req = cls._collect_required(current_node) - cls._collect_required(old_node)
            if new_req:
                breaking_changes.append(f"{schema_name}{path}: new required fields: {new_req}")

        old_conds = cls._collect_conditional_required(old_schema)
        new_conds = cls._collect_conditional_required(current_schema)
        for pointer, fields in sorted(new_conds - old_conds):
            if exempt(pointer):
                continue
            if cls._anyof_satisfied_by_old_required(current_schema, old_schema, pointer):
                continue
            breaking_changes.append(
                f"{schema_name}{pointer}: new conditional requirement: {fields} "
                "(artifacts not satisfying it become invalid)"
            )
        return breaking_changes

    @staticmethod
    def _fail_on_breaking_changes(breaking_changes: list):
        """Use the same consumer-visible verdict for focused cases and the tag gate."""
        if breaking_changes:
            msg = "Breaking schema changes detected — requires MAJOR version bump and new tag:\n"
            for change in breaking_changes:
                msg += f"  - {change}\n"
            pytest.fail(msg)

    @pytest.mark.skipif(
        os.getenv("CONTRACTS_ALLOW_BREAKING") == "1",
        reason="Skipped when CONTRACTS_ALLOW_BREAKING=1",
    )
    def test_no_breaking_changes_vs_base(self):
        """Detect restrictions or review-required changes versus the change's base.

        Breaking changes (require MAJOR version bump):
        - Removing a property from a 'properties' object
        - Removing a value from an 'enum' array
        - Adding a new field to 'required'
        - Introducing enum/const restrictions or changing allowed const values
        - Restricting additionalProperties or newly declaring constrained properties on open objects

        Allowed (MINOR/PATCH):
        - Adding optional properties to closed objects (or preserving their old value domain)
        - Adding enum values
        - Removing from required
        - Documentation changes

        If this fails, this change breaks the contract. For an intentional
        break, bump VERSION to the next MAJOR and run with
        CONTRACTS_ALLOW_BREAKING=1.
        """
        base, chosen = self._compat_base()
        if not base:
            pytest.skip(f"No base to compare against ({chosen})")

        breaking_changes = []

        for schema_file in sorted(SCHEMA_DIR.glob("*.schema.json")):
            # Fetch schema from the base. Try the current (versioned) path first;
            # fall back to the pre-v1 unversioned path so the one-time schemas/ -> schemas/v1/
            # move doesn't make every schema look "new" and silently skip the gate.
            candidate_paths = [
                schema_file.relative_to(REPO_ROOT),
                Path("schemas") / schema_file.name,
            ]
            old_schema = None
            for candidate in candidate_paths:
                try:
                    result = subprocess.run(
                        ["git", "show", f"{base}:{candidate}"],
                        cwd=REPO_ROOT,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    old_schema = json.loads(result.stdout)
                    break
                except subprocess.CalledProcessError:
                    continue
            if old_schema is None:
                # Schema didn't exist at the base under any known path — not a breaking change
                continue

            # Load current schema
            current_schema = json.loads(schema_file.read_text(encoding="utf-8"))

            breaking_changes.extend(
                self._compare_schemas(old_schema, current_schema, schema_file.name)
            )

        self._fail_on_breaking_changes(breaking_changes)


class TestCompatibilityVerdicts:
    """Real old-valid instances must not silently become invalid at the CI gate."""

    H = TestBreakingChangeDetection

    @classmethod
    def _reject(cls, old, current, value):
        Draft202012Validator(old).validate(value)
        assert not Draft202012Validator(current).is_valid(value)
        with pytest.raises(pytest.fail.Exception):
            cls.H._fail_on_breaking_changes(cls.H._compare_schemas(old, current, "case.json"))

    @classmethod
    def _accept(cls, old, current, value):
        Draft202012Validator(old).validate(value)
        Draft202012Validator(current).validate(value)
        cls.H._fail_on_breaking_changes(cls.H._compare_schemas(old, current, "case.json"))

    @pytest.mark.parametrize(
        ("old", "current", "value"),
        [
            ({"type": "string"}, {"type": "string", "enum": ["canonical"]}, "historical"),
            ({"enum": ["old", "kept"]}, {"enum": ["kept"]}, "old"),
            ({"enum": ["old"]}, {"enum": []}, "old"),
            ({"const": ["old", "kept"]}, {"const": ["kept", "old"]}, ["old", "kept"]),
            ({"const": {"class": ["old"]}}, {"const": {"class": ["new"]}}, {"class": ["old"]}),
            ({"enum": [True, 1]}, {"enum": [1]}, True),
            ({"type": "object"}, {"type": "object", "additionalProperties": False}, {"extra": 1}),
            (
                {"type": "object"},
                {"type": "object", "additionalProperties": {"type": "string"}},
                {"extra": 42},
            ),
            (
                {"type": "object", "additionalProperties": {"type": "string"}},
                {"type": "object", "additionalProperties": {"type": "string", "enum": ["new"]}},
                {"extra": "historical"},
            ),
            (
                {"type": "object"},
                {"type": "object", "properties": {"fresh": {"type": "string"}}},
                {"fresh": 42},
            ),
            (
                {"type": "object", "additionalProperties": {"enum": ["old", "kept"]}},
                {"type": "object", "properties": {"fresh": {"enum": ["kept"]}}},
                {"fresh": "old"},
            ),
            (
                {"type": "object", "properties": {"kept": {"type": "string"}}},
                {"type": "object", "properties": {}, "additionalProperties": False},
                {"kept": "historical"},
            ),
            (
                {"type": "object"},
                {"type": "object", "required": ["new"]},
                {},
            ),
            (
                {"type": "object"},
                {"type": "object", "allOf": [{"if": {}, "then": {"required": ["new"]}}]},
                {},
            ),
        ],
        ids=[
            "first-enum",
            "enum-shrink",
            "empty-enum",
            "const-list-order",
            "const-object",
            "boolean-not-number",
            "open-to-closed",
            "typed-additional",
            "constrained-additional",
            "typed-new-property",
            "finite-extra-new-property",
            "removed-property",
            "new-required",
            "new-conditional",
        ],
    )
    def test_restrictions_fail_gate(self, old, current, value):
        self._reject(old, current, value)

    @pytest.mark.parametrize(
        ("old", "current", "value"),
        [
            ({"enum": ["old"]}, {"enum": ["old", "new"]}, "old"),
            ({"const": ["old"]}, {"enum": [["old"], ["new"]]}, ["old"]),
            ({"const": ["old"]}, {"anyOf": [{"const": ["old"]}, {"const": ["new"]}]}, ["old"]),
            ({"const": {"a": 1, "b": [2]}}, {"const": {"b": [2.0], "a": 1.0}}, {"a": 1, "b": [2]}),
            (
                {"type": "object", "additionalProperties": False},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"fresh": {"type": "string"}},
                },
                {},
            ),
            (
                {"type": "object", "additionalProperties": {"type": "string"}},
                {"type": "object", "properties": {"fresh": {"type": "string"}}},
                {"fresh": "historical"},
            ),
            ({"type": "object"}, {"type": "object", "properties": {"fresh": {}}}, {"fresh": 42}),
            ({"type": "object"}, {"type": "object", "additionalProperties": {}}, {"extra": 42}),
            (
                {"type": "object", "required": ["kept"]},
                {"type": "object", "required": []},
                {"kept": 42},
            ),
            (
                {"type": "object"},
                {"type": "object", "$defs": {"write": {"enum": ["new"], "required": ["new"]}}},
                {"historical": 42},
            ),
        ],
        ids=[
            "enum-expansion",
            "const-to-enum",
            "const-to-anyof",
            "json-equivalence",
            "optional-closed-property",
            "retained-extra-domain",
            "unrestricted-new-property",
            "explicit-open-equivalence",
            "removed-required",
            "unreferenced-write-fragment",
        ],
    )
    def test_additive_changes_pass_gate(self, old, current, value):
        self._accept(old, current, value)

    def test_optional_inline_conditional_on_closed_object_is_additive(self):
        old = {"type": "object", "additionalProperties": False}
        current = {
            **old,
            "properties": {
                "fresh": {"type": "object", "allOf": [{"if": {}, "then": {"required": ["x"]}}]}
            },
        }
        self._accept(old, current, {})

    def test_finite_object_domain_is_not_mistaken_for_open_values(self):
        old = {"type": "object", "const": {"historical": 42}}
        current = {**old, "properties": {"fresh": {"type": "string"}}}
        self._accept(old, current, {"historical": 42})

    def test_object_only_keywords_cannot_narrow_an_old_string(self):
        old = {"type": "string"}
        current = {
            **old,
            "additionalProperties": False,
            "properties": {"fresh": {"type": "string"}},
        }
        self._accept(old, current, "historical")

    @pytest.mark.parametrize("closed", [False, True], ids=["open", "closed"])
    def test_new_def_conditional_respects_old_parent_openness(self, closed):
        old = {"type": "object", "additionalProperties": not closed}
        current = {
            "type": "object",
            "additionalProperties": not closed,
            "properties": {"fresh": {"$ref": "#/$defs/fresh"}},
            "$defs": {"fresh": {"type": "object", "allOf": [{"required": ["x"]}]}},
        }
        if closed:
            self._accept(old, current, {})
        else:
            self._reject(old, current, {"fresh": {}})

    @pytest.mark.parametrize("route", ["existing", "nested-closed", "shared"])
    def test_referenced_def_requirements_respect_old_reachability(self, route):
        kept = {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "additionalProperties": False,
        }
        old = {
            "type": "object",
            "properties": {"kept": {"$ref": "#/$defs/kept"}},
            "$defs": {"kept": kept},
        }
        restrictive = {"type": "object", "allOf": [{"required": ["a"]}]}
        if route == "nested-closed":
            current = {
                **old,
                "$defs": {
                    "kept": {
                        **kept,
                        "properties": {**kept["properties"], "b": {"$ref": "#/$defs/new"}},
                    },
                    "new": restrictive,
                },
            }
            self._accept(old, current, {"kept": {}})
        else:
            properties = {"kept": {"$ref": "#/$defs/new"}}
            if route == "shared":
                properties["fresh"] = {"$ref": "#/$defs/new"}
            current = {
                **old,
                "properties": properties,
                "$defs": {**old["$defs"], "new": restrictive},
            }
            self._reject(old, current, {"kept": {}})

    @pytest.mark.parametrize(
        ("key", "branches", "breaking"),
        [
            ("anyOf", [{"required": ["x"]}, {"required": ["b", "c"]}], False),
            ("anyOf", [{"required": ["x"]}, {"required": ["b", "y"]}], True),
            ("oneOf", [{"required": ["b"]}, {"required": ["c"]}], True),
            (
                "anyOf",
                [{"required": ["x"]}, {"required": ["b"], "properties": {"b": {"type": "string"}}}],
                True,
            ),
        ],
    )
    def test_conditional_alternatives_keep_existing_guards(self, key, branches, breaking):
        old = {"type": "object", "required": ["a", "b", "c"]}
        current = {"type": "object", "required": ["a"], key: branches}
        value = {"a": 1, "b": 2, "c": 3}
        if breaking:
            self._reject(old, current, value)
        else:
            self._accept(old, current, value)


class TestCompatBase:
    """The gate compares against the change's base on main, never a stale tag."""

    def _with_git(self, monkeypatch, answers: dict):
        monkeypatch.delenv("CONTRACTS_COMPAT_BASE", raising=False)
        monkeypatch.setattr(
            TestBreakingChangeDetection, "_git", staticmethod(lambda *a: answers.get(a))
        )

    def test_a_branch_compares_against_its_merge_base(self, monkeypatch):
        self._with_git(
            monkeypatch,
            {("rev-parse", "HEAD"): "head1", ("merge-base", "HEAD", "origin/main"): "base0"},
        )
        assert TestBreakingChangeDetection._compat_base() == (
            "base0",
            "merge-base with origin/main",
        )

    def test_main_itself_compares_against_the_previous_commit(self, monkeypatch):
        self._with_git(
            monkeypatch,
            {
                ("rev-parse", "HEAD"): "head1",
                ("merge-base", "HEAD", "origin/main"): "head1",
                ("rev-parse", "--verify", "--quiet", "HEAD^1"): "parent0",
            },
        )
        assert TestBreakingChangeDetection._compat_base() == (
            "parent0",
            "the previous commit on main",
        )

    def test_falls_back_to_a_local_main(self, monkeypatch):
        self._with_git(
            monkeypatch,
            {("rev-parse", "HEAD"): "head1", ("merge-base", "HEAD", "main"): "base0"},
        )
        assert TestBreakingChangeDetection._compat_base()[0] == "base0"

    def test_an_explicit_base_wins(self, monkeypatch):
        self._with_git(monkeypatch, {})
        monkeypatch.setenv("CONTRACTS_COMPAT_BASE", "v0.48.1")
        assert TestBreakingChangeDetection._compat_base() == (
            "v0.48.1",
            "CONTRACTS_COMPAT_BASE=v0.48.1",
        )

    def test_no_main_means_no_base(self, monkeypatch):
        self._with_git(monkeypatch, {("rev-parse", "HEAD"): "head1"})
        assert TestBreakingChangeDetection._compat_base()[0] is None
