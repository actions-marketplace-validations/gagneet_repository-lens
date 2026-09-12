from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable

from .config import Config
from .model import Edge, Graph, Issue, Node, stable_id


FEATURE_RE = re.compile(r"@featuretrace:([A-Za-z0-9_.-]+)")
IMPORT_RE = re.compile(
    r"(?:import\s+(?:type\s+)?(?:[^'\"]+?\s+from\s+)?|require\()['\"]([^'\"]+)['\"]"
)
JS_FUNCTION_RE = re.compile(
    r"(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
)
JS_CALL_RE = re.compile(r"(?<![.$\w])([A-Za-z_$][\w$]*)\s*\(")
API_CALL_RE = re.compile(
    r"(?:\bapi\b|\baxios\b)\.(get|post|put|patch|delete)\s*\(\s*([`'\"])(.+?)\2|"
    r"\bfetch\s*\(\s*([`'\"])(.+?)\4",
    re.IGNORECASE,
)
RELATED_FIELD_RE = re.compile(r"^\s*(?:#|//|\*)?\s*Related:\s*(.+)$")
RELATED_CONT_RE = re.compile(r"^\s*(?:#|//|\*)\s{2,}(.+)$")

JS_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "function", "return", "typeof",
    "new", "super", "import", "require", "describe", "it", "test", "expect",
}


@dataclass(slots=True)
class PendingCall:
    source: str
    name: str
    evidence: str
    language: str


@dataclass(slots=True)
class ScanState:
    graph: Graph
    root: Path
    config: Config
    definitions: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    pending_calls: list[PendingCall] = field(default_factory=list)
    module_files: dict[str, str] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        # Unreadable, or deleted since the walk. Re-reading it would raise again, outside
        # any handler, and abort the whole scan over one file.
        return ""


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _file_id(path: str) -> str:
    return stable_id("file", path)


def _symbol_id(path: str, qualified: str) -> str:
    return stable_id("symbol", f"{path}::{qualified}")


def _endpoint_id(method: str, route: str) -> str:
    return stable_id("endpoint", f"{method.upper()} {normalise_route(route)}")


def normalise_route(route: str) -> str:
    route = route.strip()
    route = re.sub(r"\$\{[^}]+\}", "{dynamic}", route)
    route = re.sub(r"//+", "/", route)
    if route != "/":
        route = route.rstrip("/")
    return route or "/"


def iter_source_files(root: Path, config: Config) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in config.extensions:
            continue
        if any(part in config.exclude_dirs for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        if any(rel == item or rel.startswith(item + "/") for item in config.exclude_paths):
            continue
        yield path


def config_fingerprint(config: Config) -> str:
    """The settings and scanner version an index was built with. A cached index is
    reusable only when these match too: adding a role to `[impact] roles` changes the
    graph without changing a single source file."""
    from .. import __version__

    payload = json.dumps({"version": __version__, "config": asdict(config)}, sort_keys=True,
                         default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def repository_content_sha(root: Path, config: Config) -> str:
    """Return the same deterministic source fingerprint stored in an index."""
    root = root.resolve()
    digest = hashlib.sha256()
    for path in iter_source_files(root, config):
        text = _read(path)
        digest.update(_rel(root, path).encode("utf-8"))
        digest.update(hashlib.sha256(text.encode("utf-8")).digest())
    return digest.hexdigest()


class PythonVisitor(ast.NodeVisitor):
    def __init__(self, state: ScanState, path: str, file_node: str, text: str, router_prefix: str = ""):
        self.state = state
        self.path = path
        self.file_node = file_node
        self.text = text
        self.scope: list[str] = []
        self.symbol_stack: list[str] = []
        self.router_prefix = router_prefix

    def _current_source(self) -> str:
        return self.symbol_stack[-1] if self.symbol_stack else self.file_node

    def _add_definition(self, node: ast.AST, name: str, kind: str) -> str:
        qualified = ".".join([*self.scope, name])
        node_id = _symbol_id(self.path, qualified)
        doc = ast.get_docstring(node) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else None
        metadata = {"qualified_name": qualified, "symbol_kind": kind}
        if doc:
            metadata["doc"] = doc[:600]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body_dump = ast.dump(
                ast.Module(body=node.body, type_ignores=[]),
                annotate_fields=True,
                include_attributes=False,
            )
            if len(body_dump) >= 110:
                metadata["body_fingerprint"] = hashlib.sha256(body_dump.encode("utf-8")).hexdigest()
        self.state.graph.add_node(Node(
            id=node_id,
            kind="symbol",
            label=qualified,
            path=self.path,
            line=getattr(node, "lineno", None),
            language="python",
            metadata=metadata,
        ))
        self.state.graph.add_edge(Edge(
            self.file_node, node_id, "CONTAINS", "exact", "python_ast", origin="ast"
        ))
        self.state.definitions[name].append(node_id)
        return node_id

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol = self._add_definition(node, node.name, "class")
        self.scope.append(node.name)
        self.symbol_stack.append(symbol)
        self.generic_visit(node)
        self.symbol_stack.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        symbol = self._add_definition(node, node.name, "function")
        self._extract_fastapi_routes(node, symbol)
        self.scope.append(node.name)
        self.symbol_stack.append(symbol)
        self.generic_visit(node)
        self.symbol_stack.pop()
        self.scope.pop()

    def _extract_fastapi_routes(self, node: ast.FunctionDef | ast.AsyncFunctionDef, symbol: str) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in {"get", "post", "put", "patch", "delete"} or not decorator.args:
                continue
            if not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
                continue
            route = normalise_route(
                f"{self.state.config.backend_api_prefix}{self.router_prefix}{decorator.args[0].value}"
            )
            endpoint = _endpoint_id(method, route)
            self.state.graph.add_node(Node(
                endpoint, "endpoint", f"{method.upper()} {route}",
                path=self.path, line=getattr(decorator, "lineno", None), language="python",
                metadata={"method": method.upper(), "route": route},
            ))
            self.state.graph.add_edge(Edge(endpoint, symbol, "HANDLES_API", "exact", "python_ast", origin="ast"))

    def visit_Call(self, node: ast.Call) -> None:
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name:
            self.state.pending_calls.append(PendingCall(
                self._current_source(), name,
                f"{self.path}:{getattr(node, 'lineno', '?')}", "python",
            ))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "db":
            _add_store_edge(
                self.state.graph, self._current_source(), "mongo_collection",
                node.attr, "high", f"{self.path}:{getattr(node, 'lineno', '?')}",
            )
        self.generic_visit(node)


def _add_store_edge(
    graph: Graph, source: str, kind: str, name: str, resolution: str, evidence: str
) -> None:
    store_id = stable_id(kind, name)
    graph.add_node(Node(store_id, kind, name, metadata={"store": name}))
    graph.add_edge(Edge(source, store_id, "TOUCHES_STORE", resolution, evidence, origin="syntax"))


def _scan_python(state: ScanState, path: Path, text: str, file_node: str) -> None:
    rel = _rel(state.root, path)
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        state.graph.issues.append(Issue(
            "PYTHON_PARSE_ERROR", "warning", f"Could not parse {rel}: {exc.msg}",
            [file_node], f"{rel}:{exc.lineno or 1}", "Fix syntax or exclude generated/vendor code.",
        ))
        return
    router_prefix = ""
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(value, ast.Call):
            continue
        func_name = value.func.id if isinstance(value.func, ast.Name) else getattr(value.func, "attr", "")
        if func_name != "APIRouter":
            continue
        for keyword in value.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                router_prefix = keyword.value.value.rstrip("/")
    PythonVisitor(state, rel, file_node, text, router_prefix).visit(tree)


def _scan_javascript(state: ScanState, path: Path, text: str, file_node: str) -> None:
    rel = _rel(state.root, path)
    ranges: list[tuple[int, str]] = []
    for match in JS_FUNCTION_RE.finditer(text):
        name = match.group(1) or match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        node_id = _symbol_id(rel, name)
        state.graph.add_node(Node(
            node_id, "symbol", name, path=rel, line=line,
            language="typescript" if path.suffix in {".ts", ".tsx"} else "javascript",
            metadata={"qualified_name": name, "symbol_kind": "function"},
        ))
        state.graph.add_edge(Edge(file_node, node_id, "CONTAINS", "probable", "javascript_regex", origin="regex"))
        state.definitions[name].append(node_id)
        ranges.append((match.start(), node_id))

    def source_for(offset: int) -> str:
        candidates = [item for item in ranges if item[0] <= offset]
        return candidates[-1][1] if candidates else file_node

    for match in JS_CALL_RE.finditer(text):
        name = match.group(1)
        if name in JS_KEYWORDS:
            continue
        state.pending_calls.append(PendingCall(
            source_for(match.start()), name,
            f"{rel}:{text.count(chr(10), 0, match.start()) + 1}",
            "typescript" if path.suffix in {".ts", ".tsx"} else "javascript",
        ))

    for match in API_CALL_RE.finditer(text):
        if match.group(1):
            method, route = match.group(1).upper(), match.group(3)
        else:
            method, route = "GET", match.group(5)
        route = normalise_route(route)
        endpoint = _endpoint_id(method, route)
        state.graph.add_node(Node(
            endpoint, "endpoint", f"{method} {route}", path=rel,
            line=text.count("\n", 0, match.start()) + 1,
            metadata={"method": method, "route": route, "dynamic": "{dynamic}" in route},
        ))
        state.graph.add_edge(Edge(
            source_for(match.start()), endpoint, "CALLS_API",
            "probable" if "{dynamic}" in route else "exact", "javascript_regex",
            origin="regex", detail="dynamic route template" if "{dynamic}" in route else None,
        ))


def _resolve_import(root: Path, source: Path, import_path: str) -> Path | None:
    if not import_path.startswith("."):
        return None
    base = (source.parent / import_path).resolve()
    candidates = [base]
    for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".py"):
        candidates.append(Path(str(base) + suffix))
    for suffix in (".ts", ".tsx", ".js", ".jsx", ".py"):
        candidates.append(base / f"index{suffix}")
    for candidate in candidates:
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


_ORM_TABLE_RE = re.compile(r"""^\s+__tablename__\s*=\s*["']([A-Za-z_]\w*)["']""", re.MULTILINE)
_ORM_SCHEMA_RE = re.compile(r"""["']schema["']\s*:\s*["']([A-Za-z_]\w*)["']""")
_GENERIC_SQL_TABLE_RE = re.compile(
    r'\b(FROM|JOIN|INTO|UPDATE)\s+"?([a-z_][a-z0-9_]*)"?(?:\."?([a-z_][a-z0-9_]*)"?)?(?![\w."]|\s*\))(\s*\()?')
_SQL_NOT_TABLES = frozenset({"set", "lateral", "only", "select", "values", "skip", "nowait", "of"})


def _vocabulary(config: Config) -> tuple[re.Pattern | None, ...]:
    """(PostgreSQL table, document collection, role, toggle) patterns from config."""
    return _compile_vocabulary(tuple(config.pg_schemas), config.mongo_receiver,
                               tuple(config.roles), tuple(config.toggle_calls))


@lru_cache(maxsize=8)
def _compile_vocabulary(pg_schemas: tuple[str, ...], mongo_receiver: str, roles: tuple[str, ...],
                        toggle_calls: tuple[str, ...]) -> tuple[re.Pattern | None, ...]:
    """Compiled once per vocabulary, not once per file. A pattern with nothing to
    match is None, never an empty alternation, which would match everywhere."""
    def words(items: tuple[str, ...]) -> str:
        return "|".join(re.escape(item) for item in items)

    return (
        re.compile(rf"\b({words(pg_schemas)})\.([a-z_][a-z0-9_]*)\b") if pg_schemas else None,
        re.compile(rf"\b{re.escape(mongo_receiver)}\.([a-zA-Z_][a-zA-Z0-9_]*)\b") if mongo_receiver else None,
        re.compile(rf"\b({words(roles)})\b") if roles else None,
        re.compile(rf"(?:{'|'.join(toggle_calls)})[(\s'\"]+([a-z][a-z0-9_.-]+)") if toggle_calls else None,
    )


def _scan_generic(state: ScanState, path: Path, text: str, file_node: str) -> None:
    rel = _rel(state.root, path)
    for match in IMPORT_RE.finditer(text):
        target = _resolve_import(state.root, path, match.group(1))
        if target:
            target_rel = _rel(state.root, target)
            target_id = _file_id(target_rel)
            state.graph.add_node(Node(target_id, "file", target_rel, path=target_rel))
            state.graph.add_edge(Edge(file_node, target_id, "IMPORTS", "exact", f"{rel}:{text.count(chr(10), 0, match.start()) + 1}", origin="syntax"))

    tags = FEATURE_RE.findall(text)
    for tag in sorted(set(tags)):
        tag_id = stable_id("concept", f"featuretrace:{tag}")
        state.graph.add_node(Node(
            tag_id, "concept", tag, metadata={"source": "featuretrace", "concept_id": tag}
        ))
        state.graph.add_edge(Edge(file_node, tag_id, "DECLARES_CONCEPT", "declared", "featuretrace_marker", origin="declared"))

    pg_table_re, mongo_re, role_re, toggle_re = _vocabulary(state.config)
    for match in pg_table_re.finditer(text) if pg_table_re else ():
        _add_store_edge(state.graph, file_node, "postgres_table", f"{match.group(1)}.{match.group(2)}", "probable", f"{rel}:{text.count(chr(10), 0, match.start()) + 1}")
    if path.suffix == ".py":
        # An ORM class DECLARES its table, so this edge needs no configured schema list.
        for match in _ORM_TABLE_RE.finditer(text):
            start = text.rfind("\nclass ", 0, match.start())
            end = text.find("\nclass ", match.end())
            schema = _ORM_SCHEMA_RE.search(text[max(start, 0): end if end != -1 else len(text)])
            table = f"{schema.group(1)}.{match.group(1)}" if schema else match.group(1)
            _add_store_edge(state.graph, file_node, "postgres_table", table, "exact",
                            f"{rel}:{text.count(chr(10), 0, match.start()) + 1}")
        if not pg_table_re:
            # No schema list: fall back to SQL-shaped text. Keywords must be upper case,
            # so a Python `from x import y` never reads as a table.
            for match in _GENERIC_SQL_TABLE_RE.finditer(text):
                keyword, first, second, paren = match.groups()
                # A parenthesis opens INSERT's column list, and is a function call anywhere else.
                if first in _SQL_NOT_TABLES or (paren and keyword != "INTO"):
                    continue
                table = f"{first}.{second}" if second else first
                _add_store_edge(state.graph, file_node, "postgres_table", table, "probable",
                                f"{rel}:{text.count(chr(10), 0, match.start()) + 1}")
    if path.suffix != ".py" and mongo_re:
        for match in mongo_re.finditer(text):
            _add_store_edge(state.graph, file_node, "mongo_collection", match.group(1), "probable", f"{rel}:{text.count(chr(10), 0, match.start()) + 1}")

    for role in sorted(set(role_re.findall(text))) if role_re else ():
        role_id = stable_id("policy", f"role:{role}")
        state.graph.add_node(Node(role_id, "policy", role, metadata={"policy_kind": "role"}))
        state.graph.add_edge(Edge(file_node, role_id, "GUARDED_BY", "ambiguous", "literal_role_reference", origin="heuristic"))
    for toggle in sorted(set(toggle_re.findall(text))) if toggle_re else ():
        toggle_id = stable_id("policy", f"toggle:{toggle}")
        state.graph.add_node(Node(toggle_id, "policy", toggle, metadata={"policy_kind": "feature_toggle"}))
        state.graph.add_edge(Edge(file_node, toggle_id, "GUARDED_BY", "probable", "toggle_reference", origin="regex"))

    if rel.endswith("/page.tsx") or rel.endswith("/page.jsx"):
        parts = rel.split("/")
        try:
            app_index = parts.index("app")
            route_parts = [p for p in parts[app_index + 1:-1] if not (p.startswith("(") and p.endswith(")"))]
            route = "/" + "/".join(route_parts)
            route = route if route != "" else "/"
            page_id = stable_id("page", route)
            state.graph.add_node(Node(page_id, "page", route, path=rel, metadata={"route": route}))
            state.graph.add_edge(Edge(page_id, file_node, "IMPLEMENTED_BY", "exact", "next_app_router_path", origin="framework_path"))
        except ValueError:
            pass

    _scan_related_fields(state, rel, text, file_node)


def _scan_related_fields(state: ScanState, rel: str, text: str, file_node: str) -> None:
    lines = text.splitlines()
    collecting = False
    for index, line in enumerate(lines, start=1):
        match = RELATED_FIELD_RE.match(line)
        if match:
            collecting = True
            value = match.group(1).strip()
        elif collecting:
            cont = RELATED_CONT_RE.match(line)
            if not cont:
                collecting = False
                continue
            value = cont.group(1).strip()
        else:
            continue
        token = value.split()[0].rstrip(",;)") if value else ""
        if not token or "/" not in token:
            continue
        target_path = token.replace("`", "")
        if (state.root / target_path).is_file():
            target = _file_id(target_path)
            state.graph.add_node(Node(target, "file", target_path, path=target_path))
            state.graph.add_edge(Edge(file_node, target, "RELATED_TO", "declared", f"{rel}:{index}", origin="declared"))
        else:
            state.graph.issues.append(Issue(
                "DANGLING_RELATED", "warning", f"Related target does not exist: {target_path}",
                [file_node], f"{rel}:{index}", "Correct the path or remove the stale relationship.",
            ))


def _listish(raw: dict, key: str) -> list:
    """`raw.get(key, [])` does NOT default a key that exists holding `None`.

    This is footgun #14 in the repository these adapters were written to read, and
    `docs/architecture/canonical_owners.json` is full of it: 58 of its 65 entries
    serialise `consumers: null` (the field is optional in the source YAML, and the
    generator emits the key regardless). The result was a hard TypeError partway
    through `_load_canonical_owners` — after the AST scan had completed — so the whole
    run died with no output at the one step that reads declared policy.

    An absent key and a null key mean the same thing here: nothing declared.
    """
    value = raw.get(key)
    return value if isinstance(value, (list, tuple)) else []


def _load_canonical_owners(state: ScanState) -> None:
    configured = state.config.canonical_owners_json
    if not configured:
        return
    path = state.root / configured
    if not path.is_file():
        return
    try:
        payload = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        state.graph.issues.append(Issue(
            "BAD_CANONICAL_OWNER_ARTIFACT", "warning", f"Cannot parse {configured}: {exc}",
            [], configured, "Regenerate or correct the canonical-owner JSON artifact.",
        ))
        return
    for raw in payload.get("concepts", []):
        concept = str(raw.get("concept", "")).strip()
        owner = str(raw.get("owner", "")).strip()
        if not concept or not owner:
            continue
        concept_id = stable_id("concept", f"canonical:{concept}")
        state.graph.add_node(Node(
            concept_id, "concept", concept,
            metadata={
                "source": "canonical_owners", "concept_id": concept,
                "rule": raw.get("rule"), "why": raw.get("why"),
                "symbols": _listish(raw, "symbols"),
            },
        ))
        owner_id = _file_id(owner)
        state.graph.add_node(Node(owner_id, "file", owner, path=owner))
        state.graph.add_edge(Edge(concept_id, owner_id, "OWNS", "declared", configured, origin="policy"))
        for symbol in _listish(raw, "symbols"):
            candidates = state.definitions.get(str(symbol), [])
            for candidate in candidates:
                if state.graph.nodes[candidate].path == owner:
                    state.graph.add_edge(Edge(concept_id, candidate, "OWNED_SYMBOL", "exact", configured, origin="policy+ast"))
        for test_path in _listish(raw, "tests"):
            test_id = _file_id(str(test_path))
            state.graph.add_node(Node(test_id, "file", str(test_path), path=str(test_path)))
            state.graph.add_edge(Edge(concept_id, test_id, "VERIFIED_BY", "declared", configured, origin="policy"))
        for consumer in _listish(raw, "consumers"):
            consumer_path = consumer if isinstance(consumer, str) else consumer.get("path")
            if not consumer_path:
                continue
            consumer_id = _file_id(str(consumer_path))
            state.graph.add_node(Node(consumer_id, "file", str(consumer_path), path=str(consumer_path)))
            state.graph.add_edge(Edge(
                consumer_id, concept_id, "CONSUMES", "declared", configured,
                origin="policy", detail=consumer.get("relationship") if isinstance(consumer, dict) else None,
            ))
        for violation in _listish(raw, "found_violations"):
            state.graph.issues.append(Issue(
                "CANONICAL_OWNER_VIOLATION", "error",
                f"{concept} has a recorded non-owner implementation: {violation}",
                [concept_id], configured,
                "Repoint the implementation to the canonical owner or document a genuine distinct concept.",
            ))


def _load_router_datastore_map(state: ScanState) -> None:
    configured = state.config.router_datastore_json
    if not configured:
        return
    path = state.root / configured
    if not path.is_file():
        return
    try:
        payload = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        state.graph.issues.append(Issue(
            "BAD_ROUTER_DATASTORE_ARTIFACT", "warning", f"Cannot parse {configured}: {exc}",
            [], configured, "Regenerate or correct the router/datastore JSON artifact.",
        ))
        return
    for router in payload.get("routers", []):
        router_path = str(router.get("file") or "").strip()
        if not router_path:
            continue
        router_id = _file_id(router_path)
        state.graph.add_node(Node(
            router_id, "file", router_path, path=router_path,
            metadata={"wired": router.get("wired"), "classification": router.get("classification")},
        ))
        for route in router.get("routes", []):
            method = str(route.get("method", "GET")).upper()
            raw_path = str(route.get("path", "/"))
            endpoint_path = normalise_route(f"{state.config.backend_api_prefix}{raw_path}")
            endpoint_id = _endpoint_id(method, endpoint_path)
            state.graph.add_node(Node(
                endpoint_id, "endpoint", f"{method} {endpoint_path}", path=router_path,
                metadata={"method": method, "route": endpoint_path, "wired": router.get("wired")},
            ))
            state.graph.add_edge(Edge(
                endpoint_id, router_id, "IMPLEMENTED_BY", "declared", configured,
                origin="generated_static_artifact",
            ))
        for field, relationship in (("mongo_reads", "READS_STORE"), ("mongo_writes", "WRITES_STORE")):
            value = router.get(field, {})
            names = value.keys() if isinstance(value, dict) else value or []
            for name in names:
                store_id = stable_id("mongo_collection", str(name))
                state.graph.add_node(Node(store_id, "mongo_collection", str(name), metadata={"store": str(name)}))
                state.graph.add_edge(Edge(
                    router_id, store_id, relationship, "declared", configured,
                    origin="generated_static_artifact",
                ))
        for name in router.get("postgres_tables", []):
            store_id = stable_id("postgres_table", str(name))
            state.graph.add_node(Node(store_id, "postgres_table", str(name), metadata={"store": str(name)}))
            state.graph.add_edge(Edge(
                router_id, store_id, "TOUCHES_STORE", "declared", configured,
                origin="generated_static_artifact",
            ))
        for name in router.get("postgres_unverified_refs", []):
            store_id = stable_id("postgres_table", str(name))
            state.graph.add_node(Node(store_id, "postgres_table", str(name), metadata={"store": str(name), "unverified": True}))
            state.graph.add_edge(Edge(
                router_id, store_id, "TOUCHES_STORE", "ambiguous", configured,
                origin="generated_static_artifact", detail="PostgreSQL name not validated against a live catalog",
            ))
        if router.get("wired") is False:
            state.graph.issues.append(Issue(
                "UNWIRED_ROUTER", "warning", f"Router is declared but not wired: {router_path}",
                [router_id], configured,
                "Confirm whether the router is intentionally dormant or missing from application registration.",
            ))


def _resolve_calls(state: ScanState) -> None:
    grouped: dict[tuple[str, str], list[PendingCall]] = defaultdict(list)
    for call in state.pending_calls:
        grouped[(call.source, call.name)].append(call)
    for (source, name), calls in grouped.items():
        targets = sorted(set(state.definitions.get(name, [])))
        if not targets:
            continue
        if len(targets) > state.config.max_ambiguous_targets:
            continue
        resolution = "exact" if len(targets) == 1 else "ambiguous"
        evidence = calls[0].evidence
        for target in targets:
            if target == source:
                continue
            state.graph.add_edge(Edge(
                source, target, "CALLS", resolution,
                "unique_symbol_name" if len(targets) == 1 else "ambiguous_symbol_name",
                origin="name_resolution", detail=evidence,
            ))
        if len(targets) > 1:
            state.graph.issues.append(Issue(
                "AMBIGUOUS_CALL", "info",
                f"Call to {name} has {len(targets)} possible definitions.",
                [source, *targets[:6]], evidence,
                "Treat this edge as a candidate until imports or type information resolve it.",
                subject=name,
            ))


def _detect_endpoint_gaps(state: ScanState) -> None:
    incoming_kinds: dict[str, set[str]] = defaultdict(set)
    outgoing_kinds: dict[str, set[str]] = defaultdict(set)
    for edge in state.graph.edges:
        outgoing_kinds[edge.source].add(edge.kind)
        incoming_kinds[edge.target].add(edge.kind)
    for node in state.graph.nodes.values():
        if node.kind != "endpoint":
            continue
        called = "CALLS_API" in incoming_kinds[node.id]
        handled = bool({"HANDLES_API", "IMPLEMENTED_BY"} & outgoing_kinds[node.id])
        if called and not handled:
            state.graph.issues.append(Issue(
                "API_CALL_WITHOUT_HANDLER", "warning",
                f"No matching backend handler was found for {node.label}.", [node.id],
                node.path or node.label,
                "Check API prefixes, dynamic path normalization, proxy routes, or a missing backend handler.",
            ))
        elif handled and not called:
            state.graph.issues.append(Issue(
                "API_HANDLER_WITHOUT_STATIC_CALLER", "info",
                f"No static frontend caller was found for {node.label}.", [node.id],
                node.path or node.label,
                "Confirm whether this is external, scheduled, dynamically invoked, or unreachable.",
            ))


def _detect_structural_duplicates(state: ScanState) -> None:
    groups: dict[str, list[Node]] = defaultdict(list)
    for node in state.graph.nodes.values():
        fingerprint = node.metadata.get("body_fingerprint")
        if not fingerprint or not node.path:
            continue
        if node.path.startswith(("tests/", "test/")) or "/tests/" in node.path:
            continue
        groups[str(fingerprint)].append(node)
    for fingerprint, nodes in groups.items():
        paths = {node.path for node in nodes}
        if len(nodes) < 2 or len(paths) < 2:
            continue
        ordered = sorted(nodes, key=lambda item: (item.path or "", item.line or 0, item.label))
        for left, right in zip(ordered, ordered[1:]):
            state.graph.add_edge(Edge(
                left.id, right.id, "STRUCTURALLY_SIMILAR", "ambiguous",
                f"python_ast_body:{fingerprint[:16]}", origin="heuristic",
            ))
        state.graph.issues.append(Issue(
            "SIMILAR_FUNCTION_BODY", "info",
            f"{len(ordered)} Python functions in different files have the same normalized AST body.",
            [node.id for node in ordered[:8]], f"python_ast_body:{fingerprint[:16]}",
            "Review for a shared owner, but keep distinct implementations when their business meaning differs.",
        ))


def scan_repository(root: Path, config: Config | None = None) -> Graph:
    root = root.resolve()
    config = config or Config.load(root)
    graph = Graph(root=str(root))
    state = ScanState(graph=graph, root=root, config=config)
    state.files = list(iter_source_files(root, config))

    digest = hashlib.sha256()
    for path in state.files:
        rel = _rel(root, path)
        text = _read(path)
        digest.update(rel.encode("utf-8"))
        digest.update(hashlib.sha256(text.encode("utf-8")).digest())
        file_node = _file_id(rel)
        graph.add_node(Node(
            file_node, "file", rel, path=rel,
            language=path.suffix.lstrip("."),
            metadata={"size": len(text), "lines": text.count("\n") + 1},
        ))
        # A scanner walks whatever a checkout happens to contain, including vendored
        # third-party code nobody chose. `_scan_python` caught SyntaxError only, so a
        # single deeply-nested expression raised RecursionError out of ast.visit and
        # took the ENTIRE scan with it — no graph, no diagnostics, no partial result.
        # Hit on strata-management: a file under `_archive/venv-root-stale/` (the
        # directory is not named `venv`, so the default exclude does not match it),
        # while every file the repo actually owns tops out at AST depth 24.
        # An unreadable file is a diagnostic; it is not a reason to report nothing.
        try:
            _scan_generic(state, path, text, file_node)
            if path.suffix == ".py":
                _scan_python(state, path, text, file_node)
            elif path.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                _scan_javascript(state, path, text, file_node)
        except RecursionError:
            state.graph.issues.append(Issue(
                "FILE_TOO_DEEPLY_NESTED", "warning",
                f"Could not walk {rel}: expression nesting exceeded the interpreter's "
                "recursion limit. The file is skipped; the rest of the scan continues.",
                [file_node], rel,
                "Usually vendored or generated code. Exclude it, or raise the "
                "recursion limit if the file is one you own and need indexed.",
            ))
        except Exception as exc:  # noqa: BLE001 - one file may never end the run
            state.graph.issues.append(Issue(
                "FILE_SCAN_FAILED", "warning",
                f"Could not scan {rel}: {type(exc).__name__}: {exc}",
                [file_node], rel,
                "Report the file; the scan continued without it, so this result is "
                "incomplete for that path only.",
            ))

    _resolve_calls(state)
    _load_canonical_owners(state)
    _load_router_datastore_map(state)
    _detect_endpoint_gaps(state)
    _detect_structural_duplicates(state)
    graph.metadata.update({
        "content_sha256": digest.hexdigest(),
        "config_sha256": config_fingerprint(config),
        "file_count": len(state.files),
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "issue_count": len(graph.issues),
        "evidence_model": "declared intent, static syntax, lexical inference kept separate",
    })
    return graph
