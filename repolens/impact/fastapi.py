"""Resolve static FastAPI routes, router mounts, dependencies and request/response models
from already parsed, admitted files.

A route's path is the chain of every `include_router`/`mount` above its router, each
with a prefix that may be a literal, a module constant or a settings class default.
Nothing here imports or runs the application: a value that is not static text is
reported (DYNAMIC_ROUTER_PREFIX, DYNAMIC_ROUTE_DECLARATION), never guessed.
"""
from __future__ import annotations

import ast
import warnings
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterator

from ..scan.python_ast import annotated_aliases, dotted, functions, keyword_value, last, module_level
from .model import Edge, Issue, Node
from .state import with_api_prefix, PendingCall, ScanState, _endpoint_id, _symbol_id, normalise_route

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"})
_BASE_CONSTRUCTORS = frozenset({"APIRouter", "FastAPI"})
_DEPENDENCY_MARKERS = frozenset({"Depends", "Security"})
#: Parameter markers that take a value from somewhere other than the request body.
_NOT_BODY_MARKERS = frozenset({"Depends", "Security", "Header", "Query", "Path", "Cookie"})
_ENUM_BASES = frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"})
_MAX_DEPTH = 12
#: Longest string annotation re-parsed, and longest expression unparsed into a message.
_MAX_ANNOTATION_TEXT = 2_000
_MAX_UNPARSED_SPAN = 2_000

Key = tuple[str, str]  # (module path, router variable; "<function>.<variable>" inside a factory)


def _shown(expr: ast.AST, limit: int = 120) -> str:
    """`expr` as source for a message, bounded: a huge or deeply nested expression is
    summarised rather than unparsed, since unparsing recurses once per level."""
    lines = (getattr(expr, "end_lineno", None) or 0) - (getattr(expr, "lineno", None) or 0)
    span = (getattr(expr, "end_col_offset", None) or 0) - (getattr(expr, "col_offset", None) or 0)
    if lines > 20 or span > _MAX_UNPARSED_SPAN:
        return f"<{type(expr).__name__} expression>"
    try:
        return ast.unparse(expr)[:limit]
    except (RecursionError, ValueError, MemoryError):
        return f"<{type(expr).__name__} expression>"


@dataclass(frozen=True)
class _Dep:
    name: str    # dotted, as written: `get_db`, `deps.get_current_user`
    module: str  # the module the name is written in, which resolves it
    line: int


@dataclass(frozen=True)
class _Link:
    parent: Key
    prefix: str
    dependencies: tuple[_Dep, ...]
    # A mounted sub-application does not run its parent's app-level dependencies.
    inherit: bool


class _Module:
    """Module-level definitions, including those under if/try/with/for."""
    __slots__ = ("classes", "functions", "assigns", "sequences")

    def __init__(self, tree: ast.Module):
        self.classes: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.assigns: dict[str, ast.AST] = _assignments(module_level(tree))
        for node in module_level(tree):
            if isinstance(node, ast.ClassDef):
                self.classes[node.name] = node
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
        self.sequences = _sequences(self.assigns)


def _assignments(statements) -> dict[str, ast.AST]:
    found: dict[str, ast.AST] = {}
    for node in statements:
        node = node[0] if isinstance(node, tuple) else node
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            found[node.target.id] = node.value
    return found


def _sequences(assigns: dict[str, ast.AST]) -> dict[str, list[ast.expr]]:
    return {name: list(value.elts) for name, value in assigns.items() if isinstance(value, (ast.List, ast.Tuple))}


def _statements(body: list[ast.stmt], sequences: dict[str, list[ast.expr]]
                ) -> Iterator[tuple[ast.stmt, dict[str, list[ast.expr]]]]:
    """Statements of one body, including those under if/try/with/for but never inside a
    nested def or class, each with the values a literal `for` loop variable takes there:
    `for mod in (a, b): app.include_router(mod.router)` mounts both routers."""
    stack: list[tuple[ast.stmt, dict[str, list[ast.expr]]]] = [(s, {}) for s in reversed(body)]
    while stack:
        node, env = stack.pop()
        yield node, env
        inner = env
        if isinstance(node, (ast.For, ast.AsyncFor)):
            inner = dict(env)
            if isinstance(node.target, ast.Name):
                it = node.iter
                values = (it.elts if isinstance(it, (ast.List, ast.Tuple, ast.Set))
                          else sequences.get(it.id) if isinstance(it, ast.Name) else None)
                if values is None:
                    inner.pop(node.target.id, None)
                else:
                    inner[node.target.id] = list(values)
            children = [*node.body, *node.orelse]
        elif isinstance(node, (ast.If, ast.While, ast.With, ast.AsyncWith, ast.Try)) or type(node).__name__ == "TryStar":
            children = [*getattr(node, "body", []), *getattr(node, "orelse", []), *getattr(node, "finalbody", [])]
            for handler in getattr(node, "handlers", []):
                children.extend(handler.body)
        else:
            continue
        stack.extend((child, inner) for child in reversed(children))


def _calls(statement: ast.stmt) -> Iterator[ast.Call]:
    """Calls a statement makes itself; a compound statement's body is yielded separately."""
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Try)) \
            or type(statement).__name__ == "TryStar":
        return
    if isinstance(statement, (ast.If, ast.While)):
        roots: list[ast.AST] = [statement.test]
    elif isinstance(statement, (ast.For, ast.AsyncFor)):
        roots = [statement.iter]
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        roots = [item.context_expr for item in statement.items]
    else:
        roots = [statement]
    for root in roots:
        for node in ast.walk(root):
            if isinstance(node, ast.Call):
                yield node


def _candidates(arg: ast.expr, env: dict[str, list[ast.expr]]) -> list[ast.expr]:
    if isinstance(arg, ast.Name) and arg.id in env:
        return env[arg.id]
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in env:
        return [ast.Attribute(value=value, attr=arg.attr, ctx=ast.Load()) for value in env[arg.value.id]]
    return [arg]


def _scoped(scope: str, name: str) -> str:
    return f"{scope}.{name}" if scope else name


def _chain(scope: str) -> Iterator[str]:
    while True:
        yield scope
        if not scope:
            return
        scope = scope.rpartition(".")[0]


def _is_marker(node: ast.AST | None, names: frozenset[str]) -> bool:
    return isinstance(node, ast.Call) and last(node.func) in names


def _parameters(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.AST | None]]:
    args = fn.args
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    return [*zip(positional, defaults, strict=True), *zip(args.kwonlyargs, args.kw_defaults, strict=True)]


def _annotated(annotation: ast.AST | None) -> tuple[ast.AST | None, list[ast.AST]]:
    """`Annotated[T, m1, m2]` -> (T, [m1, m2]); anything else -> (itself, [])."""
    if isinstance(annotation, ast.Subscript) and last(annotation.value) == "Annotated" \
            and isinstance(annotation.slice, ast.Tuple) and annotation.slice.elts:
        return annotation.slice.elts[0], list(annotation.slice.elts[1:])
    return annotation, []


def _dependency_target(marker: ast.Call, fallback: ast.AST | None) -> ast.AST | None:
    """`Depends(get_db)` -> get_db; `Depends(require("admin"))` -> require; a bare
    `Depends()` depends on the parameter's annotated class."""
    target = marker.args[0] if marker.args else keyword_value(marker, "dependency")
    if target is None:
        target = fallback
    return target.func if isinstance(target, ast.Call) else target


def _type_names(annotation: ast.AST) -> list[str]:
    """Class names a parameter or return annotation can hold: `list[Item] | None` ->
    [list, Item]; `Annotated[Item, Body()]` -> [Item]. Builtins fall out at resolution."""
    names: list[str] = []
    stack = [annotation]
    while stack and len(names) < 20:
        node = stack.pop()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # A string annotation is parsed again here, outside the per-file guard, so
            # an absurdly long or nested one must not end the whole route pass.
            if len(node.value) > _MAX_ANNOTATION_TEXT:
                continue
            try:
                with warnings.catch_warnings():  # the target's own SyntaxWarnings are not ours to print
                    warnings.simplefilter("ignore")
                    stack.append(ast.parse(node.value, mode="eval").body)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
        elif isinstance(node, ast.Subscript):
            base = last(node.value)
            elts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            if base == "Literal":
                continue
            if base == "Annotated":
                stack.extend(elts[:1])
                continue
            stack.append(node.value)
            stack.extend(elts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            stack.extend((node.left, node.right))
        elif isinstance(node, (ast.Tuple, ast.List)):
            stack.extend(node.elts)
        elif name := dotted(node):
            names.append(name)
    return names


class _FastAPI:
    def __init__(self, state: ScanState):
        self.state = state
        self.graph = state.graph
        self.modules = {path: _Module(tree) for path, tree in state.python_trees.items()}
        self.constructors = self._constructors()
        self.owners: dict[Key, tuple[str, str, ast.Call]] = {}  # key -> (module, scope, constructor call)
        self.aliases: dict[Key, Key] = {}  # `app = create_app()` -> the app create_app returns
        self.parents: dict[Key, list[_Link]] = defaultdict(list)
        self.locals: dict[tuple[str, str], dict[str, ast.AST]] = {}
        self.function_nodes: dict[str, tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self._own_cache: dict[Key, tuple[str, tuple[_Dep, ...]]] = {}
        self._mount_cache: dict[Key, list[tuple[str, tuple[_Dep, ...]]]] = {}
        self._alias_cache: dict[str, dict[str, ast.Call]] = {}
        self._linked: set[tuple[str, _Dep]] = set()
        self._issued: set[tuple[str, str, str]] = set()

    # -- resolution helpers ---------------------------------------------------------

    def _constructors(self) -> frozenset[str]:
        """APIRouter, FastAPI and every class deriving from one (`class MyRouter(APIRouter)`),
        local or imported, by class name."""
        names = set(_BASE_CONSTRUCTORS)
        classes = [(name, [last(base) for base in cls.bases])
                   for module in self.modules.values() for name, cls in module.classes.items()]
        # `from fastapi import APIRouter as _APIRouter`: the local name constructs a router too.
        # Read from the import statements as well as the recorded bindings: an import whose
        # top-level name is also a local file or folder (a vendored `fastapi.py`) is left
        # unbound, and the alias must not be lost with it.
        aliases = [(local, target[1]) for path in self.modules
                   for local, target in self.state.imports.get(path, {}).items() if target[1] not in {"*", local}]
        aliases += [(alias.asname, alias.name) for tree in self.state.python_trees.values()
                    for statement, _ in _statements(tree.body, {}) if isinstance(statement, ast.ImportFrom)
                    for alias in statement.names if alias.asname and alias.asname != alias.name]
        changed = True
        while changed:
            changed = False
            for name, bases in [*classes, *((local, [original]) for local, original in aliases)]:
                if name not in names and any(base in names for base in bases):
                    names.add(name)
                    changed = True
        return frozenset(names)

    def _issue(self, code: str, severity: str, message: str, nodes: list[str], evidence: str,
               recommendation: str) -> None:
        key = (code, evidence, message)
        if key not in self._issued:
            self._issued.add(key)
            self.graph.issues.append(Issue(code, severity, message, nodes, evidence, recommendation))

    def _bindings(self, path: str) -> dict[str, tuple[str, str]]:
        # `external:` targets (stdlib, site-packages) are never a definition to follow.
        return {name: target for name, target in self.state.imports.get(path, {}).items()
                if not target[0].startswith("external:")}

    def _locate(self, path: str, name: str, depth: int = 0) -> Key | None:
        """(module, top-level name) that `name`, possibly dotted, refers to in `path`,
        through import bindings, package submodules and re-exports."""
        if depth > _MAX_DEPTH or path not in self.modules:
            return None
        module = self.modules[path]
        bindings = self._bindings(path)
        parts = name.split(".")
        if len(parts) == 1:
            if name in module.classes or name in module.functions:
                return (path, name)
            binding = bindings.get(name)
            # Before module assignments: `try: from app.routes import c` /
            # `except ImportError: c = None` still mounts the imported router.
            if binding and binding[1] != "*":
                return self._locate(binding[0], binding[1], depth + 1)
            return (path, name) if name in module.assigns else None
        for size in range(len(parts) - 1, 0, -1):
            binding = bindings.get(".".join(parts[:size]))
            if not binding:
                continue
            target, exported = binding
            if exported != "*":
                return None  # an attribute of an imported object, not of a module
            rest = parts[size:]
            while len(rest) > 1:
                index = self.state.import_index
                submodule = (index.python(target, rest[0], 1)
                             if index is not None and target.endswith("__init__.py") else None)
                if submodule is None:
                    return None
                target, rest = submodule, rest[1:]
            return self._locate(target, rest[0], depth + 1)
        return None

    def _canonical(self, key: Key | None) -> Key | None:
        for _ in range(_MAX_DEPTH):
            if key is None or key in self.owners:
                return key
            key = self.aliases.get(key)
        return None

    def _router(self, path: str, scope: str, expr: ast.AST | None) -> Key | None:
        name = dotted(expr) if expr is not None else ""
        if not name:
            return None
        if "." not in name:
            for enclosing in _chain(scope):
                key = (path, _scoped(enclosing, name))
                if key in self.owners or key in self.aliases:
                    return self._canonical(key)
        return self._canonical(self._locate(path, name))

    def _locals(self, path: str, scope: str) -> dict[str, ast.AST] | None:
        return self.locals.get((path, scope)) if scope else None

    def _text(self, path: str, expr: ast.AST | None, local: dict[str, ast.AST] | None = None,
              depth: int = 0) -> str | None:
        """Static text: a literal, a concatenation or f-string of static parts, a module
        constant (`PREFIX = "/v1"`), or a class attribute default reached through an
        instance (`settings.API_V1_STR` where `settings = Settings()`)."""
        if expr is None or depth > _MAX_DEPTH or path not in self.modules:
            return None
        if isinstance(expr, ast.Constant):
            return expr.value if isinstance(expr.value, str) else None
        if isinstance(expr, ast.JoinedStr):
            parts = []
            for value in expr.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                    text = self._text(path, value.value, local, depth + 1)
                    if text is None:
                        return None
                    parts.append(text)
                else:
                    return None
            return "".join(parts)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._text(path, expr.left, local, depth + 1)
            right = self._text(path, expr.right, local, depth + 1) if left is not None else None
            return left + right if right is not None else None
        if isinstance(expr, ast.Name) and local and expr.id in local:
            return self._text(path, local[expr.id], local, depth + 1)
        name = dotted(expr)
        if name and (found := self._locate(path, name)) and found[1] in self.modules[found[0]].assigns:
            return self._text(found[0], self.modules[found[0]].assigns[found[1]], None, depth + 1)
        if isinstance(expr, ast.Attribute):
            owner = self._class_of(path, expr.value, local, depth + 1)
            if owner:
                return self._class_attribute(owner[0], owner[1], expr.attr, depth + 1)
        return None

    def _class_of(self, path: str, expr: ast.AST, local: dict[str, ast.AST] | None,
                  depth: int) -> tuple[str, ast.ClassDef] | None:
        """The class an expression is (`Settings`) or is an instance of (`settings`,
        `get_settings()`), when that is statically evident."""
        if depth > _MAX_DEPTH:
            return None
        if isinstance(expr, ast.Call):
            return self._instance(path, expr.func, depth + 1)
        name = dotted(expr)
        if not name:
            return None
        value = local.get(name) if local else None
        if value is None:
            found = self._locate(path, name)
            if found is None:
                return None
            module = self.modules[found[0]]
            if found[1] in module.classes:
                return found[0], module.classes[found[1]]
            path, value = found[0], module.assigns.get(found[1])
        return self._instance(path, value.func, depth + 1) if isinstance(value, ast.Call) else None

    def _instance(self, path: str, func: ast.AST, depth: int) -> tuple[str, ast.ClassDef] | None:
        name = dotted(func)
        found = self._locate(path, name) if name and depth <= _MAX_DEPTH else None
        if found is None:
            return None
        module = self.modules[found[0]]
        if found[1] in module.classes:
            return found[0], module.classes[found[1]]
        function = module.functions.get(found[1])
        # `@lru_cache def get_settings(): return Settings()`
        for statement, _ in _statements(function.body if function else [], {}):
            if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
                if owner := self._instance(found[0], statement.value.func, depth + 1):
                    return owner
        return None

    def _class_attribute(self, path: str, cls: ast.ClassDef, attr: str, depth: int) -> str | None:
        if depth > _MAX_DEPTH:
            return None
        for statement in cls.body:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or statement.value is None:
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(target, ast.Name) and target.id == attr for target in targets):
                value = statement.value
                if isinstance(value, ast.Call) and last(value.func) == "Field":
                    value = value.args[0] if value.args else keyword_value(value, "default")
                return self._text(path, value, None, depth + 1)
        for base in cls.bases:
            owner = self._class_of(path, base, None, depth + 1)
            if owner and (text := self._class_attribute(owner[0], owner[1], attr, depth + 1)) is not None:
                return text
        return None

    def _prefix(self, path: str, local: dict[str, ast.AST] | None, expr: ast.AST | None, evidence: str) -> str:
        if expr is None:
            return ""
        text = self._text(path, expr, local)
        if text is None:
            self._issue(
                "DYNAMIC_ROUTER_PREFIX", "info",
                f"Router prefix {_shown(expr)} is not static text; its routes are registered without it.",
                [], evidence, "Declare the prefix as a string constant or a settings default, or confirm the runtime value.",
            )
            return ""
        return text

    def _dependencies(self, path: str, value: ast.AST | None) -> tuple[_Dep, ...]:
        """`dependencies=[Depends(a), Security(b)]` on a route, router, include or app."""
        if not isinstance(value, (ast.List, ast.Tuple)):
            return ()
        found = []
        for element in value.elts:
            if _is_marker(element, _DEPENDENCY_MARKERS):
                target = _dependency_target(element, None)
                if target is not None and (name := dotted(target)):
                    found.append(_Dep(name, path, element.lineno))
        return tuple(found)

    def _annotated_aliases(self, path: str) -> dict[str, ast.Call]:
        if path not in self._alias_cache:
            self._alias_cache[path] = annotated_aliases(self.state.python_trees[path])
        return self._alias_cache[path]

    def _param_dependencies(self, path: str, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[_Dep, ...]:
        """Depends/Security in a default, in `Annotated[T, Depends(x)]`, or behind a
        module-level `Alias = Annotated[T, Depends(x)]` declared here or imported."""
        found = []
        for arg, default in _parameters(fn):
            if arg.arg in ("self", "cls"):
                continue
            base, markers = _annotated(arg.annotation)
            module = path
            if _is_marker(default, _DEPENDENCY_MARKERS):
                marker, fallback = default, arg.annotation
            else:
                marker = next((m for m in markers if _is_marker(m, _DEPENDENCY_MARKERS)), None)
                fallback = base
            if marker is None and arg.annotation is not None and (name := dotted(arg.annotation)):
                fallback = None
                marker = self._annotated_aliases(path).get(name)
                if marker is None and (alias := self._locate(path, name)):
                    module = alias[0]
                    marker = self._annotated_aliases(alias[0]).get(alias[1])
            if marker is None:
                continue
            target = _dependency_target(marker, fallback)
            if target is not None and (dependency := dotted(target)):
                found.append(_Dep(dependency, module, marker.lineno))
        return tuple(found)

    def _link_dependencies(self, symbol: str, symbol_path: str, dependencies: tuple[_Dep, ...]) -> None:
        for dependency in dependencies:
            if (symbol, dependency) in self._linked:
                continue
            self._linked.add((symbol, dependency))
            evidence = f"{dependency.module}:{dependency.line}"
            if dependency.module == symbol_path:
                self.state.pending_calls.append(PendingCall(symbol, dependency.name, evidence, "python"))
                continue
            # Declared in another module (an imported alias, a router or include):
            # that module's imports say what the name is, not the handler's.
            found = self._locate(dependency.module, dependency.name)
            target = _symbol_id(*found) if found else ""
            if target in self.graph.nodes and target != symbol:
                self.graph.add_edge(Edge(
                    symbol, target, "CALLS", "high", evidence, origin="import_binding",
                    detail="FastAPI dependency declared in another module; import-bound syntax, dependency overrides unverified",
                ))
            else:
                self.state.pending_calls.append(PendingCall(symbol, dependency.name.rsplit(".", 1)[-1], evidence, "python"))

    # -- mounts ---------------------------------------------------------------------

    def _own(self, key: Key) -> tuple[str, tuple[_Dep, ...]]:
        if key not in self._own_cache:
            module, scope, call = self.owners[key]
            prefix = self._prefix(module, self._locals(module, scope), keyword_value(call, "prefix"),
                                  f"{module}:{call.lineno}")
            self._own_cache[key] = (prefix, self._dependencies(module, keyword_value(call, "dependencies")))
        return self._own_cache[key]

    def _mounts(self, key: Key, seen: tuple[Key, ...] = ()) -> list[tuple[str, tuple[_Dep, ...]]]:
        """Every (prefix, inherited dependencies) a router's routes are served under."""
        if not seen and key in self._mount_cache:
            return self._mount_cache[key]
        if key in seen or len(seen) >= 30:
            return []
        own_prefix, own_dependencies = self._own(key)
        links = self.parents.get(key)
        if not links:
            result = [(own_prefix, own_dependencies)]
        else:
            result = []
            for link in links:
                for parent_prefix, parent_dependencies in self._mounts(link.parent, (*seen, key)):
                    inherited = parent_dependencies if link.inherit else ()
                    item = (parent_prefix + link.prefix + own_prefix, (*inherited, *link.dependencies, *own_dependencies))
                    if item not in result:
                        result.append(item)
                if len(result) >= 100:
                    break
        if not seen:
            self._mount_cache[key] = result
        return result

    def _include(self, path: str, scope: str, call: ast.Call, env: dict[str, list[ast.expr]]) -> None:
        arg = call.args[0] if call.args else keyword_value(call, "router")
        if arg is None:
            return
        evidence = f"{path}:{call.lineno}"
        parent = self._router(path, scope, call.func.value)
        children = [self._router(path, scope, candidate) for candidate in _candidates(arg, env)]
        if parent is None or None in children:
            self._issue("UNRESOLVED_ROUTER_MOUNT", "warning", "A FastAPI router mount could not be resolved statically.",
                        [], evidence, "Review router factories, dynamic includes, and import aliases.")
            if parent is None:
                return
        prefix = self._prefix(path, self._locals(path, scope), keyword_value(call, "prefix"), evidence)
        dependencies = self._dependencies(path, keyword_value(call, "dependencies"))
        for child in children:
            if child is not None:
                self.parents[child].append(_Link(parent, prefix, dependencies, True))

    def _mount(self, path: str, scope: str, call: ast.Call) -> None:
        """`app.mount("/sub", subapp)`: a FastAPI sub-application serves its routes under
        the mount path. `app.mount("/static", StaticFiles(...))` is not a router."""
        child_expr = call.args[1] if len(call.args) > 1 else keyword_value(call, "app")
        path_expr = call.args[0] if call.args else keyword_value(call, "path")
        if child_expr is None or path_expr is None or not dotted(child_expr):
            return
        evidence = f"{path}:{call.lineno}"
        child = self._router(path, scope, child_expr)
        if child is None:
            # Only a name whose definition cannot be found could be an unseen app; one
            # defined as anything but a FastAPI()/APIRouter() construction is not.
            head = dotted(child_expr).split(".")[0]
            if head in self._bindings(path) and self._locate(path, dotted(child_expr)) is None:
                self._issue("UNRESOLVED_ROUTER_MOUNT", "warning", "A mounted application could not be resolved statically.",
                            [], evidence, "Review application factories and import aliases.")
            return
        parent = self._router(path, scope, call.func.value)
        if parent is None:
            self._issue("UNRESOLVED_ROUTER_MOUNT", "warning", "A FastAPI application mount could not be resolved statically.",
                        [], evidence, "Review application factories and import aliases.")
            return
        prefix = self._prefix(path, self._locals(path, scope), path_expr, evidence)
        self.parents[child].append(_Link(parent, prefix, (), False))

    # -- routes ---------------------------------------------------------------------

    def _methods(self, path: str, scope: str, call: ast.Call) -> list[str] | None:
        """`methods=["GET", "POST"]`; FastAPI's default is GET. None when not literal: a
        guessed method would either invent a mutation or hide one."""
        value = keyword_value(call, "methods")
        if value is None:
            return ["GET"]
        if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return None
        texts = [self._text(path, element, self._locals(path, scope)) for element in value.elts]
        if any(text is None for text in texts):
            return None
        return list(dict.fromkeys(text.upper() for text in texts if text.upper() in _HTTP_METHODS))

    def _handler(self, path: str, scope: str, expr: ast.AST) -> str | None:
        name = dotted(expr)
        if not name:
            return None
        if "." not in name:
            for enclosing in _chain(scope):
                symbol = _symbol_id(path, _scoped(enclosing, name))
                if symbol in self.function_nodes:
                    return symbol
        elif (symbol := _symbol_id(path, name)) in self.function_nodes:
            return symbol  # `Handlers.list` in the same module
        found = self._locate(path, name)
        symbol = _symbol_id(*found) if found else ""
        return symbol if symbol in self.function_nodes else None

    def _register(self, path: str, scope: str, call: ast.Call, symbol: str, methods: list[str] | None,
                  path_expr: ast.AST, distinctive: bool) -> None:
        fn_path, _, fn = self.function_nodes[symbol]
        evidence = f"{path}:{call.lineno}"
        assert isinstance(call.func, ast.Attribute)
        receiver = self._router(path, scope, call.func.value)
        declared = self._text(path, path_expr, self._locals(path, scope))
        if declared is None or methods is None:
            if receiver is not None or distinctive:
                self._issue("DYNAMIC_ROUTE_DECLARATION", "info",
                            f"Route path or methods for {self.graph.nodes[symbol].label} are not static text; the route is not registered.",
                            [symbol], evidence, "Declare the path and methods as literals or module constants.")
            return
        # Preserve bare router fixtures, but distinguish an inferred receiver.
        variants = self._mounts(receiver) if receiver else [("", ())]
        if not variants:
            self._issue("ROUTER_MOUNT_CYCLE", "warning", "Router mount cycle prevented route resolution.",
                        [symbol], evidence, "Remove cyclic router includes.")
            return
        route_dependencies = (*self._dependencies(path, keyword_value(call, "dependencies")),
                              *self._param_dependencies(fn_path, fn))
        for prefix, inherited in variants:
            dependencies = (*inherited, *route_dependencies)
            names = list(dict.fromkeys(d.name.rsplit(".", 1)[-1] for d in dependencies))
            route = normalise_route(with_api_prefix(self.state, prefix + declared))
            for method in methods:
                endpoint = _endpoint_id(method, route)
                self.graph.add_node(Node(endpoint, "endpoint", f"{method} {route}", path=path, line=call.lineno,
                                         language="python", metadata={"method": method, "route": route,
                                                                     "framework": "fastapi", "dependencies": names}))
                self.graph.add_edge(Edge(endpoint, symbol, "HANDLES_API", "exact" if receiver else "probable",
                                         evidence, origin="python_ast",
                                         detail="Static router mount; runtime registration not executed"))
                self._model_edges(endpoint, path, call, fn_path, fn)
            self._link_dependencies(symbol, fn_path, dependencies)

    def _model_edges(self, endpoint: str, path: str, call: ast.Call, fn_path: str,
                     fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for arg, default in _parameters(fn):
            if arg.arg in ("self", "cls") or arg.annotation is None or _is_marker(default, _NOT_BODY_MARKERS):
                continue
            if any(_is_marker(marker, _NOT_BODY_MARKERS) for marker in _annotated(arg.annotation)[1]):
                continue
            for name in _type_names(arg.annotation):
                self._model_edge(endpoint, fn_path, name, "ACCEPTS_MODEL", f"{fn_path}:{arg.lineno}",
                                 "Request parameter annotation; FastAPI validation not executed")
        response = keyword_value(call, "response_model")
        for module, expr, line in ((path, response, call.lineno), (fn_path, fn.returns, fn.lineno)):
            for name in _type_names(expr) if expr is not None else ():
                self._model_edge(endpoint, module, name, "RETURNS_MODEL", f"{module}:{line}",
                                 "response_model or return annotation; serialisation not executed")

    def _model_edge(self, endpoint: str, module: str, name: str, kind: str, evidence: str, detail: str) -> None:
        if "." not in name and module in self.modules and name in self.modules[module].classes:
            found, resolution = (module, name), "exact"
        else:
            found, resolution = self._locate(module, name), "high"
        cls = self.modules[found[0]].classes.get(found[1]) if found else None
        if cls is None or any(last(base) in _ENUM_BASES for base in cls.bases):
            return
        target = _symbol_id(*found)
        if target in self.graph.nodes:
            self.graph.add_edge(Edge(endpoint, target, kind, resolution, evidence, origin="python_ast", detail=detail))

    # -- pipeline -------------------------------------------------------------------

    def run(self) -> None:
        scopes: list[tuple[str, str, list[ast.stmt]]] = []
        for path, tree in self.state.python_trees.items():
            scopes.append((path, "", tree.body))
            for fn, qualname in functions(tree):
                scopes.append((path, qualname, fn.body))
                symbol = _symbol_id(path, qualname)
                if symbol in self.graph.nodes:  # the same qualified names PythonVisitor generates
                    self.function_nodes[symbol] = (path, qualname, fn)

        factory_calls: list[tuple[Key, ast.Call]] = []
        for path, scope, body in scopes:
            if scope:
                self.locals[(path, scope)] = _assignments(_statements(body, {}))
            for statement, _ in _statements(body, {}):
                if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or not isinstance(statement.value, ast.Call):
                    continue
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    key = (path, _scoped(scope, target.id))
                    if last(statement.value.func) in self.constructors:
                        self.owners[key] = (path, scope, statement.value)
                    else:
                        factory_calls.append((key, statement.value))
        for key, call in factory_calls:
            self._factory(key, call)

        api_routes: list[tuple[str, str, ast.Call]] = []
        for path, scope, body in scopes:
            local = self.locals.get((path, scope), {})
            sequences = {**self.modules[path].sequences, **_sequences(local)}
            for statement, env in _statements(body, sequences):
                for call in _calls(statement):
                    if not isinstance(call.func, ast.Attribute):
                        continue
                    if call.func.attr == "include_router":
                        self._include(path, scope, call, env)
                    elif call.func.attr == "mount":
                        self._mount(path, scope, call)
                    elif call.func.attr in {"add_api_route", "add_api_websocket_route"}:
                        api_routes.append((path, scope, call))

        for symbol, (path, qualname, fn) in self.function_nodes.items():
            scope = qualname.rpartition(".")[0]  # where the decorator is evaluated
            for decorator in fn.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and dotted(decorator.func.value)):
                    continue
                attr = decorator.func.attr
                if attr.upper() in _HTTP_METHODS:
                    methods, distinctive = [attr.upper()], False
                elif attr == "api_route":
                    methods, distinctive = self._methods(path, scope, decorator), True
                elif attr == "websocket":
                    methods, distinctive = ["WEBSOCKET"], True
                else:
                    continue
                path_expr = decorator.args[0] if decorator.args else keyword_value(decorator, "path")
                if path_expr is not None:
                    self._register(path, scope, decorator, symbol, methods, path_expr, distinctive)

        for path, scope, call in api_routes:
            endpoint_expr = call.args[1] if len(call.args) > 1 else keyword_value(call, "endpoint")
            path_expr = call.args[0] if call.args else keyword_value(call, "path")
            symbol = self._handler(path, scope, endpoint_expr) if endpoint_expr is not None else None
            if symbol is None or path_expr is None:
                self._issue("DYNAMIC_ROUTE_DECLARATION", "info",
                            "An add_api_route handler or path could not be resolved statically; the route is not registered.",
                            [], f"{path}:{call.lineno}", "Pass a module-level function and a literal path.")
                continue
            methods = ["WEBSOCKET"] if call.func.attr == "add_api_websocket_route" else self._methods(path, scope, call)
            self._register(path, scope, call, symbol, methods, path_expr, True)

        # Sub-dependencies: `def get_current_user(session: SessionDep)` depends on get_db
        # the same way a handler does, and impact must cross that chain.
        for symbol, (path, _, fn) in self.function_nodes.items():
            if dependencies := self._param_dependencies(path, fn):
                self._link_dependencies(symbol, path, dependencies)

    def _factory(self, key: Key, call: ast.Call) -> None:
        """`app = create_app()`: the app the factory returns, whether it builds and
        returns a local (`app = FastAPI(); app.include_router(...); return app`) or
        returns the construction directly."""
        name = dotted(call.func)
        found = self._locate(key[0], name) if name else None
        function = self.modules[found[0]].functions.get(found[1]) if found else None
        if function is None:
            return
        for statement, _ in _statements(function.body, {}):
            if not isinstance(statement, ast.Return) or statement.value is None:
                continue
            value = statement.value
            if isinstance(value, ast.Call) and last(value.func) in self.constructors:
                self.owners[key] = (found[0], found[1], value)
                return
            if isinstance(value, ast.Name) and (local := (found[0], _scoped(found[1], value.id))) in self.owners:
                self.aliases[key] = local
                return


def add_routes(state: ScanState) -> None:
    """Post-walk pass: add FastAPI endpoints, HANDLES_API and model edges, and dependency links.

    Runs over every parsed Python module at once, because routers are mounted across modules."""
    _FastAPI(state).run()
