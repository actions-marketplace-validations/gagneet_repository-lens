"""Shared, read-only Python AST helpers: parse once, find routes and their dependencies."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from ..core.files import iter_files
from .settings import ScanSettings

HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete"})
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PATH_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}")

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def dotted(node: ast.AST) -> str:
    """`a.b.c` for an attribute chain rooted at a name; "" for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def last(node: ast.AST) -> str:
    """The final name of a callee: `db.units.find_one` -> `find_one`, `f` -> `f`."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


@lru_cache(maxsize=8192)
def parse(path: str) -> ast.Module | None:
    try:
        return ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, OSError):
        return None


def python_files(s: ScanSettings) -> list[Path]:
    return iter_files(s.root, s.python_roots, [".py"], s.skip_parts)


def functions(tree: ast.AST) -> Iterator[tuple[FunctionNode, str]]:
    """Every function and method, with a dotted qualname."""
    def visit(node: ast.AST, prefix: str) -> Iterator[tuple[FunctionNode, str]]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                yield from visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child, f"{prefix}{child.name}"
                yield from visit(child, f"{prefix}{child.name}.")
    yield from visit(tree, "")


def walk_body(fn: FunctionNode, *, lambdas: bool = False) -> Iterator[ast.AST]:
    """Every node in `fn`'s body, NOT descending into nested functions or classes.

    A nested sync `def` inside an async handler is exactly how blocking work is handed to
    a worker thread, so descending into it would flag the remedy as the defect.
    `lambdas=True` descends into lambdas, for questions about what the handler READS:
    `postgres_handler=lambda: _reject(payment_id, current_user)` still hands the caller's
    identity on, and missing it reported a guarded route as an unguarded one.
    """
    skip = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef) + (() if lambdas else (ast.Lambda,))
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, skip):
                continue
            stack.append(child)


def names_read(fn: FunctionNode) -> set[str]:
    return {n.id for n in walk_body(fn, lambdas=True) if isinstance(n, ast.Name)}


def literal_text(node: ast.AST, trusted: set[str], constant_name: re.Pattern[str],
                 shadowed: frozenset[str] | set[str] = frozenset()) -> bool:
    """Whether `node` evaluates to text assembled only from literals and trusted names.

    A name spelled like a module constant is trusted only if nothing in the function
    binds it (`shadowed`): `def rows(ORDER: str)` makes `ORDER` caller input.
    """
    def ok(n: ast.AST) -> bool:
        return literal_text(n, trusted, constant_name, shadowed)

    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in trusted or (node.id not in shadowed and bool(constant_name.search(node.id)))
    if isinstance(node, ast.Attribute):
        return constant_attribute(node, constant_name, shadowed)
    if isinstance(node, ast.JoinedStr):
        return all(ok(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return ok(node.value)
    if isinstance(node, ast.BinOp):
        return ok(node.left) and ok(node.right)
    if isinstance(node, ast.IfExp):
        return ok(node.body) and ok(node.orelse)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(ok(e) for e in node.elts)
    if isinstance(node, ast.Subscript):
        # `COLUMNS[key]`: a lookup in a module constant yields one of its own values, or
        # raises. Mapping a caller's key to a fixed identifier is the allow-list remedy.
        return _constant_ref(node.value, constant_name, shadowed)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get" and node.args and not node.keywords
            and _constant_ref(node.func.value, constant_name, shadowed)):
        return all(ok(a) for a in node.args[1:])  # the default must be literal too
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and len(node.args) == 1 and not node.keywords):
        return ok(node.func.value) and ok(node.args[0])
    return False


def _constant_ref(node: ast.AST, constant_name: re.Pattern[str],
                  shadowed: frozenset[str] | set[str]) -> bool:
    """A module constant: `ALLOWED`, or `settings.ALLOWED`, not rebound in the function."""
    if isinstance(node, ast.Name):
        return node.id not in shadowed and bool(constant_name.search(node.id))
    if isinstance(node, ast.Attribute):
        return constant_attribute(node, constant_name, shadowed)
    return False


#: Attributes that hold request data in the common frameworks. However one is spelled,
#: it is caller input: Django's `request.GET` matches a constant-name pattern.
_REQUEST_DATA = frozenset({"GET", "POST", "FILES", "COOKIES", "META", "REQUEST", "headers",
                           "args", "form", "query_params", "path_params", "cookies"})


def constant_attribute(node: ast.Attribute, constant_name: re.Pattern[str],
                       shadowed: frozenset[str] | set[str]) -> bool:
    """`settings.ALLOWED` or `self.ALLOWED`: an attribute spelled like a constant, reached
    from a module or directly from the instance.

    The spelling alone is not enough. `request.GET['sort']` reads as a constant by name
    and is a query-string value. So the chain must start at a name the function does
    not bind (a module, not a parameter or a local), or be exactly `self.X` / `cls.X`.
    No attribute on the way may be a request-data one."""
    if not constant_name.search(node.attr):
        return False
    chain: list[str] = []
    value: ast.AST = node
    while isinstance(value, ast.Attribute):
        chain.append(value.attr)
        value = value.value
    if not isinstance(value, ast.Name) or any(a in _REQUEST_DATA for a in chain):
        return False
    if value.id in ("self", "cls"):
        return len(chain) == 1
    return value.id not in shadowed


def literal_locals(fn: FunctionNode, constant_name: re.Pattern[str]) -> set[str]:
    """Local names in `fn` that only ever hold text built from literals.

    `where.append("status = :status")` then `" AND ".join(where)` is the ordinary way to
    assemble a dynamic WHERE clause with every VALUE bound. Interpolating the result is
    safe, and a scanner that cannot see that reports injection on every such route — four
    of four of the first run's route-level SQL findings were exactly this.

    Greatest fixed point: trust every local that is plainly assigned, then withdraw trust
    from any name with a write that is not literal text given the names still trusted.
    Parameters, loop variables over anything but a literal, unpacked targets, `with` and
    `match` captures are never trusted.

    A list or dict can also change WITHOUT a visible write to its name, so a mutable
    container loses trust the moment it escapes: aliased (`w = where; w.append(x)`) or
    handed to a call that could mutate it (`_add_filters(where, status)`). Only the
    consumers that read without mutating (`join`, `len`, ...) keep it trusted.
    """
    args = fn.args
    tainted = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    tainted |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    writes: dict[str, list[ast.AST]] = {}
    assigned: set[str] = set()
    containers = _mutable_containers(fn)

    def taint(target: ast.AST) -> None:
        tainted.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))

    def write(name: str, value: ast.AST, *, initial: bool) -> None:
        writes.setdefault(name, []).append(value)
        if initial:
            assigned.add(name)

    def escapes(value: ast.AST) -> None:
        for n in (value.elts if isinstance(value, (ast.Tuple, ast.List)) else [value]):
            n = n.value if isinstance(n, ast.Starred) else n
            if isinstance(n, ast.Name) and n.id in containers:
                tainted.add(n.id)

    for node in walk_body(fn):
        if isinstance(node, ast.Call) and last(node.func) not in _READ_ONLY_CONSUMERS:
            for value in [*node.args, *(k.value for k in node.keywords)]:
                escapes(value)
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            tainted.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            tainted.add(node.rest)
        elif isinstance(node, ast.Assign):
            escapes(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    write(target.id, node.value, initial=True)
                else:
                    taint(target)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                write(node.target.id, node.value, initial=True)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                write(node.target.id, node.value, initial=False)
            else:
                taint(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name) and isinstance(node.iter, (ast.List, ast.Tuple, ast.Set)):
                for elt in node.iter.elts:
                    write(node.target.id, elt, initial=True)
            else:
                taint(node.target)
        elif isinstance(node, ast.comprehension):
            taint(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    taint(item.optional_vars)
        elif isinstance(node, ast.NamedExpr):
            taint(node.target)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            tainted.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            tainted.add(node.name)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name)
              and node.func.attr in ("append", "extend", "insert") and node.args):
            write(node.func.value.id, node.args[-1], initial=False)

    bound = bound_names(fn)
    trusted = {name for name in writes if name in assigned and name not in tainted}
    changed = True
    while changed:
        changed = False
        for name in sorted(trusted):
            if not all(literal_text(v, trusted, constant_name, bound - trusted) for v in writes[name]):
                trusted.discard(name)
                changed = True
    return trusted


#: Calls that read a container without being able to change it.
_READ_ONLY_CONSUMERS = frozenset({"join", "len", "bool", "any", "all", "enumerate", "zip",
                                  "sorted", "reversed", "tuple", "list", "set", "frozenset",
                                  "min", "max", "sum", "str", "repr"})
_CONTAINER_VALUES = (ast.List, ast.Set, ast.Dict, ast.ListComp, ast.SetComp, ast.DictComp)


def _mutable_containers(fn: FunctionNode) -> set[str]:
    found: set[str] = set()
    for node in walk_body(fn):
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        is_container = isinstance(value, _CONTAINER_VALUES) or (
            isinstance(value, ast.Call) and last(value.func) in ("list", "set", "dict"))
        if not is_container:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        found.update(t.id for t in targets if isinstance(t, ast.Name))
    return found


def bound_names(fn: FunctionNode) -> set[str]:
    """Every name `fn` binds: parameters, assignment targets, loop, `with`, `except` and
    `match` captures. A name here is not a module constant, however it is spelled."""
    args = fn.args
    names = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    names |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    for node in walk_body(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def raises_auth_error(fn: FunctionNode) -> bool:
    """Whether the body raises a 401/403 itself — an in-body authorisation decision."""
    for node in walk_body(fn):
        if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
            continue
        values = [*node.exc.args, *(k.value for k in node.exc.keywords)]
        for value in values:
            if isinstance(value, ast.Constant) and value.value in (401, 403):
                return True
            if isinstance(value, ast.Attribute) and re.search(r"HTTP_40[13]_", value.attr):
                return True
    return False


@dataclass
class Dependency:
    param: str | None     # None for a decorator-level `dependencies=[...]`
    name: str             # the dependency callable: Depends(require_feature("x")) -> require_feature


@dataclass
class Route:
    node: FunctionNode
    qualname: str
    method: str
    path: str
    dependencies: list[Dependency] = field(default_factory=list)
    # Parameters the CALLER supplies (no Depends/Header default): path, query, body.
    request_params: list[str] = field(default_factory=list)
    header_params: list[str] = field(default_factory=list)
    # The path as the decorator spells it. `path` adds every prefix the route inherits
    # from its router and the routers that mount it.
    declared_path: str = ""

    @property
    def path_params(self) -> list[str]:
        return _PATH_PARAM.findall(self.path)

    @property
    def line(self) -> int:
        return self.node.lineno


def _is_marker(node: ast.AST | None, names: tuple[str, ...]) -> bool:
    return isinstance(node, ast.Call) and last(node.func) in names


def _dependency_name(call: ast.Call) -> str | None:
    target = call.args[0] if call.args else next(
        (k.value for k in call.keywords if k.arg == "dependency"), None)
    if isinstance(target, ast.Call):
        target = target.func
    name = last(target) if target is not None else ""
    return name or None


def _annotated_marker(annotation: ast.AST | None, names: tuple[str, ...]) -> ast.Call | None:
    """`Annotated[T, Depends(x)]` -> the Depends call."""
    if not isinstance(annotation, ast.Subscript) or last(annotation.value) != "Annotated":
        return None
    elts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else []
    return next((e for e in elts[1:] if _is_marker(e, names)), None)


def _parameters(fn: FunctionNode) -> list[tuple[ast.arg, ast.AST | None]]:
    args = fn.args
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    return [*zip(positional, defaults), *zip(args.kwonlyargs, args.kw_defaults)]


@dataclass(frozen=True)
class Mount:
    """What a router object gives every route declared on it: a path prefix and
    router-level dependencies, from its own `APIRouter(...)` and every `include_router`
    that mounts it. Resolved across files by `scan.mounts.MountIndex`."""
    prefix: str = ""
    dependencies: tuple[str, ...] = ()


def keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def router_prefix(call: ast.Call) -> str:
    """`prefix="/x"` on an APIRouter(...) or include_router(...) call; "" otherwise."""
    value = keyword_value(call, "prefix")
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else ""


def dependency_names(value: ast.AST | None) -> tuple[str, ...]:
    """`dependencies=[Depends(a), Security(b)]` -> ("a", "b")."""
    if not isinstance(value, (ast.List, ast.Tuple)):
        return ()
    return tuple(name for elt in value.elts
                 if _is_marker(elt, ("Depends", "Security")) and (name := _dependency_name(elt)))


def module_level(tree: ast.Module) -> Iterator[ast.stmt]:
    """Module statements, including those under if/try/with/for, never inside a def or
    class: `try: from routers.x import router` is how optional routers are wired."""
    stack = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For)) \
                or type(node).__name__ == "TryStar":
            children = [*getattr(node, "body", []), *getattr(node, "orelse", []),
                        *getattr(node, "finalbody", [])]
            for handler in getattr(node, "handlers", []):
                children.extend(handler.body)
            stack.extend(reversed(children))


def declared_routers(tree: ast.Module, constructors: frozenset[str]) -> dict[str, Mount]:
    """Module-level `name = APIRouter(prefix=..., dependencies=[...])`, and app objects
    (`app = FastAPI(dependencies=[...])`), with what each declares for itself."""
    found: dict[str, Mount] = {}
    for node in module_level(tree):
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(value, ast.Call) or last(value.func) not in constructors:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                found[target.id] = Mount(router_prefix(value),
                                         dependency_names(keyword_value(value, "dependencies")))
    return found


def routes(tree: ast.AST, mounts: dict[str, Mount] | None = None) -> list[Route]:
    """Every decorated route handler. `mounts` (router variable -> Mount) adds what each
    route inherits from its router: without it, router-level auth reads as none."""
    found: list[Route] = []
    for fn, qualname in functions(tree):
        for dec in fn.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            verb = dec.func.attr.lower()
            if verb not in HTTP_VERBS:
                continue
            if not (dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)):
                continue
            declared = dec.args[0].value
            receiver = dec.func.value.id if isinstance(dec.func.value, ast.Name) else ""
            mount = (mounts or {}).get(receiver) or Mount()
            route = Route(node=fn, qualname=qualname, method=verb.upper(),
                          path=mount.prefix + declared, declared_path=declared)
            route.dependencies.extend(Dependency(None, name) for name in mount.dependencies)
            for kw in dec.keywords:
                if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if _is_marker(elt, ("Depends", "Security")) and (name := _dependency_name(elt)):
                            route.dependencies.append(Dependency(None, name))
            for arg, default in _parameters(fn):
                if arg.arg in ("self", "cls"):
                    continue
                marker = default if _is_marker(default, ("Depends", "Security")) else \
                    _annotated_marker(arg.annotation, ("Depends", "Security"))
                if marker is not None:
                    if name := _dependency_name(marker):
                        route.dependencies.append(Dependency(arg.arg, name))
                elif _is_marker(default, ("Header",)) or _annotated_marker(arg.annotation, ("Header",)):
                    route.header_params.append(arg.arg)
                else:
                    route.request_params.append(arg.arg)
            found.append(route)
    return found
