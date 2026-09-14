"""Shared, read-only Python AST helpers: parse once, find routes and their dependencies."""
from __future__ import annotations

import warnings
import ast
import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, TypeVar

_T = TypeVar("_T")

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


def _parse_source(path: str, text: str) -> ast.Module | None:
    try:
        with warnings.catch_warnings():  # target code's own SyntaxWarnings are not ours to print
            warnings.simplefilter("ignore")
            tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return None
    # Kept for `may_mention`, set before the tree is shared. Only ASCII source: a non-ASCII
    # identifier is NFKC-normalised by the parser, so its node name need not appear as text.
    tree._repolens_source = text if text.isascii() else None  # type: ignore[attr-defined]
    return tree


def may_mention(tree: ast.AST, *words: str) -> bool:
    """False only when the module's source text contains none of `words`, so no name or
    attribute node in it can be one of them. A prefilter for a whole-tree `ast.walk`
    looking for a specific name; True whenever the source is unknown."""
    source = getattr(tree, "_repolens_source", None)
    return source is None or any(word in source for word in words)


_parse_text = lru_cache(maxsize=256)(_parse_source)


def _read(path: str, max_bytes: int) -> str | None:
    from ..impact.source import read_source
    source = Path(path)
    return read_source(source.parent, source, max_bytes).text


def parse(path: str, max_bytes: int = 2_000_000) -> ast.Module | None:
    """A parse outside any run: a small content-keyed LRU, so a long-lived API process
    never reuses yesterday's AST for a path changed in place, and never holds thousands
    of them. The checks use their run's `ParseCache` (`ScanSettings.parse_cache`)."""
    text = _read(path, max_bytes)
    return _parse_text(path, text) if text is not None else None


class ParseCache:
    """The parsed modules of ONE run of the checks, shared by every check in it.

    Each check reads every Python file several times: `route_exposure` and `MountIndex`
    parse the tree before the check's own loop does, and security and performance each do
    all three. A process-wide LRU either holds thousands of ASTs after the run ends (it
    was 8192) or misses on nearly every parse of a large tree (at 256 the checks ran
    30-40% slower on a 2,274-file repository). So the cache belongs to the run: it hangs
    off the `ScanSettings` the run was configured with, which `dataclasses.replace` shares
    and which is garbage when the run is.

    Entries are keyed on the path and the SHA-256 of the bounded read, so a file edited
    during a run is re-parsed rather than answered from its old tree. One entry per path:
    capacity grows to the number of distinct files the run declares (`reserve`), and past
    it the least recently used entry goes, so memory is bounded by the run's own inventory
    (which `MountIndex` held in full at once anyway). A file that does not parse, or is too
    deep for the parser (RecursionError), is cached as None like any other result; a
    RecursionError while a CHECK walks a tree is still caught per file by that check.
    Trees are shared, so a check must never mutate one.
    """

    def __init__(self, capacity: int = 256) -> None:
        self.capacity = capacity
        self._entries: OrderedDict[tuple[str, int], tuple[bytes, ast.Module | None]] = OrderedDict()
        self._declared: set[str] = set()
        self._derived: dict[str, tuple[Any, Any]] = {}
        self.hits = 0
        self.misses = 0

    def derived(self, name: str, key: Any, compute: Callable[[], _T]) -> _T:
        """The last `compute()` stored under `name`, while `key` still equals the key it was
        computed for; otherwise computed again. One value per name, so this holds only the
        latest index of each kind (route exposure, mount index) for the run.

        The key must name every input: `run_inputs(s, trees)`. Trees compare by identity,
        so a file edited since (a new tree) recomputes, and the key keeps them alive."""
        held = self._derived.get(name)
        if held is not None and held[0] == key:
            return held[1]
        value = compute()
        self._derived[name] = (key, value)
        return value

    def __len__(self) -> int:
        return len(self._entries)

    def reserve(self, paths: Iterable[Path | str]) -> None:
        """Room for every file in `paths` (with those declared before) at once."""
        self._declared.update(str(p) for p in paths)
        self.capacity = max(self.capacity, len(self._declared))

    def parse(self, path: Path | str, max_bytes: int) -> ast.Module | None:
        path = str(path)
        text = _read(path, max_bytes)
        if text is None:
            return None
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
        key = (path, max_bytes)
        cached = self._entries.get(key)
        if cached is not None and cached[0] == digest:
            self._entries.move_to_end(key)
            self.hits += 1
            return cached[1]
        self.misses += 1
        tree = _parse_source(path, text)
        self._entries[key] = (digest, tree)
        self._entries.move_to_end(key)
        while len(self._entries) > self.capacity:
            self._entries.popitem(last=False)
        return tree


def python_files(s: ScanSettings) -> list[Path]:
    """The Python files the checks read: the admitted inventory when the analysis service
    set one, else every `.py` under the configured roots except untracked gitignored ones."""
    if s.admitted_python_files is not None:
        return [s.root / path for path in s.admitted_python_files]
    return not_gitignored(s, iter_files(s.root, s.python_roots, [".py"], s.skip_parts))


def not_gitignored(s: ScanSettings, paths: list[Path]) -> list[Path]:
    """`paths` without the untracked files git ignores (with `respect_gitignore`). The git
    listing is taken once per parse cache, which lives for one run: settings reused after the
    working tree changes keep the old listing. When git cannot list them, every path is kept: reading
    a backup is noise, skipping source would be a silent hole."""
    if not s.respect_gitignore:
        return paths
    from ..core.git import under_ignored, untracked_ignored
    listed = s.parse_cache.derived("gitignored", s.root, lambda: untracked_ignored(s.root)[0])
    if not listed:
        return paths
    return [path for path in paths if not under_ignored(s.rel(path), listed)]


def run_inputs(s: ScanSettings, trees: dict[str, ast.Module]) -> tuple:
    """Everything a whole-tree index (`wiring.route_exposure`, `mounts.MountIndex`) is built
    from: the settings those read and the parsed tree of each file, by identity."""
    return (s.root, s.python_roots, s.skip_parts, s.internal_prefixes, s.entrypoints,
            s.app_constructors, s.deployment_detection, s.respect_gitignore, s.max_file_bytes, s.admitted_python_files,
            s.security.auth_scheme_classes, tuple(trees.items()))


def parsed_files(s: ScanSettings, paths: list[Path] | None = None) -> Iterator[tuple[Path, ast.Module]]:
    """(path, tree) for every file in `paths` (default: `python_files(s)`) that parses,
    from the run's shared cache."""
    files = python_files(s) if paths is None else paths
    s.parse_cache.reserve(files)
    for path in files:
        tree = s.parse_cache.parse(path, s.max_file_bytes)
        if tree is not None:
            yield path, tree


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


def dependency_name(call: ast.Call) -> str | None:
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


def _alias_statement(node: ast.AST) -> tuple[str, ast.AST] | None:
    """(name, value) for `N = V`, `N: TypeAlias = V` and Python 3.12's `type N = V`."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    if type(node).__name__ == "TypeAlias" and isinstance(getattr(node, "name", None), ast.Name):
        return node.name.id, node.value
    return None


def annotated_aliases(tree: ast.Module) -> dict[str, ast.Call]:
    """Module-level `CurrentUser = Annotated[User, Depends(get_current_user)]` -> the
    Depends/Security call each alias carries.

    FastAPI's own docs, and its full-stack template (`SessionDep`, `CurrentUser`), declare
    dependencies this way. A parameter annotated with the alias depends on exactly what
    the alias names, and reading only an inline `Annotated[...]` reported every such
    route as declaring no authentication."""
    found: dict[str, ast.Call] = {}
    for node in module_level(tree):
        pair = _alias_statement(node)
        if pair and (marker := _annotated_marker(pair[1], ("Depends", "Security"))) is not None:
            found[pair[0]] = marker
    return found


def security_schemes(tree: ast.Module, classes: frozenset[str]) -> set[str]:
    """Module-level names holding a FastAPI security scheme (`oauth2_scheme =
    OAuth2PasswordBearer(tokenUrl="token")`), and module classes deriving from one.

    Depending on a scheme instance authenticates: it raises 401/403 when the credential
    is missing. Not with `auto_error=False`, which hands the handler None instead, so
    that instance does not count. A class is counted by its base's NAME only."""
    found: set[str] = set()
    for node in module_level(tree):
        if isinstance(node, ast.ClassDef) and any(last(b) in classes for b in node.bases):
            found.add(node.name)
            continue
        pair = _alias_statement(node)
        value = pair[1] if pair else None
        if not (isinstance(value, ast.Call) and last(value.func) in classes):
            continue
        auto_error = keyword_value(value, "auto_error")
        if not (isinstance(auto_error, ast.Constant) and auto_error.value is False):
            found.add(pair[0])
    return found


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
                 if _is_marker(elt, ("Depends", "Security")) and (name := dependency_name(elt)))


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


def _text(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _methods(call: ast.Call) -> list[str] | None:
    """`methods=["GET", "POST"]` on api_route/add_api_route, upper-cased and limited to
    HTTP_VERBS; FastAPI's default is GET. None when the list is not literal: a guessed
    method would either invent a mutation or hide one."""
    value = keyword_value(call, "methods")
    if value is None:
        return ["GET"]
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return None
    texts = [_text(e) for e in value.elts]
    if any(t is None for t in texts):
        return None
    return list(dict.fromkeys(t.upper() for t in texts if t.lower() in HTTP_VERBS))


def _route_path(call: ast.Call) -> str | None:
    return _text(call.args[0] if call.args else keyword_value(call, "path"))


def _endpoint_calls(tree: ast.AST) -> Iterator[tuple[ast.Call, str]]:
    """`router.add_api_route("/p", handler, methods=[...])` anywhere in the module, with
    the NAME of the handler it registers (positional or `endpoint=`)."""
    if not may_mention(tree, "add_api_route"):
        return
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_api_route"):
            continue
        endpoint = node.args[1] if len(node.args) > 1 else keyword_value(node, "endpoint")
        if isinstance(endpoint, ast.Name):
            yield node, endpoint.id


def routes(tree: ast.AST, mounts: dict[str, Mount] | None = None,
           aliases: dict[str, ast.Call] | None = None) -> list[Route]:
    """Every route handler: decorated (`@router.post`, `@router.api_route(methods=...)`,
    `@app.websocket`), or registered with `router.add_api_route(path, handler)`.

    `mounts` (router variable -> Mount) adds what each route inherits from its router:
    without it, router-level auth reads as none. `aliases` (annotation name -> the
    Depends call it stands for) adds dependency aliases imported from other modules;
    the module's own are always read. A path or method list that is not a literal is
    skipped rather than guessed."""
    # The module's own alias wins over an imported name it shadows: it is bound later.
    known = {**(aliases or {}), **(annotated_aliases(tree) if isinstance(tree, ast.Module) else {})}
    found: list[Route] = []
    by_name: dict[str, tuple[FunctionNode, str]] = {}
    for fn, qualname in functions(tree):
        by_name.setdefault(qualname, (fn, qualname))
        for dec in fn.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            kind = dec.func.attr.lower()
            if kind in HTTP_VERBS:
                methods: list[str] | None = [kind.upper()]
            elif dec.func.attr == "api_route":
                methods = _methods(dec)
            elif dec.func.attr == "websocket":
                methods = ["WEBSOCKET"]
            else:
                continue
            declared = _route_path(dec)
            if declared is None or not methods:
                continue
            for method in methods:
                found.append(_route(fn, qualname, method, declared, dec, mounts, known))
    for call, name in _endpoint_calls(tree):
        declared, methods = _route_path(call), _methods(call)
        if name in by_name and declared is not None and methods:
            fn, qualname = by_name[name]
            found.extend(_route(fn, qualname, m, declared, call, mounts, known) for m in methods)
    return found


def _route(fn: FunctionNode, qualname: str, method: str, declared: str, call: ast.Call,
           mounts: dict[str, Mount] | None, aliases: dict[str, ast.Call]) -> Route:
    """One Route for `fn`, registered by `call` (a decorator or add_api_route) on the
    router the call is made on."""
    receiver = call.func.value.id if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) else ""
    mount = (mounts or {}).get(receiver) or Mount()
    route = Route(node=fn, qualname=qualname, method=method,
                  path=mount.prefix + declared, declared_path=declared)
    route.dependencies.extend(Dependency(None, name) for name in mount.dependencies)
    route.dependencies.extend(Dependency(None, name)
                              for name in dependency_names(keyword_value(call, "dependencies")))
    for arg, default in _parameters(fn):
        if arg.arg in ("self", "cls"):
            continue
        marker = default if _is_marker(default, ("Depends", "Security")) else \
            _annotated_marker(arg.annotation, ("Depends", "Security"))
        if marker is None and arg.annotation is not None:
            marker = aliases.get(dotted(arg.annotation))
        if marker is not None:
            if name := dependency_name(marker):
                route.dependencies.append(Dependency(arg.arg, name))
        elif _is_marker(default, ("Header",)) or _annotated_marker(arg.annotation, ("Header",)):
            route.header_params.append(arg.arg)
        else:
            route.request_params.append(arg.arg)
    return route
