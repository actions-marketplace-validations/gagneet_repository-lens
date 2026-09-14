"""Where each FastAPI router is mounted: the prefix and router-level dependencies every
route on it inherits.

A route's decorator is not the whole story. `APIRouter(prefix="/x",
dependencies=[Depends(auth)])` and `parent.include_router(child, prefix="/y",
dependencies=[...])` both apply to every route on the router. Reading only the decorator
reported router-level authentication as "no authentication", and printed every path
without its prefix.

The same import resolution answers two more questions about a route file: which
dependency aliases (`CurrentUser = Annotated[User, Depends(get_current_user)]`) and which
security scheme instances (`oauth2_scheme = OAuth2PasswordBearer(...)`) its names refer
to, when they are defined in another module (`dependency_aliases`, `schemes`).

Resolution follows `include_router` calls across files, through imports
(`from routers.x import router as x_router`, `from routers import x` + `x.router`), and
up the chain of parents: `app.include_router(api)` where `api = APIRouter(prefix="/api")`.
A name imported twice resolves to the import in effect at the `include_router` line. A
loop over a literal list or tuple, or over a module-level one, is expanded:
`for r in (a, b): app.include_router(r)` mounts both.

Limits:
  * A router passed through a function, built by a factory, or mounted under a name
    the scanner cannot resolve: that mount is not counted, and the error goes either
    way. If it was the router's only mount, the router keeps only what it declares
    itself and reads as LESS protected than it is. If the router is also mounted
    somewhere the scanner can read, with dependencies, its routes read as protected on
    the unread path too.
  * A router mounted in more than one place takes the prefix of the mount that sorts
    first (by the including file, then the parent variable), and only the dependencies
    EVERY mount applies: a route is authenticated only if each path to it is.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass

from .python_ast import (
    Mount,
    annotated_aliases,
    declared_routers,
    dependency_name,
    dependency_names,
    keyword_value,
    may_mention,
    parsed_files,
    router_prefix,
    run_inputs,
    security_schemes,
)
from .settings import ScanSettings
from .wiring import ModuleMap

_ROUTER_CONSTRUCTORS = frozenset({"APIRouter"})

Key = tuple[str, str]  # (repo-relative file, router variable)
Target = tuple[str, str | None]  # (module, attribute): what an imported name refers to
_LAST_LINE = 1 << 30  # a binding looked up for the whole file: the last import wins
_REEXPORT_DEPTH = 4  # `from .deps import CurrentUser` in an __init__, followed this far


@dataclass(frozen=True)
class _Include:
    parent: Key
    child: Key
    prefix: str
    dependencies: tuple[str, ...]


def _aliases(tree: ast.Module, module: str, is_package: bool) -> dict[str, list[tuple[int, Target]]]:
    """Local name -> every (line, (module, attribute)) binding of it, in line order:
    `from m import a as b` -> b: (m, a); `import m as b` -> b: (m, None)."""
    package = module.split(".") if is_package else module.split(".")[:-1]
    out: dict[str, list[tuple[int, Target]]] = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level - 1 > len(package):
                    continue
                base = package[: len(package) - node.level + 1]
            else:
                base = []
            mod = ".".join(base + (node.module.split(".") if node.module else []))
            for alias in node.names:
                if alias.name != "*":
                    out[alias.asname or alias.name].append((node.lineno, (mod, alias.name)))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname].append((node.lineno, (alias.name, None)))
    for bindings in out.values():
        bindings.sort(key=lambda b: b[0])
    return out


def _binding(aliases: dict[str, list[tuple[int, Target]]], name: str, line: int) -> Target:
    """What `name` refers to at `line`: the last import of it at or before that line, else
    the first one after it (an import inside a function body that runs later). Taking
    the last import in the FILE made `from a import router as r; include(r); from b
    import router as r; include(r)` mount b twice and a nowhere."""
    bindings = aliases.get(name)
    if not bindings:
        return ("", None)
    before = [target for at, target in bindings if at <= line]
    return before[-1] if before else bindings[0][1]


def _loop_bindings(tree: ast.Module) -> dict[int, tuple[str, list[ast.expr]]]:
    """id(call) -> (loop variable, the values it takes), for every call inside a `for`
    over a literal list, tuple or set, or over a module-level list or tuple."""
    sequences = {target.id: node.value.elts for node in tree.body
                 if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple))
                 for target in node.targets if isinstance(target, ast.Name)}
    found: dict[int, tuple[str, list[ast.expr]]] = {}
    for loop in ast.walk(tree):  # breadth first: an inner loop overrides its outer one
        if not (isinstance(loop, (ast.For, ast.AsyncFor)) and isinstance(loop.target, ast.Name)):
            continue
        it = loop.iter
        values = (it.elts if isinstance(it, (ast.List, ast.Tuple, ast.Set))
                  else sequences.get(it.id) if isinstance(it, ast.Name) else None)
        if values is None:
            continue
        for stmt in loop.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    found[id(sub)] = (loop.target.id, list(values))
    return found


def _candidates(arg: ast.AST, loop: tuple[str, list[ast.expr]] | None) -> list[ast.AST]:
    """What an include_router argument stands for: itself or, when it is the loop's
    variable (`r`, or `module.router`), one expression per value the loop takes."""
    if loop is None:
        return [arg]
    var, values = loop
    if isinstance(arg, ast.Name) and arg.id == var:
        return values
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == var:
        return [ast.Attribute(value=v, attr=arg.attr, ctx=ast.Load()) for v in values]
    return [arg]


def mount_index(s: ScanSettings) -> "MountIndex":
    """The run's MountIndex: built once for security and performance both, and again only
    if a file or a setting it reads changed (`ParseCache.derived`)."""
    trees = {s.rel(path): tree for path, tree in parsed_files(s)}
    return s.parse_cache.derived("mount_index", run_inputs(s, trees), lambda: MountIndex(s, trees))


class MountIndex:
    """Every router in the scanned tree, with the Mount it effectively has."""

    def __init__(self, s: ScanSettings, trees: dict[str, ast.Module] | None = None):
        if trees is None:
            trees = {s.rel(path): tree for path, tree in parsed_files(s)}
        # A module name more than one file can claim resolves to none of them: mounting
        # the wrong router's dependencies could make an open route read as protected.
        self._trees = trees
        self._modules = ModuleMap(list(trees), s.python_roots)
        self._scheme_classes = s.security.auth_scheme_classes
        self._import_memo: dict[str, dict[str, list[tuple[int, Target]]]] = {}
        self._alias_memo: dict[str, dict[str, ast.Call]] = {}
        self._scheme_memo: dict[str, set[str]] = {}

        constructors = _ROUTER_CONSTRUCTORS | s.app_constructors
        self._own: dict[Key, Mount] = {}
        self._by_file: dict[str, list[str]] = defaultdict(list)
        for rel, tree in trees.items():
            for name, mount in declared_routers(tree, constructors).items():
                self._own[(rel, name)] = mount
                self._by_file[rel].append(name)

        includes: list[_Include] = []
        for rel, tree in trees.items():
            if not may_mention(tree, "include_router") or not any(
                    isinstance(n, ast.Attribute) and n.attr == "include_router" for n in ast.walk(tree)):
                continue
            aliases = self._imports(rel)
            loops = _loop_bindings(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "include_router" and node.args
                        and isinstance(node.func.value, ast.Name)):
                    continue
                for arg in _candidates(node.args[0], loops.get(id(node))):
                    child = self._resolve(arg, rel, aliases, node.lineno)
                    if child is not None:
                        includes.append(_Include((rel, node.func.value.id), child, router_prefix(node),
                                                 dependency_names(keyword_value(node, "dependencies"))))
        self._parents: dict[Key, list[_Include]] = defaultdict(list)
        for inc in sorted(includes, key=lambda i: (i.parent, i.child, i.prefix, i.dependencies)):
            self._parents[inc.child].append(inc)
        self._memo: dict[Key, Mount] = {}

    def _imports(self, rel: str) -> dict[str, list[tuple[int, Target]]]:
        if rel not in self._import_memo:
            self._import_memo[rel] = _aliases(self._trees[rel], self._modules.own[rel],
                                              rel.endswith("__init__.py"))
        return self._import_memo[rel]

    def _resolve(self, arg: ast.AST, rel: str, aliases: dict[str, list[tuple[int, Target]]],
                 line: int) -> Key | None:
        """The router an `include_router(<arg>)` argument names, if it can be found."""
        if isinstance(arg, ast.Name):
            if (rel, arg.id) in self._own:
                return (rel, arg.id)
            module, attr = _binding(aliases, arg.id, line)
            file = self._modules.unique(module, rel)
            if file and attr and (file, attr) in self._own:
                return (file, attr)
            return None
        if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
            module, attr = _binding(aliases, arg.value.id, line)
            file = self._modules.unique(f"{module}.{attr}" if attr else module, rel)
            if file and (file, arg.attr) in self._own:
                return (file, arg.attr)
        return None

    def effective(self, key: Key) -> Mount:
        """The prefix and dependencies every route on `key` inherits."""
        if key in self._memo:
            return self._memo[key]
        own = self._own.get(key, Mount())
        self._memo[key] = own  # provisional: a mount cycle resolves to the router's own
        candidates = []
        for inc in self._parents.get(key, ()):
            parent = self.effective(inc.parent)
            candidates.append(Mount(parent.prefix + inc.prefix + own.prefix,
                                    parent.dependencies + inc.dependencies + own.dependencies))
        if candidates:
            rest = candidates[1:]
            common = [d for d in candidates[0].dependencies if all(d in m.dependencies for m in rest)]
            result = Mount(candidates[0].prefix, tuple(dict.fromkeys(common)))
        else:
            result = own
        self._memo[key] = result
        return result

    def for_file(self, rel: str) -> dict[str, Mount]:
        """Router variable -> effective Mount, for the routers declared in `rel`."""
        return {name: self.effective((rel, name)) for name in self._by_file.get(rel, ())}

    # ── names defined in another module ─────────────────────────────────────────────
    def _aliases_in(self, rel: str) -> dict[str, ast.Call]:
        if rel not in self._alias_memo:
            self._alias_memo[rel] = annotated_aliases(self._trees[rel])
        return self._alias_memo[rel]

    def _schemes_in(self, rel: str) -> set[str]:
        if rel not in self._scheme_memo:
            self._scheme_memo[rel] = security_schemes(self._trees[rel], self._scheme_classes)
        return self._scheme_memo[rel]

    def _defined(self, rel: str, name: str, table, depth: int = 0) -> Key | None:
        """(file, name) where `name`, as `rel` sees it, is defined in `table(file)`: in
        `rel` itself, or through a `from m import name`, following a re-export (an
        `__init__` that imports it from a submodule) a few levels deep."""
        if name in table(rel):
            return (rel, name)
        if depth >= _REEXPORT_DEPTH:
            return None
        module, attr = _binding(self._imports(rel), name, _LAST_LINE)
        file = self._modules.unique(module, rel) if attr else None
        return self._defined(file, attr, table, depth + 1) if file else None

    def _module_imports(self, rel: str) -> dict[str, str]:
        """Local name -> file, for names bound to a whole module: `import app.deps as
        deps`, or `from app import deps` where `app/deps.py` is a scanned file."""
        out: dict[str, str] = {}
        for local in self._imports(rel):
            module, attr = _binding(self._imports(rel), local, _LAST_LINE)
            file = self._modules.unique(f"{module}.{attr}" if attr else module, rel)
            if file:
                out[local] = file
        return out

    def dependency_aliases(self, rel: str) -> dict[str, ast.Call]:
        """Annotation name as spelled in `rel` (`CurrentUser`, `deps.CurrentUser`) -> the
        Depends/Security call of an alias another module defines. The file's own
        aliases `routes()` reads itself."""
        out: dict[str, ast.Call] = {}
        for local in self._imports(rel):
            if (key := self._defined(rel, local, self._aliases_in)) is not None:
                out[local] = self._aliases_in(key[0])[key[1]]
        for local, file in self._module_imports(rel).items():
            out.update((f"{local}.{name}", call) for name, call in self._aliases_in(file).items())
        return out

    def _visible_schemes(self, rel: str) -> set[str]:
        """Scheme names a dependency in `rel` can name: its own, imported ones (a
        dependency is named by its last attribute, so `deps.oauth2_scheme` is
        `oauth2_scheme`), and those an alias it uses depends on in the alias's module
        (`TokenDep = Annotated[str, Depends(reusable_oauth2)]` in deps.py)."""
        names = set(self._schemes_in(rel))
        names.update(local for local in self._imports(rel)
                     if self._defined(rel, local, self._schemes_in) is not None)
        for file in self._module_imports(rel).values():
            names |= self._schemes_in(file)
        aliases = [(rel, name) for name in self._aliases_in(rel)]
        aliases += [key for local in self._imports(rel)
                    if (key := self._defined(rel, local, self._aliases_in)) is not None]
        for file, alias in aliases:
            target = dependency_name(self._aliases_in(file)[alias])
            if target and (target in self._schemes_in(file) or
                           self._defined(file, target, self._schemes_in) is not None):
                names.add(target)
        return names

    def schemes(self, rel: str) -> frozenset[str]:
        """Dependency names that are security schemes for the routes in `rel`, including
        router-level ones: an `include_router(..., dependencies=[Depends(scheme)])` in
        another file names the scheme as THAT file sees it."""
        names = self._visible_schemes(rel)
        seen: set[str] = {rel}
        stack: list[Key] = [(rel, name) for name in self._by_file.get(rel, ())]
        visited: set[Key] = set(stack)
        while stack:
            for inc in self._parents.get(stack.pop(), ()):
                if inc.parent[0] not in seen:
                    seen.add(inc.parent[0])
                    names |= self._visible_schemes(inc.parent[0])
                if inc.parent not in visited:
                    visited.add(inc.parent)
                    stack.append(inc.parent)
        return frozenset(names)
