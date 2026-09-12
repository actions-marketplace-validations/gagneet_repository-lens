"""Where each FastAPI router is mounted: the prefix and router-level dependencies every
route on it inherits.

A route's decorator is not the whole story. `APIRouter(prefix="/x",
dependencies=[Depends(auth)])` and `parent.include_router(child, prefix="/y",
dependencies=[...])` both apply to every route on the router. Reading only the decorator
reported router-level authentication as "no authentication", and printed every path
without its prefix.

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
    declared_routers,
    dependency_names,
    keyword_value,
    parse,
    python_files,
    router_prefix,
)
from .settings import ScanSettings
from .wiring import module_names

_ROUTER_CONSTRUCTORS = frozenset({"APIRouter"})

Key = tuple[str, str]  # (repo-relative file, router variable)
Target = tuple[str, str | None]  # (module, attribute): what an imported name refers to


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


class MountIndex:
    """Every router in the scanned tree, with the Mount it effectively has."""

    def __init__(self, s: ScanSettings):
        trees: dict[str, ast.Module] = {}
        by_module: dict[str, str] = {}
        for path in python_files(s):
            tree = parse(str(path))
            if tree is None:
                continue
            rel = s.rel(path)
            trees[rel] = tree
            for name in module_names(rel, s.python_roots):
                by_module.setdefault(name, rel)

        constructors = _ROUTER_CONSTRUCTORS | s.app_constructors
        self._own: dict[Key, Mount] = {}
        self._by_file: dict[str, list[str]] = defaultdict(list)
        for rel, tree in trees.items():
            for name, mount in declared_routers(tree, constructors).items():
                self._own[(rel, name)] = mount
                self._by_file[rel].append(name)

        includes: list[_Include] = []
        for rel, tree in trees.items():
            if not any(isinstance(n, ast.Attribute) and n.attr == "include_router"
                       for n in ast.walk(tree)):
                continue
            names = module_names(rel, s.python_roots)
            own_module = min(names, key=len) if names else ""
            aliases = _aliases(tree, own_module, rel.endswith("__init__.py"))
            loops = _loop_bindings(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "include_router" and node.args
                        and isinstance(node.func.value, ast.Name)):
                    continue
                for arg in _candidates(node.args[0], loops.get(id(node))):
                    child = self._resolve(arg, rel, aliases, by_module, node.lineno)
                    if child is not None:
                        includes.append(_Include((rel, node.func.value.id), child, router_prefix(node),
                                                 dependency_names(keyword_value(node, "dependencies"))))
        self._parents: dict[Key, list[_Include]] = defaultdict(list)
        for inc in sorted(includes, key=lambda i: (i.parent, i.child, i.prefix, i.dependencies)):
            self._parents[inc.child].append(inc)
        self._memo: dict[Key, Mount] = {}

    def _resolve(self, arg: ast.AST, rel: str, aliases: dict[str, list[tuple[int, Target]]],
                 by_module: dict[str, str], line: int) -> Key | None:
        """The router an `include_router(<arg>)` argument names, if it can be found."""
        if isinstance(arg, ast.Name):
            if (rel, arg.id) in self._own:
                return (rel, arg.id)
            module, attr = _binding(aliases, arg.id, line)
            file = by_module.get(module)
            if file and attr and (file, attr) in self._own:
                return (file, attr)
            return None
        if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
            module, attr = _binding(aliases, arg.value.id, line)
            file = by_module.get(f"{module}.{attr}" if attr else module)
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
