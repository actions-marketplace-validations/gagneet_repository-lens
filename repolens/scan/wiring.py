"""Which route modules does the running app reach? The rest is dead code.

A router file nothing imports is never registered, so its routes are either 404s or —
the dangerous case — served by a DIFFERENT copy somewhere else. Findings in such a file
are real defects in code that does not run: they are reported with exposure
"unreachable" (the lowest priority), never hidden, because the dead copy is often the
one a test imports, and a guard present there proves nothing about the live handler.

Reachability is by import, starting from the files that construct the app (a call named
in [scan] app_constructors, outside the internal prefixes), the files that register
routers on an app a factory built (`app = get_application(); app.include_router(...)`),
plus [scan] entrypoints.
Imports inside functions and try/except count, and so do a dotted module name in a
string constant and a constant `importlib.import_module(...)`/`__import__(...)` argument
(relative names resolved against `package=`). A reachable file that imports modules
chosen at run time (`pkgutil.iter_modules`, `import_module(f"...{name}")`, `runpy`,
`spec_from_file_location`) makes reachability unknown, so nothing is marked. With no
entrypoint found the answer is "unknown" too: a guess here would demote live code.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..core.findings import UNDEPLOYED_NOTE, Finding
from .python_ast import (
    functions,
    last,
    may_mention,
    module_level,
    parsed_files,
    routes,
    run_inputs,
    walk_body,
)
from .settings import ScanSettings

_DOTTED = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$")
NOTE = " [in a module the app never imports: dead code]"


#: Directories commonly put on sys.path in place of the repository root. Mirrors
#: `impact.resolution.ImportIndex.python`, so the graph and these checks agree on what
#: `from app.api import x` names in a `backend/` or `src/` layout.
_LAYOUT_ROOTS = ("src", "backend")


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def module_names(rel: str, python_roots: tuple[str, ...],
                 packages: frozenset[str] | set[str] = frozenset()) -> list[str]:
    """Every dotted name `rel` can be imported by. The first is always the path from the
    repository root (`backend/app/main.py` -> `backend.app.main`), which is what a
    relative import inside the file is resolved against.

    The others strip a directory that is put on sys.path instead of the root: a
    configured python_root, `src/` or `backend/`, and the directory above the file's
    outermost package (`packages`: directories holding an `__init__.py`). Reading only
    the root-relative name, `backend/app/main.py`'s `from app.api.main import
    api_router` resolved to nothing, so every live route read as dead code. The package
    rule is applied only to a file inside a package: a bare script's stem (`main`,
    `routes`) would be claimed by every same-named script in the tree."""
    stem = rel[:-3] if rel.endswith(".py") else rel
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    roots = [r.strip("/") for r in python_roots]
    roots += list(_LAYOUT_ROOTS)
    top = folder = _parent(rel)
    while top in packages and top:
        top = _parent(top)
    if top != folder:
        roots.append(top)
    names = [stem.replace("/", ".")]
    for root in roots:
        if root and root != "." and stem.startswith(root + "/"):
            names.append(stem[len(root) + 1:].replace("/", "."))
    return list(dict.fromkeys(names))


class ModuleMap:
    """Module name -> the scanned files it can name, for every file in the scan.

    A name more than one file can claim (`app.main` under both `app/` and `backend/app/`)
    is ambiguous: `candidates` returns all of them and `unique` none. Which is the
    conservative answer depends on the question, so each caller picks."""

    def __init__(self, rels: list[str] | tuple[str, ...], python_roots: tuple[str, ...]):
        packages = frozenset(_parent(r) for r in rels if r == "__init__.py" or r.endswith("/__init__.py"))
        self.own: dict[str, str] = {}
        self._files: dict[str, set[str]] = defaultdict(set)
        for rel in rels:
            names = module_names(rel, python_roots, packages)
            self.own[rel] = names[0]
            for name in names:
                self._files[name].add(rel)

    def candidates(self, module: str, importer: str = "") -> set[str]:
        """Files `module` may name when imported from `importer`. The importer's own
        directory counts too, as it does for a script run in place (and in ImportIndex)."""
        found = set(self._files.get(module, ()))
        folder = _parent(importer)
        if module and folder:
            found |= self._files.get(f"{folder.replace('/', '.')}.{module}", set())
        return found

    def unique(self, module: str, importer: str = "") -> str | None:
        """The one file `module` names from `importer`, or None when none or several do."""
        found = self.candidates(module, importer)
        return next(iter(found)) if len(found) == 1 else None


_IMPORT_CALLS = frozenset({"import_module", "__import__"})
#: Calls that import or run modules found at run time: what they reach is unknown.
_DISCOVERY_CALLS = frozenset({"iter_modules", "walk_packages", "spec_from_file_location", "run_path",
                              "run_module", "load_source", "load_module", "module_from_spec"})


def _constant_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword(node: ast.Call, position: int, name: str) -> ast.AST | None:
    if len(node.args) > position:
        return node.args[position]
    return next((k.value for k in node.keywords if k.arg == name), None)


def _imported_by_call(node: ast.Call) -> str | None:
    """`import_module("a.b")` -> "a.b"; `import_module("..b", "a.c")` -> "a.b"; None when
    the name is not a constant (`imports_dynamically` covers that)."""
    name = _constant_str(_keyword(node, 0, "name"))
    if not name or not name.startswith("."):
        return name or None
    anchor = _constant_str(_keyword(node, 1, "package")) if last(node.func) == "import_module" else None
    if not anchor:
        return None  # a relative name without its package raises at run time
    base, level = anchor.split("."), len(name) - len(name.lstrip("."))
    if level - 1 >= len(base):
        return None
    rest = name.lstrip(".")
    return ".".join([*base[: len(base) - level + 1], *([rest] if rest else [])])


def imports_dynamically(tree: ast.Module) -> bool:
    """Whether the module imports or runs modules whose names are only known at run time."""
    if not may_mention(tree, *_IMPORT_CALLS, *_DISCOVERY_CALLS):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = last(node.func)
            if name in _DISCOVERY_CALLS or (
                    name in _IMPORT_CALLS and _constant_str(_keyword(node, 0, "name")) is None):
                return True
    return False


def _imports(tree: ast.Module, module: str, is_package: bool) -> set[str]:
    package = module.split(".") if is_package else module.split(".")[:-1]
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level - 1 > len(package):
                    continue
                base = package[: len(package) - node.level + 1]
            else:
                base = []
            mod = base + (node.module.split(".") if node.module else [])
            if mod:
                out.add(".".join(mod))
            out.update(".".join([*mod, a.name]) for a in node.names if a.name != "*")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and _DOTTED.match(node.value):
            out.add(node.value)
        elif isinstance(node, ast.Call) and last(node.func) in _IMPORT_CALLS:
            imported = _imported_by_call(node)
            if imported:
                out.add(imported)
    return out


def _constructs_app(tree: ast.Module, constructors: frozenset[str]) -> bool:
    return may_mention(tree, *constructors) and any(isinstance(n, ast.Call) and last(n.func) in constructors for n in ast.walk(tree))


_ROUTER_CONSTRUCTORS = frozenset({"APIRouter", "Blueprint"})


def _registrations(nodes: list[ast.AST]) -> list[ast.Call]:
    """`x.include_router(...)` and `x.mount("/path", ...)` calls on a named object. A
    mount needs a path: `session.mount("https://", adapter)` is the requests library."""
    found = []
    for node in nodes:
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)):
                continue
            if call.func.attr == "include_router" or (
                    call.func.attr == "mount" and call.args and isinstance(call.args[0], ast.Constant)
                    and isinstance(call.args[0].value, str) and call.args[0].value.startswith("/")):
                found.append(call)
    return found


def _router_names(nodes: list[ast.AST]) -> set[str]:
    return {t.id for node in nodes for n in ast.walk(node) if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Call) and last(n.value.func) in _ROUTER_CONSTRUCTORS
            for t in n.targets if isinstance(t, ast.Name)}


def _registers_on_app(tree: ast.Module) -> bool:
    """Routers registered on an app built somewhere else: `app = get_application()` then
    `app.include_router(items.router)`, or a factory that does it and returns the app.
    Only files that CALL FastAPI() used to be roots, so an app made by a factory in
    another module left every router it mounts reading as dead code.

    Registering onto a router (`api_router = APIRouter()`, then
    `api_router.include_router(...)`) is not an app: that aggregator is live only if
    something imports it, and making it a root would hide that it is not."""
    if not may_mention(tree, "include_router", "mount"):
        return False  # both searches below look only for these calls
    statements = [n for n in module_level(tree)
                  if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    routers = _router_names(statements)
    # Module level: the compound statements `module_level` yields also hold their
    # children, which it yields again; walking only simple statements counts each once.
    simple = [n for n in statements if not isinstance(n, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For))
              and type(n).__name__ != "TryStar"]
    if any(c.func.value.id not in routers for c in _registrations(simple)):
        return True
    for fn, _ in functions(tree):
        returned = {n.value.id for n in walk_body(fn) if isinstance(n, ast.Return) and isinstance(n.value, ast.Name)}
        body = list(walk_body(fn))
        local_routers = routers | _router_names(fn.body)
        calls = [n for n in body if isinstance(n, ast.Call)]
        if any(c.func.value.id in returned and c.func.value.id not in local_routers
               for c in _registrations(calls)):
            return True
    return False


@dataclass(frozen=True)
class RouteExposure:
    """What reachability says about the route files: never-imported files, and files only
    an app no deployment manifest runs reaches (file -> the note naming what does run)."""

    unreachable: frozenset[str] = frozenset()
    undeployed: dict[str, str] = field(default_factory=dict)


def _closure(trees: dict[str, ast.Module], modules: ModuleMap, roots: set[str]) -> set[str]:
    seen, stack = set(roots), list(roots)
    while stack:
        rel = stack.pop()
        for imported in _imports(trees[rel], modules.own[rel], rel.endswith("__init__.py")):
            parts = imported.split(".")
            # Importing a.b.c runs a/__init__ and a/b/__init__ too. A name more than one
            # file can claim reaches every one of them: marking live code dead is the
            # costly error here, and an unresolved import would do exactly that.
            for i in range(len(parts), 0, -1):
                for target in modules.candidates(".".join(parts[:i]), rel):
                    if target not in seen:
                        seen.add(target)
                        stack.append(target)
    return seen


def route_exposure(s: ScanSettings) -> RouteExposure:
    """Unreachable route files, and (with [scan] deployment_detection) undeployed ones.

    Undeployed needs positive evidence: at least one non-auxiliary deployment manifest runs
    a Python server that resolves to a scanned file, and `deploy.discover` reports no
    blocking target at all. Blocking covers an application that cannot be named statically
    (`uvicorn $APP_MODULE`), any program or format it does not understand, an unreadable
    or unparsable manifest, and unresolvable targets in auxiliary files too (a dev script's
    ambiguous `uvicorn main:app`). Then a route file that some app reaches but nothing a
    manifest runs (nor [scan] entrypoints) reaches is reported "undeployed". With no
    manifest, a discovery that fails, or a live file importing modules chosen at run time,
    nothing is marked undeployed.

    Computed once per run (security and performance both ask), and again only if a file or
    a setting it reads changed. Deployment manifests are read on the first computation."""
    trees = {s.rel(path): tree for path, tree in parsed_files(s)}
    return s.parse_cache.derived("route_exposure", run_inputs(s, trees),
                                 lambda: _route_exposure(s, trees))


def _route_exposure(s: ScanSettings, trees: dict[str, ast.Module]) -> RouteExposure:
    modules = ModuleMap(list(trees), s.python_roots)

    apps = {rel for rel, tree in trees.items()
            if not s.is_internal(rel) and (_constructs_app(tree, s.app_constructors)
                                           or _registers_on_app(tree))}
    entrypoints = {rel for rel in trees if rel in s.entrypoints}
    roots = apps | entrypoints
    if not roots:
        return RouteExposure()
    seen = _closure(trees, modules, roots)
    # A reachable file importing modules found at run time may reach any route file.
    unreachable = frozenset() if any(imports_dynamically(trees[rel]) for rel in seen) else frozenset(
        rel for rel, tree in trees.items() if rel not in seen and routes(tree))
    if not s.deployment_detection:
        return RouteExposure(unreachable)

    from .deploy import discover  # deploy builds on ModuleMap
    try:
        deployment = discover(s, list(trees), modules)
    except Exception:  # noqa: BLE001 - a failed discovery is an unknown deployment, never a known one
        return RouteExposure(unreachable)
    # Tests, CI and dev scripts add to what is live but never make the deployment known.
    runs = [t for t in deployment.targets
            if t.files and not t.auxiliary and (t.server or set(t.files) & roots)]
    if not runs or deployment.blocking:
        return RouteExposure(unreachable)
    live = _closure(trees, modules, {f for t in deployment.targets for f in t.files if f in trees}
                    | entrypoints)
    if any(imports_dynamically(trees[rel]) for rel in live):
        return RouteExposure(unreachable)
    described = list(dict.fromkeys(f"{t.manifest} runs {', '.join(t.files)}" for t in runs))
    shown = "; ".join(described[:3]) + (f"; +{len(described) - 3} more" if len(described) > 3 else "")
    note = f" [{UNDEPLOYED_NOTE}: {shown}]"
    undeployed = {rel: note for rel, tree in trees.items()
                  if rel in seen and rel not in live and routes(tree)}
    return RouteExposure(unreachable, undeployed)


def unreachable_route_files(s: ScanSettings) -> frozenset[str]:
    """Route-defining files that no entrypoint reaches by import."""
    return route_exposure(s).unreachable


def mark_unreachable(findings: list[Finding]) -> None:
    """Demote findings in a never-imported file to exposure "unreachable", noting why."""
    for finding in findings:
        finding.exposure = "unreachable"
        finding.message += NOTE


def mark_undeployed(findings: list[Finding], note: str) -> None:
    """Demote findings to exposure "undeployed" and append `note` (what does run)."""
    for finding in findings:
        finding.exposure = "undeployed"
        finding.message += note


def mark(findings: list[Finding], rel: str, exposure: RouteExposure) -> None:
    """Apply `exposure` to one file's findings: demoted, never dropped."""
    if rel in exposure.unreachable:
        mark_unreachable(findings)
    elif rel in exposure.undeployed:
        mark_undeployed(findings, exposure.undeployed[rel])
