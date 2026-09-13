"""Which route modules does the running app reach? The rest is dead code.

A router file nothing imports is never registered, so its routes are either 404s or —
the dangerous case — served by a DIFFERENT copy somewhere else. Findings in such a file
are real defects in code that does not run: they are reported with exposure
"unreachable" (the lowest priority), never hidden, because the dead copy is often the
one a test imports, and a guard present there proves nothing about the live handler.

Reachability is by import, starting from the files that construct the app (a call named
in [scan] app_constructors, outside the internal prefixes) plus [scan] entrypoints.
Imports inside functions and try/except count, and so does a dotted module name in a
string constant (importlib wiring). With no entrypoint found the answer is "unknown" and
nothing is marked: a guess here would demote live code.
"""
from __future__ import annotations

import ast
import re

from ..core.findings import Finding
from .python_ast import last, parse, python_files, routes
from .settings import ScanSettings

_DOTTED = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$")
NOTE = " [in a module the app never imports: dead code]"


def module_names(rel: str, python_roots: tuple[str, ...]) -> list[str]:
    """`backend/routers/x.py` under root `backend` -> [`backend.routers.x`, `routers.x`]."""
    stem = rel[:-3] if rel.endswith(".py") else rel
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    names = [stem.replace("/", ".")]
    for root in python_roots:
        root = root.strip("/")
        if root and root != "." and stem.startswith(root + "/"):
            names.append(stem[len(root) + 1:].replace("/", "."))
    return names


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
    return out


def _constructs_app(tree: ast.Module, constructors: frozenset[str]) -> bool:
    return any(isinstance(n, ast.Call) and last(n.func) in constructors for n in ast.walk(tree))


def unreachable_route_files(s: ScanSettings) -> frozenset[str]:
    """Route-defining files that no entrypoint reaches by import."""
    trees: dict[str, ast.Module] = {}
    by_module: dict[str, str] = {}
    for path in python_files(s):
        tree = parse(str(path), s.max_file_bytes)
        if tree is None:
            continue
        rel = s.rel(path)
        trees[rel] = tree
        for name in module_names(rel, s.python_roots):
            by_module.setdefault(name, rel)

    roots = {rel for rel, tree in trees.items()
             if rel in s.entrypoints
             or (not s.is_internal(rel) and _constructs_app(tree, s.app_constructors))}
    if not roots:
        return frozenset()
    seen, stack = set(roots), list(roots)
    while stack:
        rel = stack.pop()
        own = min(module_names(rel, s.python_roots), key=len)
        for imported in _imports(trees[rel], own, rel.endswith("__init__.py")):
            parts = imported.split(".")
            # Importing a.b.c runs a/__init__ and a/b/__init__ too.
            for i in range(len(parts), 0, -1):
                target = by_module.get(".".join(parts[:i]))
                if target and target not in seen:
                    seen.add(target)
                    stack.append(target)
    return frozenset(rel for rel, tree in trees.items() if rel not in seen and routes(tree))


def mark_unreachable(findings: list[Finding]) -> None:
    for finding in findings:
        finding.exposure = "unreachable"
        finding.message += NOTE
