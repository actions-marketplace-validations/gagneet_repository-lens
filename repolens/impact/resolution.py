"""Local import resolution against the admitted scan inventory only."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re

from .source import read_source

_JSONC = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/')


def jsonc(text: str) -> dict:
    """Read comments/trailing commas without evaluating a JS config file."""
    text = _JSONC.sub(lambda m: m[0] if m[0].startswith('"') else " " * len(m[0]), text)
    # Remove trailing commas only outside quoted strings.
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])')
    text = tokens.sub(lambda m: m[0] if m[0].startswith('"') else "", text)
    result = json.loads(text)
    if not isinstance(result, dict):
        raise ValueError("configuration must be an object")
    return result


class ImportIndex:
    """Resolves import specifiers to files in the admitted scan inventory, and nowhere else.

    JS/TS specifiers also use tsconfig/jsconfig `paths` and `baseUrl`; a config that cannot
    be read, fully or partly, is recorded in `problems`."""
    def __init__(self, root: Path, files: list[Path], max_bytes: int):
        self.root = root
        self.files = {p.relative_to(root).as_posix() for p in files}
        self._root_text = os.path.normpath(str(root))
        # (base, python) -> resolved file. A large Python tree asks the same question for
        # every import of a module from every package root.
        self._resolved: dict[tuple[str, bool], str | None] = {}
        # directory -> (paths base, compilerOptions.paths, whether a baseUrl is in effect)
        self.configs: dict[Path, tuple[Path, dict, bool]] = {}
        # (config path, message, fatal). A fatal problem discards the config; a partial
        # one (a package `extends`) keeps the local options that could be read.
        self.problems: list[tuple[str, str, bool]] = []
        self.max_bytes = max_bytes
        # tsconfig files are JSON and therefore already in the admitted inventory.
        for path in files:
            if path.name in {"tsconfig.json", "jsconfig.json"}:
                rel = path.relative_to(root).as_posix()
                try:
                    loaded = self._load_config(path, set())
                except (ValueError, TypeError) as exc:
                    self.problems.append((rel, str(exc), True))
                    continue
                self.problems.extend((rel, note, False) for note in loaded["partial"])
                # TypeScript resolves `paths` against baseUrl when one is in effect, and
                # otherwise against the directory of the config that declares `paths`.
                base = loaded["base_url"] or loaded["paths_dir"] or path.parent
                if path.name == "tsconfig.json" or path.parent not in self.configs:
                    self.configs[path.parent] = (base, loaded["paths"] or {}, loaded["base_url"] is not None)

    def _load_config(self, path: Path, seen: set[Path]) -> dict:
        path = path.resolve()
        if path in seen or len(seen) >= 12:
            raise ValueError("cyclic or excessively deep tsconfig extends")
        source = read_source(self.root, path, self.max_bytes)
        if source.text is None:
            raise ValueError(f"tsconfig could not be read: {source.status}")
        data = jsonc(source.text)
        seen = seen | {path}
        result: dict = {"base_url": None, "paths": None, "paths_dir": None, "partial": []}
        extends = data.get("extends")
        parents = extends if isinstance(extends, list) else [extends] if extends else []
        for parent in parents:  # array extends apply in order, later entries winning
            if not isinstance(parent, str):
                raise ValueError("tsconfig extends must be a string or an array of strings")
            if not parent.startswith("."):
                # A shared config package (`@repo/tsconfig/nextjs.json`) lives in
                # node_modules, which is never read. Its options are unknown; this
                # config's own paths still apply.
                result["partial"].append(f"extends {parent!r} is a package; its compilerOptions were not read")
                continue
            target = path.parent / parent
            if target.suffix != ".json":
                target = Path(str(target) + ".json")
            inherited = self._load_config(target, seen)
            for key in ("base_url", "paths", "paths_dir"):
                if inherited[key] is not None:
                    result[key] = inherited[key]
            result["partial"].extend(inherited["partial"])
        options = data.get("compilerOptions", {})
        if not isinstance(options, dict):
            raise ValueError("compilerOptions must be an object")
        if "baseUrl" in options:
            if not isinstance(options["baseUrl"], str):
                raise ValueError("compilerOptions.baseUrl must be a string")
            result["base_url"] = (path.parent / options["baseUrl"]).resolve()
        if "paths" in options:
            paths = options["paths"]
            if not isinstance(paths, dict) or any(not isinstance(k, str) or not isinstance(v, list)
                                                 or any(not isinstance(p, str) for p in v) for k, v in paths.items()):
                raise ValueError("compilerOptions.paths must map strings to arrays of strings")
            result["paths"], result["paths_dir"] = paths, path.parent
        return result

    def _relative(self, candidate: str) -> str | None:
        """`candidate` as a repository-relative POSIX path, computed lexically; None outside
        the root. Membership in `files`, the admitted inventory whose symlinks the scan
        already checked, is the only test, so the filesystem is never consulted: resolving
        every candidate cost minutes of `realpath` calls on a large repository."""
        normal = os.path.normpath(candidate)
        if not normal.startswith(self._root_text + os.sep):
            return None
        return normal[len(self._root_text) + 1:].replace(os.sep, "/")

    def _candidate(self, base: Path, python: bool = False) -> str | None:
        key = (str(base), python)
        if key not in self._resolved:
            self._resolved[key] = self._find(base, python)
        return self._resolved[key]

    def _find(self, base: Path, python: bool) -> str | None:
        # Declaration files last: `import "../types/env"` resolving to env.d.ts is a type-only
        # module, and an unresolved one would read as a missing local file.
        suffixes = (".py",) if python else (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json",
                                            ".d.ts", ".d.mts", ".d.cts")
        candidates = [base]
        # TS NodeNext commonly imports emitted .js paths while sources are .ts.
        if not python and base.suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            substitution = {".js": [".ts", ".tsx"], ".jsx": [".tsx", ".ts"], ".mjs": [".mts"], ".cjs": [".cts"]}
            candidates = [base.with_suffix(ext) for ext in substitution[base.suffix]] + candidates
        candidates += [Path(str(base) + ext) for ext in suffixes]
        candidates += [base / ("__init__" + ext if python else "index" + ext) for ext in suffixes]
        for candidate in candidates:
            rel = self._relative(str(candidate))
            if rel is not None and rel in self.files:
                return rel
        return None

    def javascript(self, source: str, module: str) -> tuple[str | None, bool]:
        """Return (resolved file, expected-local), distinguishing packages from gaps."""
        path = self.root / source
        if module.startswith("."):
            return self._candidate(path.parent / module), True
        candidates = [parent for parent in (path.parent, *path.parents) if parent in self.configs]
        if candidates:
            base, paths, has_base_url = self.configs[candidates[0]]
            for key in sorted(paths, key=lambda value: (-len(value.split("*")[0]), value)):
                pieces = key.split("*")
                if len(pieces) > 2:
                    continue
                match = re.fullmatch(re.escape(key).replace(r"\*", "(.*)"), module)
                if match:
                    wildcard = match[1] if len(pieces) == 2 else ""
                    for target in paths[key]:
                        resolved = self._candidate(base / target.replace("*", wildcard))
                        if resolved:
                            return resolved, True
                    return None, True
            # Non-relative module names resolve against baseUrl only when one is set;
            # otherwise `import x from "lib"` is a package even if ./lib exists.
            resolved = self._candidate(base / module) if has_base_url else None
            if resolved:
                return resolved, True
        return None, False

    def python(self, source: str, module: str, level: int = 0) -> str | None:
        """The admitted file that importing `module` from `source` names, or None.

        A relative import (`level` > 0) walks up from the importing package. An absolute
        import tries the importer's outermost package root first, then the repository root,
        `src/`, `backend/` and the importer's directory; several matches resolve to None."""
        base = (self.root / source).parent
        if level:
            for _ in range(level - 1):
                base = base.parent
            return self._candidate(base / module.replace(".", "/"), python=True)
        # The directory holding the file's outermost package is the sys.path entry an
        # absolute import is written against. In a monorepo (`services/api/app/...` next
        # to `services/worker/app/...`) that root names one implementation, where the
        # repository-wide roots below see two and resolve neither. Intermediate package
        # directories are not candidates: Python 3 has no implicit relative imports.
        package_root = base
        while (package_root != self.root and package_root.parent != package_root
               and self._relative(os.path.join(str(package_root), "__init__.py")) in self.files):
            package_root = package_root.parent
        if found := self._candidate(package_root / module.replace(".", "/"), python=True):
            return found
        # Common repository and src layouts. Multiple roots with the same module
        # name remain unresolved instead of selecting an arbitrary implementation.
        roots = [self.root, self.root / "src", self.root / "backend", base]
        matches = {found for root in roots if (found := self._candidate(root / module.replace(".", "/"), python=True))}
        return next(iter(matches)) if len(matches) == 1 else None

    def python_bindings(self, source: str, tree: ast.Module) -> list[tuple[str, str, str, int]]:
        """Module-level imports in `tree` that resolve locally, as (target file, local name,
        imported name or `*` for a whole module, line)."""
        bindings = []
        # Only module imports; a function-local import cannot bind other functions. Imports
        # under if/try/with at module level do bind the module: `try: from app.routes
        # import c` is how optional routers are wired.
        statements: list[ast.stmt] = []
        stack = list(reversed(tree.body))
        while stack:
            statement = stack.pop()
            statements.append(statement)
            if isinstance(statement, (ast.If, ast.Try, ast.With)) or type(statement).__name__ == "TryStar":
                children = [*getattr(statement, "body", []), *getattr(statement, "orelse", []),
                            *getattr(statement, "finalbody", [])]
                for handler in getattr(statement, "handlers", []):
                    children.extend(handler.body)
                stack.extend(reversed(children))
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    module = node.module or ""
                    submodule = self.python(source, ".".join(filter(None, (module, alias.name))), node.level)
                    target = submodule or self.python(source, module, node.level)
                    if target:
                        bindings.append((target, alias.asname or alias.name, "*" if submodule else alias.name, node.lineno))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    target = self.python(source, alias.name)
                    if target:
                        bindings.append((target, alias.asname or alias.name, "*", node.lineno))
        return bindings
