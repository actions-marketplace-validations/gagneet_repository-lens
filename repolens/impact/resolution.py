"""Local import resolution against the admitted scan inventory only."""
from __future__ import annotations

import ast
import json
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
    def __init__(self, root: Path, files: list[Path], max_bytes: int):
        self.root = root
        self.files = {p.relative_to(root).as_posix() for p in files}
        self.configs: dict[Path, tuple[Path, dict]] = {}
        self.problems: list[tuple[str, str]] = []
        self.max_bytes = max_bytes
        # tsconfig files are JSON and therefore already in the admitted inventory.
        for path in files:
            if path.name in {"tsconfig.json", "jsconfig.json"}:
                try:
                    base, paths = self._load_config(path, set())
                    if path.name == "tsconfig.json" or path.parent not in self.configs:
                        self.configs[path.parent] = (base, paths)
                except (ValueError, TypeError) as exc:
                    self.problems.append((path.relative_to(root).as_posix(), str(exc)))

    def _load_config(self, path: Path, seen: set[Path]) -> tuple[Path, dict]:
        path = path.resolve()
        if path in seen or len(seen) >= 12:
            raise ValueError("cyclic or excessively deep tsconfig extends")
        source = read_source(self.root, path, self.max_bytes)
        if source.text is None:
            raise ValueError(f"tsconfig could not be read: {source.status}")
        data = jsonc(source.text)
        seen = seen | {path}
        base, paths = path.parent, {}
        if data.get("extends"):
            parent = data["extends"]
            if not isinstance(parent, str) or not parent.startswith("."):
                raise ValueError("package or array tsconfig extends is unresolved; use a local flattened config")
            target = path.parent / parent
            if target.suffix != ".json":
                target = Path(str(target) + ".json")
            base, paths = self._load_config(target, seen)
        options = data.get("compilerOptions", {})
        if not isinstance(options, dict):
            raise ValueError("compilerOptions must be an object")
        if "baseUrl" in options:
            base = (path.parent / options["baseUrl"]).resolve()
        if "paths" in options:
            paths = options["paths"]
            if "baseUrl" not in options and not data.get("extends"):
                base = path.parent
        if not isinstance(paths, dict) or any(not isinstance(k, str) or not isinstance(v, list)
                                             or any(not isinstance(p, str) for p in v) for k, v in paths.items()):
            raise ValueError("compilerOptions.paths must map strings to arrays of strings")
        return base, paths

    def _candidate(self, base: Path, python: bool = False) -> str | None:
        suffixes = (".py",) if python else (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json")
        candidates = [base]
        # TS NodeNext commonly imports emitted .js paths while sources are .ts.
        if not python and base.suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            substitution = {".js": [".ts", ".tsx"], ".jsx": [".tsx", ".ts"], ".mjs": [".mts"], ".cjs": [".cts"]}
            candidates = [base.with_suffix(ext) for ext in substitution[base.suffix]] + candidates
        candidates += [Path(str(base) + ext) for ext in suffixes]
        candidates += [base / ("__init__" + ext if python else "index" + ext) for ext in suffixes]
        for candidate in candidates:
            try:
                rel = candidate.resolve().relative_to(self.root).as_posix()
            except (ValueError, OSError, RuntimeError):
                continue
            if rel in self.files:
                return rel
        return None

    def javascript(self, source: str, module: str) -> tuple[str | None, bool]:
        """Return (resolved file, expected-local), distinguishing packages from gaps."""
        path = self.root / source
        if module.startswith("."):
            return self._candidate(path.parent / module), True
        candidates = [parent for parent in (path.parent, *path.parents) if parent in self.configs]
        if candidates:
            base, paths = self.configs[candidates[0]]
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
            resolved = self._candidate(base / module)
            if resolved:
                return resolved, True
        return None, False

    def python(self, source: str, module: str, level: int = 0) -> str | None:
        base = (self.root / source).parent
        if level:
            for _ in range(level - 1):
                base = base.parent
            return self._candidate(base / module.replace(".", "/"), python=True)
        # Common repository and src layouts. Multiple roots with the same module
        # name remain unresolved instead of selecting an arbitrary implementation.
        roots = [self.root, self.root / "src", self.root / "backend", base]
        matches = {found for root in roots if (found := self._candidate(root / module.replace(".", "/"), python=True))}
        return next(iter(matches)) if len(matches) == 1 else None

    def python_bindings(self, source: str, tree: ast.Module) -> list[tuple[str, str, str, int]]:
        bindings = []
        # Only module imports; a function-local import cannot bind other functions.
        for node in tree.body:
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
