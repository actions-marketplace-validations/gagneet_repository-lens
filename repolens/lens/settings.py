"""Function Lens settings, read from `[lens]` in repolens.toml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import Config, merge

JAVASCRIPT_PARSERS = ("regex", "tree-sitter")

DEFAULTS: dict = {
    "python_roots": ["."],
    "frontend_roots": [],
    "frontend_extensions": [".ts", ".tsx", ".js", ".jsx"],
    # How frontend declarations are extracted: "regex" or "tree-sitter". Named, never
    # detected: the committed digest must not depend on which extras a machine has
    # installed. "regex" is the default because every index committed before this
    # setting existed was built by it, and it needs nothing installed.
    "javascript_parser": "regex",
    "tests_dir": "tests",
    "test_extensions": [".py", ".ts", ".tsx", ".js", ".jsx"],
    # Whole path components. `alembic/versions` is a run of two: a migration's
    # upgrade()/downgrade() pair is frozen per revision, and indexing a hundred
    # identical pairs drowns the index in exactly the false duplicates it surfaces.
    "skip_parts": ["venv", ".venv", "node_modules", "__pycache__", ".next", "site-packages",
                   "alembic/versions", ".git", "dist", "build", "coverage"],
    # Calls that establish a trust boundary, recorded per function. Framework-specific,
    # so empty by default.
    "guard_calls": [],
    # `<receiver>.<collection>` attribute access is a document-store read.
    "mongo_receiver": "db",
    # `<call>("SELECT ... FROM schema.table")` is a SQL read.
    "sql_call": "text",
    # A docstring whose first line starts with one of these is boilerplate, not a purpose.
    "placeholder_prefixes": [],
    "owners_yaml": "",
    "datastore_json": "",
    "title": "Function Lens",
    "command": "repolens lens",
    "out_full": ".repolens/function_lens.json",
    "out_digest": ".repolens/function_lens_digest.json",
    "out_html": "",
    # Appended after the core limits; describe what THIS profile excludes.
    "extra_limits": [],
}


@dataclass
class LensSettings:
    root: Path
    python_roots: list[str]
    frontend_roots: list[str]
    frontend_extensions: list[str]
    javascript_parser: str
    tests_dir: str
    test_extensions: list[str]
    skip_parts: list[str]
    guard_calls: frozenset[str]
    mongo_receiver: str
    sql_call: str
    placeholder_prefixes: tuple[str, ...]
    owners_yaml: str
    datastore_json: str
    title: str
    command: str
    out_full: Path
    out_digest: Path
    out_html: Path | None
    extra_limits: list[str]

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()


def from_config(cfg: Config) -> LensSettings:
    d = merge(DEFAULTS, cfg.section("lens"))
    root = cfg.root
    parser = d["javascript_parser"]
    if parser not in JAVASCRIPT_PARSERS:
        # No "auto": a parser chosen by what happens to be importable makes the committed
        # digest machine-dependent, and `--check` then reports the machine as staleness.
        raise SystemExit(f"[lens] javascript_parser must be one of {', '.join(map(repr, JAVASCRIPT_PARSERS))}, "
                         f"not {parser!r}. It is never detected: a committed index has to "
                         "come out the same on every machine.")
    return LensSettings(
        root=root,
        python_roots=list(d["python_roots"]),
        frontend_roots=list(d["frontend_roots"]),
        frontend_extensions=list(d["frontend_extensions"]),
        javascript_parser=parser,
        tests_dir=d["tests_dir"],
        test_extensions=list(d["test_extensions"]),
        skip_parts=list(d["skip_parts"]),
        guard_calls=frozenset(d["guard_calls"]),
        mongo_receiver=d["mongo_receiver"],
        sql_call=d["sql_call"],
        placeholder_prefixes=tuple(d["placeholder_prefixes"]),
        owners_yaml=d["owners_yaml"],
        datastore_json=d["datastore_json"],
        title=d["title"],
        command=d["command"],
        out_full=root / d["out_full"],
        out_digest=root / d["out_digest"],
        out_html=(root / d["out_html"]) if d["out_html"] else None,
        extra_limits=list(d["extra_limits"]),
    )
