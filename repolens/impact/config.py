from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from pathlib import PurePosixPath

from ..config import load_config

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".impact-tracer", ".next", ".venv", "venv", "node_modules",
    "dist", "build", "coverage", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".repolens", ".tox", ".ruff_cache",
}

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".md", ".html", ".sh", ".sql", ".mts", ".cts",
}


@dataclass(slots=True)
class Config:
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDES))
    exclude_paths: set[str] = field(default_factory=set)
    extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    aliases: dict[str, list[str]] = field(default_factory=dict)
    canonical_owners_json: str | None = "docs/architecture/canonical_owners.json"
    router_datastore_json: str | None = "docs/architecture/router_datastore_map.json"
    backend_api_prefix: str = ""
    max_ambiguous_targets: int = 12
    max_file_bytes: int = 2_000_000
    max_files: int = 10_000
    # Application vocabulary, empty by default. Which schemas hold tables, which words
    # are roles and which calls gate a feature are facts about ONE application; a
    # generic scanner that guessed them would draw edges nobody declared.
    pg_schemas: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    #: Regex fragments naming a call whose first argument is a feature toggle.
    toggle_calls: list[str] = field(default_factory=list)
    #: `<receiver>.<collection>` outside Python is a document-store reference.
    mongo_receiver: str = "db"

    def validate(self) -> None:
        if isinstance(self.max_file_bytes, bool) or not isinstance(self.max_file_bytes, int) or not 1 <= self.max_file_bytes <= 100_000_000:
            raise ValueError("max_file_bytes must be between 1 and 100000000")
        if isinstance(self.max_ambiguous_targets, bool) or not isinstance(self.max_ambiguous_targets, int) or not 1 <= self.max_ambiguous_targets <= 100:
            raise ValueError("max_ambiguous_targets must be between 1 and 100")
        if isinstance(self.max_files, bool) or not isinstance(self.max_files, int) or not 1 <= self.max_files <= 100_000:
            raise ValueError("max_files must be between 1 and 100000")
        if not isinstance(self.extensions, (set, frozenset, list, tuple)):
            raise ValueError("extensions must be a list of suffixes")
        if any(not isinstance(ext, str) or not ext.startswith(".") or "/" in ext or "\\" in ext
               for ext in self.extensions):
            raise ValueError("extensions must contain suffixes such as .py or .cs")
        self.extensions = {ext.lower() for ext in self.extensions}
        for name in ("exclude_dirs", "exclude_paths", "pg_schemas", "roles", "toggle_calls"):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset, list, tuple)) or any(not isinstance(v, str) for v in values):
                raise ValueError(f"{name} must be a list of strings")
        if not isinstance(self.aliases, dict) or any(
            not isinstance(key, str) or not isinstance(values, (list, tuple, set, frozenset))
            or any(not isinstance(value, str) for value in values)
            for key, values in self.aliases.items()
        ):
            raise ValueError("aliases must map strings to lists of strings")
        if not isinstance(self.backend_api_prefix, str) or not isinstance(self.mongo_receiver, str):
            raise ValueError("backend_api_prefix and mongo_receiver must be strings")
        if not self.mongo_receiver:
            raise ValueError("mongo_receiver must not be empty")
        for name in ("canonical_owners_json", "router_datastore_json"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or Path(value).is_absolute()
                or ":" in value or ".." in PurePosixPath(value.replace("\\", "/")).parts
            ):
                raise ValueError(f"{name} must be a relative path inside the repository")

    @classmethod
    def load(cls, repo: Path, explicit: Path | None = None) -> "Config":
        """Defaults, then `[impact]` from the repository's repolens.toml, then a
        `.impact-tracer.json` (or `explicit`) applied on top of both."""
        config = cls()
        config.apply(load_config(repo).section("impact"))
        path = explicit or repo / ".impact-tracer.json"
        if path.exists():
            config.apply(json.loads(path.read_text(encoding="utf-8")))
        config.validate()
        return config

    def apply(self, raw: dict) -> None:
        """Layer one configuration source over the current values."""
        if not isinstance(raw, dict):
            raise ValueError("impact configuration must be an object")

        def string_list(key: str) -> list[str]:
            value = raw.get(key, [])
            if not isinstance(value, (list, tuple, set, frozenset)) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"{key} must be a list of strings")
            return list(value)

        self.exclude_dirs.update(string_list("exclude_dirs"))
        self.exclude_paths.update(item.strip("/") for item in string_list("exclude_paths"))
        extensions = string_list("extensions")
        if extensions:
            self.extensions = set(extensions)
        if "aliases" in raw:
            if not isinstance(raw["aliases"], dict):
                raise ValueError("aliases must map strings to lists of strings")
            if any(not isinstance(key, str)
                   or not isinstance(values, (list, tuple, set, frozenset))
                   or any(not isinstance(value, str) for value in values)
                   for key, values in raw["aliases"].items()):
                raise ValueError("aliases must map strings to lists of strings")
            self.aliases = {
                key: list(values)
                for key, values in raw["aliases"].items()
            }
        artifacts = raw.get("artifacts", {})
        if not isinstance(artifacts, dict):
            raise ValueError("artifacts must be an object")
        self.canonical_owners_json = artifacts.get("canonical_owners", self.canonical_owners_json)
        self.router_datastore_json = artifacts.get("router_datastore", self.router_datastore_json)
        if "backend_api_prefix" in raw and not isinstance(raw["backend_api_prefix"], str):
            raise ValueError("backend_api_prefix must be a string")
        if "mongo_receiver" in raw and not isinstance(raw["mongo_receiver"], str):
            raise ValueError("mongo_receiver must be a string")
        self.backend_api_prefix = raw.get("backend_api_prefix", self.backend_api_prefix).rstrip("/")

        def integer(key: str, current: int) -> int:
            value = raw.get(key, current)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} must be an integer")
            return value

        self.max_ambiguous_targets = integer("max_ambiguous_targets", self.max_ambiguous_targets)
        self.max_file_bytes = integer("max_file_bytes", self.max_file_bytes)
        self.max_files = integer("max_files", self.max_files)
        for key in ("pg_schemas", "roles", "toggle_calls"):
            if key in raw:
                setattr(self, key, string_list(key))
        if "mongo_receiver" in raw:
            self.mongo_receiver = raw["mongo_receiver"]
