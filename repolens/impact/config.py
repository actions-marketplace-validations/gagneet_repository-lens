from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from ..config import load_config

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".impact-tracer", ".next", ".venv", "venv", "node_modules",
    "dist", "build", "coverage", "__pycache__", ".pytest_cache", ".mypy_cache",
}

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".md", ".html", ".sh", ".sql",
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
    # Application vocabulary, empty by default. Which schemas hold tables, which words
    # are roles and which calls gate a feature are facts about ONE application; a
    # generic scanner that guessed them would draw edges nobody declared.
    pg_schemas: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    #: Regex fragments naming a call whose first argument is a feature toggle.
    toggle_calls: list[str] = field(default_factory=list)
    #: `<receiver>.<collection>` outside Python is a document-store reference.
    mongo_receiver: str = "db"

    @classmethod
    def load(cls, repo: Path, explicit: Path | None = None) -> "Config":
        """Defaults, then `[impact]` from the repository's repolens.toml, then a
        `.impact-tracer.json` (or `explicit`) applied on top of both."""
        config = cls()
        config.apply(load_config(repo).section("impact"))
        path = explicit or repo / ".impact-tracer.json"
        if path.exists():
            config.apply(json.loads(path.read_text(encoding="utf-8")))
        return config

    def apply(self, raw: dict) -> None:
        """Layer one configuration source over the current values."""
        self.exclude_dirs.update(raw.get("exclude_dirs", []))
        self.exclude_paths.update(str(item).strip("/") for item in raw.get("exclude_paths", []))
        if raw.get("extensions"):
            self.extensions = set(raw["extensions"])
        if "aliases" in raw:
            self.aliases = {
                str(key): [str(value) for value in values]
                for key, values in raw["aliases"].items()
            }
        artifacts = raw.get("artifacts", {})
        self.canonical_owners_json = artifacts.get("canonical_owners", self.canonical_owners_json)
        self.router_datastore_json = artifacts.get("router_datastore", self.router_datastore_json)
        self.backend_api_prefix = str(raw.get("backend_api_prefix", self.backend_api_prefix)).rstrip("/")
        self.max_ambiguous_targets = int(raw.get("max_ambiguous_targets", self.max_ambiguous_targets))
        self.max_file_bytes = int(raw.get("max_file_bytes", self.max_file_bytes))
        for key in ("pg_schemas", "roles", "toggle_calls"):
            if key in raw:
                setattr(self, key, [str(value) for value in raw[key]])
        if "mongo_receiver" in raw:
            self.mongo_receiver = str(raw["mongo_receiver"])
