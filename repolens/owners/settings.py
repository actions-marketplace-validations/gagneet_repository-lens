"""Capability-index settings, read from `[owners]` in repolens.toml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import Config, merge

DEFAULTS: dict = {
    "registry": "canonical_owners.yaml",
    "python_roots": ["."],
    "javascript_roots": [],
    "javascript_extensions": [".js", ".jsx", ".ts", ".tsx"],
    # Whole path components; `a/b` is a run of consecutive components.
    "skip_parts": ["venv", ".venv", "__pycache__", "node_modules", ".next", "build", "dist",
                   "alembic/versions"],
    "out_json": ".repolens/canonical_owners.json",
    "out_html": "",
    "out_mindmap": "",
    # A source file declaring the metric ids an entry's `metric_id:` may name, and the
    # pattern that finds them. Empty = no metric_id can be verified, and saying so.
    "metric_registry": "",
    "metric_id_pattern": r'metric_id\s*=\s*"([^"]+)"',
    "title": "Canonical Owner Registry",
    "generator_label": "repolens owners",
    "command": "repolens owners",
}


@dataclass
class OwnerSettings:
    """Resolved `[owners]` settings; paths are absolute under `root`, unset outputs are None."""
    root: Path
    registry: Path
    python_roots: list[str]
    javascript_roots: list[str]
    javascript_extensions: list[str]
    skip_parts: list[str]
    out_json: Path
    out_html: Path | None
    out_mindmap: Path | None
    metric_registry: str
    metric_id_pattern: str
    title: str
    generator_label: str
    command: str

    def rel(self, path: Path) -> str:
        """`path` relative to the root, with forward slashes."""
        return path.relative_to(self.root).as_posix()

    @property
    def outputs(self) -> list[Path]:
        """The configured artefact paths (JSON, then HTML and mindmap when set)."""
        return [p for p in (self.out_json, self.out_html, self.out_mindmap) if p]


def from_config(cfg: Config) -> OwnerSettings:
    """Build `OwnerSettings` from `[owners]`, merged over `DEFAULTS`."""
    d = merge(DEFAULTS, cfg.section("owners"))
    root = cfg.root
    return OwnerSettings(
        root=root,
        registry=root / d["registry"],
        python_roots=list(d["python_roots"]),
        javascript_roots=list(d["javascript_roots"]),
        javascript_extensions=list(d["javascript_extensions"]),
        skip_parts=list(d["skip_parts"]),
        out_json=root / d["out_json"],
        out_html=(root / d["out_html"]) if d["out_html"] else None,
        out_mindmap=(root / d["out_mindmap"]) if d["out_mindmap"] else None,
        metric_registry=d["metric_registry"],
        metric_id_pattern=d["metric_id_pattern"],
        title=d["title"],
        generator_label=d["generator_label"],
        command=d["command"],
    )
