"""FeatureTrace settings: generic defaults, overridden by `[featuretrace]` in repolens.toml."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..config import Config, load_config, merge

UNKNOWN = "unknown"
ICON_FALLBACK = "\U0001f4e6"


@dataclass(frozen=True)
class Layer:
    name: str
    fill: str
    text: str
    icon: str
    shape: tuple[str, str]
    description: str


@dataclass(frozen=True)
class StoreKind:
    """How one store field (`Collection:` or `Table:`) is labelled in the maps."""
    short: str       # inside a flowchart node and after a mindmap leaf
    long: str        # the tour's quick-reference row
    json_key: str    # key under `data_stores` in the JSON graph


#: Legend order. The flowchart's class definitions and the index legend follow it.
DEFAULT_LAYERS: tuple[Layer, ...] = (
    Layer("frontend", "#bbf7d0", "#14532d", "\U0001f5a5", ("[", "]"), "UI pages and components"),
    Layer("router", "#bfdbfe", "#1e3a5f", "\U0001f50c", ("[", "]"), "HTTP route handlers"),
    Layer("service", "#fed7aa", "#7c2d12", "⚙️", ("(", ")"), "Business logic services"),
    Layer("domain", "#e9d5ff", "#4c1d95", "\U0001f3db", ("{{", "}}"), "Domain models and rules"),
    Layer("worker", "#fecaca", "#7f1d1d", "⚡", ("([", "])"), "Background workers"),
    Layer("cron", "#fde68a", "#713f12", "⏰", ("([", "])"), "Scheduled jobs"),
    Layer("model", "#a5f3fc", "#164e63", "\U0001f4d0", ("[", "]"), "Data and schema models"),
    Layer("test", "#e5e7eb", "#374151", "\U0001f9ea", ("[", "]"), "Test files"),
    Layer("seed", "#fef9c3", "#854d0e", "\U0001f331", ("[(", ")]"), "Seed and fixture scripts"),
    Layer("migration", "#cbd5e1", "#1e293b", "\U0001f5c3", ("[", "]"), "Schema migrations"),
    Layer("config", "#99f6e4", "#134e4a", "\U0001f527", ("{", "}"), "Configuration and settings files"),
    Layer("docs", "#c7d2fe", "#3730a3", "\U0001f4c4", ("[", "]"), "Documentation files"),
    Layer("script", "#ddd6fe", "#3730a3", "\U0001f4dc", ("[", "]"), "Operator CLI scripts"),
    Layer(UNKNOWN, "#f3f4f6", "#1f2937", ICON_FALLBACK, ("[", "]"),
          "No Layer field — add one for map generation"),
)

DEFAULTS: dict[str, Any] = {
    "scan_dirs": ["."],
    "skip_parts": [".git", ".next", "node_modules", "__pycache__", "venv", ".venv",
                   "dist", "build", "coverage", ".mypy_cache", ".pytest_cache"],
    "extensions": [".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".md", ".html", ".sh"],
    "map_dir": "docs/featuretrace",
    "generator_label": "repolens featuretrace map",
    "command": "repolens featuretrace map",
    "not_ours": [],
    # Entry point -> data, then tests and seeds at the end.
    "flow_order": ["frontend", "router", "service", "domain", "worker", "cron", "migration",
                   "model", "config", "docs", "seed", "script", "test"],
    "layer_descriptions": {},
    "stores": {
        "Collection": {"short": "Collection", "long": "Collections", "json_key": "collections"},
        "Table": {"short": "Table", "long": "Tables", "json_key": "tables"},
    },
    "audit": {
        # Empty = no scope qualifier is required. A multi-tenant repo lists its own.
        "scope_values": [],
        # Empty = any token containing "/" is a repo-relative reference.
        "ref_prefixes": [],
        # Extra roots a reference may be written relative to (e.g. "backend").
        "ref_alt_roots": [],
        "near_top_lines": 10,
        # Files allowed to carry a marker below the top, one per section.
        "section_marker_files": [],
        "baseline": ".repolens/featuretrace_baseline.json",
        "command": "repolens featuretrace audit",
        "standard_doc": "",
        "concept_index_hint": "",
    },
}


@dataclass
class FTSettings:
    root: Path
    scan_dirs: tuple[str, ...]
    skip_parts: frozenset[str]
    extensions: frozenset[str]
    layers: dict[str, Layer]
    flow_order: tuple[str, ...]
    tour_order: tuple[str, ...]
    stores: dict[str, StoreKind]
    map_dir: Path
    generator_label: str
    command: str
    not_ours: frozenset[str]
    scope_values: tuple[str, ...]
    ref_prefixes: tuple[str, ...]
    ref_alt_roots: tuple[str, ...]
    near_top_lines: int
    section_marker_files: frozenset[str]
    baseline: Path
    audit_command: str
    standard_doc: str
    concept_index_hint: str

    def layer(self, name: str) -> Layer:
        return self.layers.get(name) or self.layers[UNKNOWN]

    @property
    def map_dir_rel(self) -> str:
        try:
            return self.map_dir.relative_to(self.root).as_posix()
        except ValueError:
            return self.map_dir.as_posix()


def _build_layers(section: dict[str, Any]) -> dict[str, Layer]:
    defaults = {layer.name: layer for layer in DEFAULT_LAYERS}
    raw = section.get("layers")
    if raw:
        layers: dict[str, Layer] = {}
        for entry in raw:
            name = entry["name"]
            base = defaults.get(name) or Layer(name, "#f3f4f6", "#1f2937", ICON_FALLBACK, ("[", "]"), "")
            layers[name] = Layer(
                name=name,
                fill=entry.get("fill", base.fill),
                text=entry.get("text", base.text),
                icon=entry.get("icon", base.icon),
                shape=tuple(entry.get("shape", base.shape)),  # type: ignore[arg-type]
                description=entry.get("description", base.description),
            )
    else:
        layers = dict(defaults)
    layers.setdefault(UNKNOWN, defaults[UNKNOWN])
    for name, description in section.get("layer_descriptions", {}).items():
        if name in layers:
            layers[name] = replace(layers[name], description=description)
    return layers


def from_config(cfg: Config | None = None) -> FTSettings:
    cfg = cfg if cfg is not None else load_config()
    section = merge(DEFAULTS, cfg.section("featuretrace"))
    audit = section["audit"]
    root = cfg.root
    flow_order = tuple(section["flow_order"])
    return FTSettings(
        root=root,
        scan_dirs=tuple(section["scan_dirs"]),
        skip_parts=frozenset(section["skip_parts"]),
        extensions=frozenset(section["extensions"]),
        layers=_build_layers(section),
        flow_order=flow_order,
        tour_order=tuple(section.get("tour_order") or flow_order),
        stores={
            name: StoreKind(short=v["short"], long=v["long"], json_key=v["json_key"])
            for name, v in section["stores"].items()
        },
        map_dir=root / section["map_dir"],
        generator_label=section["generator_label"],
        command=section["command"],
        not_ours=frozenset(section["not_ours"]),
        scope_values=tuple(audit["scope_values"]),
        ref_prefixes=tuple(audit["ref_prefixes"]),
        ref_alt_roots=tuple(audit["ref_alt_roots"]),
        near_top_lines=int(audit["near_top_lines"]),
        section_marker_files=frozenset(audit["section_marker_files"]),
        baseline=root / audit["baseline"],
        audit_command=audit["command"],
        standard_doc=audit["standard_doc"],
        concept_index_hint=audit["concept_index_hint"],
    )
