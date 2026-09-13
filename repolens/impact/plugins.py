"""Versioned, explicitly enabled extractors for additional languages and stores.

Plugins are trusted installed Python code. Discovery does not import them; loading
requires a name supplied by the CLI caller, never one taken from the scanned repo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
import json
from pathlib import PurePosixPath
from typing import Protocol

from .model import Edge, Graph, Issue, Node

ENTRY_POINT_GROUP = "repolens.extractors"
API_VERSION = 1
MAX_RECORDS_PER_FILE = 20_000


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    file_id: str


@dataclass
class Extraction:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


class Extractor(Protocol):
    api_version: int
    name: str
    version: str
    extensions: tuple[str, ...]

    def analyze(self, source: SourceFile) -> Extraction: ...


def available() -> list[dict[str, str]]:
    """Show installed entry-point metadata without executing plugin code."""
    return sorted(({
        "name": ep.name, "entry_point": ep.value,
        "distribution": ep.dist.name if ep.dist else "unknown",
        "version": ep.dist.version if ep.dist else "unknown",
    } for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)),
        key=lambda row: (row["name"], row["distribution"]))


def load_extractors(names: list[str]) -> list[Extractor]:
    """Load only the explicitly selected installed entry points; fail on ambiguity."""
    entries = list(metadata.entry_points(group=ENTRY_POINT_GROUP)) if names else []
    loaded = []
    for name in sorted(set(names)):
        matches = [ep for ep in entries if ep.name == name]
        if len(matches) != 1:
            raise ValueError(f"extractor {name!r}: expected one installed entry point, found {len(matches)}")
        plugin = matches[0].load()()
        if getattr(plugin, "api_version", None) != API_VERSION:
            raise ValueError(f"extractor {name!r}: unsupported API version")
        if getattr(plugin, "name", None) != name or not isinstance(getattr(plugin, "version", None), str) or not plugin.version:
            raise ValueError(f"extractor {name!r}: requires a matching name and a version string")
        extensions = getattr(plugin, "extensions", None)
        if (not isinstance(extensions, (list, tuple)) or not extensions
                or any(not isinstance(ext, str) or not ext.startswith(".")
                       or ext != ext.lower() or "/" in ext or "\\" in ext for ext in extensions)):
            raise ValueError(f"extractor {name!r}: extensions must be lowercase suffixes")
        if not callable(getattr(plugin, "analyze", None)):
            raise ValueError(f"extractor {name!r}: missing analyze(source)")
        loaded.append(plugin)
    return loaded


def _valid_path(path: str | None) -> bool:
    if path is None:
        return True
    return (isinstance(path, str) and bool(path) and not PurePosixPath(path).is_absolute()
            and ".." not in PurePosixPath(path).parts and "\\" not in path and ":" not in path
            and not any(ord(char) < 32 for char in path))


def merge_extraction(graph: Graph, result: Extraction, plugin: Extractor) -> None:
    """Validate the entire result before committing it to the shared graph."""
    if not isinstance(result, Extraction):
        raise ValueError("extractor must return Extraction")
    if len(result.nodes) + len(result.edges) + len(result.issues) > MAX_RECORDS_PER_FILE:
        raise ValueError("extractor exceeded the per-file record limit")
    proposed = dict(graph.nodes)
    for node in result.nodes:
        if (not isinstance(node, Node) or not isinstance(node.id, str) or not node.id
                or not isinstance(node.label, str) or not isinstance(node.kind, str)
                or not _valid_path(node.path) or not isinstance(node.metadata, dict)):
            raise ValueError("invalid extractor node or source path")
        try:
            json.dumps(node.metadata)
        except (TypeError, ValueError) as exc:
            raise ValueError("extractor node metadata must be JSON-serializable") from exc
        previous = proposed.get(node.id)
        if previous and (previous.kind, previous.label, previous.path) != (node.kind, node.label, node.path):
            raise ValueError("extractor node ID collides with an existing node")
        proposed[node.id] = node
    for edge in result.edges:
        if (not isinstance(edge, Edge) or edge.source not in proposed or edge.target not in proposed
                or edge.resolution not in {"exact", "high", "probable", "ambiguous", "declared"}
                or not isinstance(edge.kind, str) or not isinstance(edge.evidence, str)
                or not isinstance(edge.origin, str) or (edge.detail is not None and not isinstance(edge.detail, str))):
            raise ValueError("invalid extractor edge, evidence or endpoint")
    for issue in result.issues:
        if (not isinstance(issue, Issue) or issue.severity not in {"info", "warning", "error"}
                or not isinstance(issue.message, str) or not isinstance(issue.evidence, str)
                or not isinstance(issue.recommendation, str) or not isinstance(issue.node_ids, list)
                or any(not isinstance(node_id, str) or node_id not in proposed for node_id in issue.node_ids)):
            raise ValueError("invalid extractor issue")
    # Existing node metadata is retained. An additive extractor cannot rewrite the
    # built-in parser's evidence or scan status by re-emitting its file node.
    for node in result.nodes:
        if node.id not in graph.nodes:
            node.metadata = {**node.metadata, "extractor": plugin.name, "extractor_version": plugin.version}
            graph.add_node(node)
    for edge in result.edges:
        edge.origin = f"plugin:{plugin.name}@{plugin.version}"
        graph.add_edge(edge)
    graph.issues.extend(result.issues)
