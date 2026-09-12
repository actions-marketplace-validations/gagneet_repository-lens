from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class Node:
    id: str
    kind: str
    label: str
    path: str | None = None
    line: int | None = None
    language: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Edge:
    source: str
    target: str
    kind: str
    resolution: str
    evidence: str
    origin: str = "static"
    direct: bool = True
    activation: str = "static"
    detail: str | None = None

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.source, self.target, self.kind, self.evidence


@dataclass(slots=True)
class Issue:
    code: str
    severity: str
    message: str
    node_ids: list[str]
    evidence: str
    recommendation: str
    # What the issue is ABOUT, when that is not the evidence. For AMBIGUOUS_CALL the
    # evidence is a call site (path:line) and the subject is the called name.
    subject: str = ""


@dataclass(slots=True)
class Graph:
    root: str
    version: int = 1
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    _edge_keys: set[tuple[str, str, str, str]] = field(default_factory=set, repr=False)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if not existing.path and node.path:
            existing.path = node.path
        if not existing.line and node.line:
            existing.line = node.line
        if not existing.language and node.language:
            existing.language = node.language
        existing.metadata.update(node.metadata)
        return existing

    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError(f"edge refers to missing node: {edge.source} -> {edge.target}")
        if edge.key not in self._edge_keys:
            self.edges.append(edge)
            self._edge_keys.add(edge.key)

    def incoming(self, node_id: str) -> Iterable[Edge]:
        return (edge for edge in self.edges if edge.target == node_id)

    def outgoing(self, node_id: str) -> Iterable[Edge]:
        return (edge for edge in self.edges if edge.source == node_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "root": self.root,
            "metadata": self.metadata,
            "nodes": [asdict(self.nodes[key]) for key in sorted(self.nodes)],
            "edges": [asdict(edge) for edge in sorted(
                self.edges,
                key=lambda item: (item.source, item.target, item.kind, item.evidence),
            )],
            "issues": [asdict(issue) for issue in self.issues],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Graph":
        graph = cls(
            root=payload["root"],
            version=int(payload.get("version", 1)),
            metadata=dict(payload.get("metadata", {})),
        )
        for raw in payload.get("nodes", []):
            graph.add_node(Node(**raw))
        for raw in payload.get("edges", []):
            graph.add_edge(Edge(**raw))
        graph.issues = [Issue(**raw) for raw in payload.get("issues", [])]
        return graph

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "Graph":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


def stable_id(kind: str, value: str) -> str:
    digest = hashlib.sha1(f"{kind}:{value}".encode("utf-8")).hexdigest()[:14]
    return f"{kind}:{digest}"
