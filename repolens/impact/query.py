from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from pathlib import Path
import re

from .config import Config
from .model import Edge, Graph, Issue, Node


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


@dataclass(slots=True)
class Match:
    node_id: str
    score: float
    reasons: list[str] = field(default_factory=list)
    snippets: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImpactResult:
    query: str
    seeds: list[Match]
    nodes: dict[str, Node]
    edges: list[Edge]
    issues: list[Issue]
    classifications: dict[str, str]
    omitted_nodes: int = 0
    omitted_breakdown: list[dict[str, object]] = field(default_factory=list)


# Separators inside an identifier or a path. Splitting on these is what lets a
# human phrase reach a symbol name; NOT splitting on them is why it could not.
_IDENT_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
# aB -> a B, and HTTPServer -> HTTP Server. Frontend components are PascalCase, so
# without this `ExpenditureVolatilityPage` is one opaque token.
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _normalise(value: str) -> str:
    """Lower-case words, with identifiers and paths broken into their parts.

    `TOKEN_RE` includes `_ . / : -` as WORD characters, so it returned
    "backend/services/expenditure_volatility_profile.py" as a single token. Every
    phrase match in `search()` is a substring test against a space-joined string, so
    a multi-word query could never match a snake_case, kebab-case or PascalCase name
    — only free prose.

    The effect was not subtle and it was not a ranking problem. Querying this
    repository for "expenditure volatility" scored the OWNER module
    (`backend/services/expenditure_volatility_profile.py`) at **0** and returned
    `backend/server.py` as the top seed, which won solely because it contains the
    literal prose `tags=["Expenditure Volatility"]` — a space-separated string in a
    router registration. Traversal then faithfully expanded the wrong seed. Fixing
    hub suppression and relevance weighting improved the numbers and could not have
    fixed this, because the right nodes never entered the result at all.
    """
    parts: list[str] = []
    for token in TOKEN_RE.findall(value):
        for piece in _IDENT_SPLIT_RE.split(token):
            if not piece:
                continue
            parts.extend(part.lower() for part in _CAMEL_RE.split(piece) if part)
    return " ".join(parts)


def _metadata_text(node: Node) -> str:
    chunks: list[str] = []
    for value in node.metadata.values():
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, list):
            chunks.extend(str(item) for item in value)
    return " ".join(chunks)


def _expand_aliases(query: str, config: Config) -> set[str]:
    terms = {_normalise(query)}
    normal = _normalise(query)
    for key, aliases in config.aliases.items():
        group = {_normalise(key), *(_normalise(item) for item in aliases)}
        if normal in group or any(normal in item or item in normal for item in group):
            terms.update(group)
    return {item for item in terms if item}


def search(graph: Graph, root: Path, query: str, config: Config, limit: int = 12) -> list[Match]:
    terms = _expand_aliases(query, config)
    tokens = set().union(*(set(term.split()) for term in terms))
    matches: dict[str, Match] = {}

    for node in graph.nodes.values():
        label = _normalise(node.label)
        path = _normalise(node.path or "")
        metadata = _normalise(_metadata_text(node))
        score = 0.0
        reasons: list[str] = []
        for term in terms:
            if term == label:
                score = max(score, 100.0)
                reasons.append("exact label")
            if term == path:
                score = max(score, 98.0)
                reasons.append("exact path")
            if term and term in label:
                score += 28.0
                reasons.append("label contains phrase")
            if term and term in path:
                score += 22.0
                reasons.append("path contains phrase")
            if term and term in metadata:
                score += 16.0
                reasons.append("metadata contains phrase")
        haystack_tokens = set((label + " " + path + " " + metadata).split())
        score += 4.0 * len(tokens & haystack_tokens)
        if score:
            matches[node.id] = Match(node.id, score, sorted(set(reasons)))

    lowered_terms = [term.lower() for term in terms]
    for node in graph.nodes.values():
        if node.kind != "file" or not node.path:
            continue
        path = (root / node.path).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            continue
        if not path.is_file() or path.stat().st_size > config.max_file_bytes:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        snippets: list[str] = []
        exact_hits = 0
        token_hits = 0
        for number, line in enumerate(lines, start=1):
            lowered = line.lower()
            if any(term in lowered for term in lowered_terms):
                exact_hits += 1
                if len(snippets) < 3:
                    safe = re.sub(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=<redacted>", line.strip())
                    snippets.append(f"{node.path}:{number}: {safe[:220]}")
            token_hits += len(tokens & set(_normalise(line).split()))
        if exact_hits or token_hits:
            entry = matches.setdefault(node.id, Match(node.id, 0.0))
            entry.score += min(36.0, exact_hits * 8.0) + min(12.0, token_hits * 0.2)
            entry.reasons.append("source text match")
            entry.snippets.extend(snippets)

    return sorted(matches.values(), key=lambda item: (-item.score, graph.nodes[item.node_id].label))[:limit]


# ─── Relevance weights ────────────────────────────────────────────────────────
#
# Traversal was a plain FIFO BFS whose per-node neighbour sort fell through to the
# node LABEL. That is truncation, not ranking: once a hub file is dequeued its
# hundreds of CONTAINS neighbours flood the budget in alphabetical order, so a query
# for "expenditure volatility" returned `AGMCreate`, `AmenityBookingCreate`,
# `AnnualBudgetCreate`… and omitted 830 nodes including the four files that mattered.
#
# Cost is accumulated along the path and expanded best-first, so a two-hop policy
# edge outranks a one-hop containment edge. Lower is better.
EDGE_COST: dict[str, int] = {
    # Declared policy — somebody wrote down that these move together.
    "OWNS": 0, "OWNED_SYMBOL": 0, "CONSUMES": 0, "DECLARES_CONCEPT": 1,
    # An HTTP call and the handler that serves it.
    "CALLS_API": 1, "HANDLES_API": 1,
    # Direct import, or a call resolved to exactly one definition.
    "IMPORTS": 1, "CALLS": 2,
    # Contract and data relationships.
    "TOUCHES_STORE": 3, "IMPLEMENTED_BY": 3, "GUARDED_BY": 3,
    # A FeatureTrace `Related:` line — declared, but by convention, not by policy.
    "RELATED_TO": 3, "VERIFIED_BY": 3,
    # Containment says only "same file". On a 19k-line file that is nearly no
    # information at all, which is why it costs more than any real relationship.
    "CONTAINS": 8,
    # Advisory only. Never promoted into a review action by traversal alone.
    "STRUCTURALLY_SIMILAR": 20,
}
DEFAULT_EDGE_COST = 6

# A resolution that could be wrong costs more than one that cannot.
RESOLUTION_SURCHARGE: dict[str, int] = {
    "exact": 0, "declared": 0, "framework_path": 1,
    "syntax": 2, "regex": 3, "heuristic": 5, "ambiguous": 8, "structural": 12,
}

ORIGIN_SURCHARGE: dict[str, int] = {
    "policy": 0, "policy+ast": 0, "ast": 0, "framework_path": 1,
    "name_resolution": 2, "syntax": 2, "regex": 3, "heuristic": 5,
}

# A file holding more than this many symbols is a HUB. `server.py` holds ~1,700.
# Traversal will not walk INTO a hub's contents unless the hub is the explicit query,
# because "these two functions live in the same enormous file" is not impact.
HUB_CONTAINS_THRESHOLD = 60

# No single file may supply more than this share of a bounded result — unless the
# query names it. Without the cap, one hub still crowds out every other layer even
# when it is correctly ranked last.
MAX_SINGLE_FILE_SHARE = 0.25

# The result budget is also diversified across layers so one of them cannot consume
# everything. Anything not listed shares the remainder.
LAYER_SHARE: dict[str, float] = {
    "symbol": 0.45, "file": 0.30, "endpoint": 0.15, "page": 0.15,
    "concept": 0.15, "policy": 0.10, "mongo_collection": 0.10, "postgres_table": 0.10,
}


def _edge_cost(edge: Edge) -> int:
    return (
        EDGE_COST.get(edge.kind, DEFAULT_EDGE_COST)
        + RESOLUTION_SURCHARGE.get(edge.resolution, 4)
        + ORIGIN_SURCHARGE.get(edge.origin, 3)
    )


def _node_class(distance: int, edge: Edge | None) -> str:
    if distance == 0:
        return "query match"
    if edge and edge.origin in {"policy", "policy+ast"}:
        return "required review"
    if edge and edge.resolution == "exact" and distance == 1:
        return "required review"
    if edge and edge.kind == "STRUCTURALLY_SIMILAR":
        return "similar candidate"
    if edge and edge.resolution in {"exact", "declared"}:
        return "review recommended"
    return "similar candidate"


def _hub_files(graph: Graph) -> dict[str, int]:
    """File nodes whose CONTAINS degree makes walking into them uninformative."""
    counts: dict[str, int] = {}
    for edge in graph.edges:
        if edge.kind == "CONTAINS":
            counts[edge.source] = counts.get(edge.source, 0) + 1
    return {node: n for node, n in counts.items() if n > HUB_CONTAINS_THRESHOLD}


def impact(
    graph: Graph,
    root: Path,
    query: str,
    config: Config,
    depth: int = 2,
    max_nodes: int = 40,
    seed_limit: int = 8,
) -> ImpactResult:
    seeds = search(graph, root, query, config, limit=seed_limit)
    selected: dict[str, Node] = {}
    classifications: dict[str, str] = {}
    best_cost: dict[str, int] = {}
    seen_distance: dict[str, int] = {}

    seed_ids = {seed.node_id for seed in seeds}
    hubs = _hub_files(graph)
    # A hub the caller explicitly asked about is expanded normally; that IS the query.
    expandable_hubs = seed_ids & set(hubs)

    heap: list[tuple[int, int, str, int]] = []
    counter = 0
    for seed in seeds:
        selected[seed.node_id] = graph.nodes[seed.node_id]
        classifications[seed.node_id] = "query match"
        seen_distance[seed.node_id] = 0
        best_cost[seed.node_id] = 0
        heapq.heappush(heap, (0, counter, seed.node_id, 0))
        counter += 1

    adjacency: dict[str, list[tuple[str, Edge]]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source, []).append((edge.target, edge))
        adjacency.setdefault(edge.target, []).append((edge.source, edge))

    # Budgets. A seed never counts against a cap — refusing to show what was asked for
    # would be worse than any crowding it causes.
    per_file_cap = max(1, int(max_nodes * MAX_SINGLE_FILE_SHARE))
    file_used: dict[str, int] = {}
    layer_used: dict[str, int] = {}
    omitted: list[dict[str, str]] = []

    def _file_of(node: Node) -> str:
        return node.path or node.label

    while heap:
        cost, _, node_id, distance = heapq.heappop(heap)
        if cost > best_cost.get(node_id, cost):
            continue
        if distance >= depth:
            continue
        for neighbour, edge in adjacency.get(node_id, []):
            # Hub suppression: do not walk a huge file's contents unless it is the query.
            if (
                edge.kind == "CONTAINS"
                and node_id in hubs
                and node_id not in expandable_hubs
            ):
                omitted.append({
                    "file": graph.nodes[node_id].label,
                    "type": graph.nodes[neighbour].kind,
                    "relationship": "CONTAINS",
                    "reason": "hub file collapsed",
                })
                continue

            next_cost = cost + _edge_cost(edge)
            next_distance = distance + 1
            if neighbour in best_cost and best_cost[neighbour] <= next_cost:
                continue
            if neighbour not in selected:
                node = graph.nodes[neighbour]
                owner = _file_of(node)
                layer_cap = max(1, int(max_nodes * LAYER_SHARE.get(node.kind, 0.20)))
                if len(selected) >= max_nodes:
                    omitted.append({
                        "file": owner, "type": node.kind,
                        "relationship": edge.kind, "reason": "node budget reached",
                    })
                    continue
                if owner not in seed_ids and file_used.get(owner, 0) >= per_file_cap:
                    omitted.append({
                        "file": owner, "type": node.kind,
                        "relationship": edge.kind, "reason": "per-file share cap",
                    })
                    continue
                if layer_used.get(node.kind, 0) >= layer_cap:
                    omitted.append({
                        "file": owner, "type": node.kind,
                        "relationship": edge.kind, "reason": "per-layer share cap",
                    })
                    continue
                file_used[owner] = file_used.get(owner, 0) + 1
                layer_used[node.kind] = layer_used.get(node.kind, 0) + 1
                selected[neighbour] = node
                classifications[neighbour] = _node_class(next_distance, edge)

            best_cost[neighbour] = next_cost
            seen_distance[neighbour] = min(seen_distance.get(neighbour, next_distance), next_distance)
            counter += 1
            heapq.heappush(heap, (next_cost, counter, neighbour, next_distance))

    selected_edges = [
        edge for edge in graph.edges
        if edge.source in selected and edge.target in selected
    ]
    selected_issues = [issue for issue in graph.issues if _issue_is_about(issue, selected)]
    return ImpactResult(
        query=query,
        seeds=seeds,
        nodes=selected,
        edges=selected_edges,
        issues=selected_issues,
        classifications=classifications,
        omitted_nodes=len(omitted),
        omitted_breakdown=_group_omissions(omitted),
    )


def _group_omissions(omitted: list[dict[str, str]]) -> list[dict[str, object]]:
    """Grouped by file, node type and relationship — never an alphabetical cutoff.

    "830 omitted" says only that the answer is incomplete. "812 symbols contained by
    backend/server.py, collapsed as a hub" says the omission was deliberate and that
    nothing was lost.
    """
    buckets: dict[tuple[str, str, str, str], int] = {}
    for item in omitted:
        key = (item["file"], item["type"], item["relationship"], item["reason"])
        buckets[key] = buckets.get(key, 0) + 1
    grouped = [
        {"file": f, "type": t, "relationship": r, "reason": why, "count": n}
        for (f, t, r, why), n in buckets.items()
    ]
    grouped.sort(key=lambda row: (-row["count"], row["file"]))
    return grouped


def _issue_is_about(issue: Issue, selected: dict[str, Node]) -> bool:
    """Is this issue ABOUT something in the result, or does it merely mention it?

    Two filters were wrong before this, in opposite directions.

    An issue with NO node attached used to be included unconditionally, so every query
    inherited every global finding — 5,320 "relevant" issues against a repository total
    of 28,755.

    Requiring merely that ANY attached node be selected is barely better, and on a path
    query it was not better at all: `AMBIGUOUS_CALL` attaches `[call_site, *up_to_six_
    candidate_targets]`, so an issue counted as relevant whenever ONE OF SIX GUESSES
    happened to land in the result. Querying `monte_carlo_engine.py` still reported
    5,315 issues that way.

    The SUBJECT of an issue is its first node — the call site, the handler, the file
    that owns the problem. A candidate target is evidence about the subject, not a
    second subject. So: the subject must be selected. Issues carrying one or two nodes
    keep the looser test, because for those there is no distinction to draw.
    """
    if not issue.node_ids:
        return False
    if len(issue.node_ids) <= 2:
        return any(node_id in selected for node_id in issue.node_ids)
    return issue.node_ids[0] in selected
