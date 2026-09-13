from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import json
import re

from .model import Edge, Node
from .query import ImpactResult


KIND_ORDER = {
    "concept": 0, "page": 1, "file": 2, "symbol": 3, "endpoint": 4,
    "mongo_collection": 5, "postgres_table": 5, "policy": 6,
}

SHAPES = {
    "concept": ('(["', '"])'),
    "page": ('["', '"]'),
    "file": ('["', '"]'),
    "symbol": ('("', '")'),
    "endpoint": ('{{"', '"}}'),
    "mongo_collection": ('[("', '")]'),
    "postgres_table": ('[("', '")]'),
    "policy": ('["', '"]'),
}


def _safe_label(value: str) -> str:
    # Keep repository-controlled labels inside Mermaid string literals. Escape
    # HTML, pipes and delimiters with Mermaid's decimal entity notation.
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))[:100]
    return "".join(f"#{ord(char)};" if char in '#"<>|`{}[]\\%' else char for char in value)


def _mermaid_id(node_id: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def candidates(result: ImpactResult) -> set[str]:
    """Nodes this result reaches ONLY through an ambiguous call edge.

    A call to a name with several definitions is drawn to every one of them, and only
    one can be the real target. Rendered like a resolved node, each read as a confirmed
    dependency. Walking out from the matches over every other edge finds what is
    firmly linked; whatever that walk misses — the guessed definition, and the file it
    brought in with it — is marked, so a reader knows which boxes are guesses."""
    firm: dict[str, set[str]] = {}
    touched: set[str] = set()
    for edge in result.edges:
        touched.update((edge.source, edge.target))
        if edge.kind == "CALLS" and edge.resolution == "ambiguous":
            continue
        firm.setdefault(edge.source, set()).add(edge.target)
        firm.setdefault(edge.target, set()).add(edge.source)
    reached = {m.node_id for m in result.seeds if m.node_id in result.nodes}
    if not reached:
        return set()
    stack = list(reached)
    while stack:
        for nxt in firm.get(stack.pop(), ()):
            if nxt not in reached:
                reached.add(nxt)
                stack.append(nxt)
    return {node_id for node_id in result.nodes if node_id in touched and node_id not in reached}


def render_mermaid(result: ImpactResult) -> str:
    lines = ["flowchart TD"]
    guesses = candidates(result)
    for node in sorted(result.nodes.values(), key=lambda item: (KIND_ORDER.get(item.kind, 9), item.label, item.id)):
        prefix, suffix = SHAPES.get(node.kind, ('["', '"]'))
        marker = "candidate " if node.id in guesses else ""
        label = _safe_label(f"{marker}{node.kind}: {node.label}")
        lines.append(f"    {_mermaid_id(node.id)}{prefix}{label}{suffix}")
    for edge in sorted(result.edges, key=lambda item: (item.source, item.target, item.kind, item.evidence)):
        label = _safe_label(f"{edge.kind} · {edge.resolution}")
        if edge.resolution == "ambiguous" or edge.origin == "heuristic":
            connector = f"-. {label} .->"
        elif edge.resolution == "declared":
            connector = f"-. {label} .->"
        else:
            connector = f"-->|{label}|"
        lines.append(f"    {_mermaid_id(edge.source)} {connector} {_mermaid_id(edge.target)}")
    if guesses:
        lines.append("    classDef candidate stroke-dasharray:4 3")
        lines.append(f"    class {','.join(sorted(_mermaid_id(n) for n in guesses))} candidate")
    return "\n".join(lines) + "\n"


def render_markdown(result: ImpactResult) -> str:
    counts = Counter(result.classifications.values())
    lines = [
        f"# Impact trace: `{result.query}`",
        "",
        "## Summary",
        "",
        f"- Query matches: {counts.get('query match', 0)}",
        f"- Required reviews: {counts.get('required review', 0)}",
        f"- Recommended reviews: {counts.get('review recommended', 0)}",
        f"- Similar candidates: {counts.get('similar candidate', 0)}",
        f"- Relevant issues: {len(result.issues)}",
        f"- Omitted by graph limit: {result.omitted_nodes}" + (" (grouped below)" if result.omitted_breakdown else ""),
        "",
        "No discovered linkage means only that the scanner found no supported evidence; it does not prove a component is unaffected.",
        "",
        "## Linkage diagram",
        "",
        "```mermaid",
        render_mermaid(result).rstrip(),
        "```",
        "",
        "## Matched entry points",
        "",
        "| Match | Kind | Location | Score | Evidence |",
        "|---|---|---|---:|---|",
    ]
    for match in result.seeds:
        node = result.nodes.get(match.node_id)
        if not node:
            continue
        location = node.path or "—"
        if node.line:
            location += f":{node.line}"
        evidence = "; ".join(match.reasons + match.snippets[:1]).replace("|", "\\|")
        lines.append(f"| `{node.label}` | {node.kind} | `{location}` | {match.score:.1f} | {evidence} |")

    lines.extend([
        "", "## Review list", "",
        "| Action | Item | Kind | Location |",
        "|---|---|---|---|",
    ])
    guesses = candidates(result)
    for node_id, node in sorted(
        result.nodes.items(),
        key=lambda item: (
            {"query match": 0, "required review": 1, "review recommended": 2, "similar candidate": 3}.get(result.classifications[item[0]], 9),
            KIND_ORDER.get(item[1].kind, 9), item[1].label,
        ),
    ):
        location = node.path or "—"
        if node.line:
            location += f":{node.line}"
        action = result.classifications[node_id]
        if node_id in guesses:
            action += " (candidate: ambiguous name, may not be the real target)"
        lines.append(f"| {action} | `{node.label}` | {node.kind} | `{location}` |")

    lines.extend(["", "## Evidence edges", "", "| From | Relationship | To | Origin | Resolution | Evidence |", "|---|---|---|---|---|---|"])
    for edge in sorted(result.edges, key=lambda item: (item.kind, item.source, item.target)):
        source = result.nodes[edge.source].label
        target = result.nodes[edge.target].label
        evidence = edge.evidence.replace("|", "\\|")
        lines.append(f"| `{source}` | {edge.kind} | `{target}` | {edge.origin} | {edge.resolution} | `{evidence}` |")

    if result.omitted_breakdown:
        lines.extend([
            "", "## What was left out, and why", "",
            "Grouped rather than listed. An alphabetical cutoff tells you the answer is",
            "incomplete; this tells you the omission was deliberate and what it covered.",
            "", "| Count | File | Type | Relationship | Reason |", "|---|---|---|---|---|",
        ])
        for row in result.omitted_breakdown[:15]:
            lines.append(
                f"| {row['count']} | `{row['file']}` | {row['type']} | "
                f"{row['relationship']} | {row['reason']} |"
            )
        if len(result.omitted_breakdown) > 15:
            lines.append(f"| … | _{len(result.omitted_breakdown) - 15} more groups_ | | | |")

    lines.extend(["", "## Issues and uncertainty", ""])
    if not result.issues:
        lines.append("No scanner issue intersects this bounded result.")
    else:
        # Issues are GROUPED by code, and ambiguous calls additionally by the
        # unresolved NAME. Emitting one section per possible edge produced 25,400
        # AMBIGUOUS_CALL entries repository-wide and thousands per query — a volume
        # that is not read, so the genuinely actionable codes beneath it were not
        # read either.
        by_code: dict[str, list] = {}
        for issue in result.issues:
            by_code.setdefault(issue.code, []).append(issue)
        severity_rank = {"error": 0, "warning": 1, "info": 2}
        for code in sorted(by_code, key=lambda c: (
            severity_rank.get(by_code[c][0].severity, 3), -len(by_code[c]), c
        )):
            issues = by_code[code]
            first = issues[0]
            lines.extend([
                f"### {first.severity.upper()}: {code} ({len(issues)} in this result)", "",
                first.message, "",
                f"Recommended action: {first.recommendation}", "",
            ])
            if code == "AMBIGUOUS_CALL":
                # Grouped by the called NAME. The evidence is a call site, and listing
                # call sites under this heading presented locations as if they were names.
                names: dict[str, int] = {}
                for issue in issues:
                    label = (issue.subject or issue.evidence or "").strip() or "unknown"
                    names[label] = names.get(label, 0) + 1
                lines.append("Unresolved names, with how many calling functions each covers:")
                lines.append("")
                for label, count in sorted(names.items(), key=lambda kv: (-kv[1], kv[0]))[:10]:
                    lines.append(f"- `{label}` — {count} caller(s)")
                if len(names) > 10:
                    lines.append(f"- _{len(names) - 10} more unresolved names_")
                lines.append("")
            else:
                for issue in issues[:5]:
                    lines.append(f"- `{issue.evidence}`")
                if len(issues) > 5:
                    lines.append(f"- _{len(issues) - 5} more_")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ImpactResult) -> str:
    payload = {
        "query": result.query,
        "seeds": [asdict(match) for match in result.seeds],
        "nodes": [asdict(node) for node in result.nodes.values()],
        "edges": [asdict(edge) for edge in result.edges],
        "issues": [asdict(issue) for issue in result.issues],
        "classifications": result.classifications,
        "omitted_nodes": result.omitted_nodes,
        "omitted_breakdown": result.omitted_breakdown,
    }
    return json.dumps(payload, indent=2, default=str) + "\n"
