"""Render an `ImpactResult` as Mermaid, Markdown or JSON, with repository text escaped."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import json
import re

from .model import Graph
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


STORE_KINDS = frozenset({"postgres_table", "mongo_collection"})
#: `omitted_breakdown` reason for regex-only stores kept out of the default map.
UNVERIFIED_REASON = "unverified: regex match only"


def unverified_stores(graph: Graph) -> set[str]:
    """Store nodes whose every relationship comes from a regex match.

    A regex sees `billing.summary` in a test's route key or `patch("routers.billing.db")`
    as easily as in a query, so a store nothing else confirms (a parsed statement, an
    ORM model, a driver call, a declared artifact) is a lead, not a table. Derived
    from the edges, because a later file can confirm a store an earlier regex made."""
    stores = {node_id for node_id, node in graph.nodes.items() if node.kind in STORE_KINDS}
    seen: set[str] = set()
    confirmed: set[str] = set()
    for edge in graph.edges:
        for endpoint in (edge.source, edge.target):
            if endpoint in stores:
                seen.add(endpoint)
                if edge.origin != "regex":
                    confirmed.add(endpoint)
    return seen - confirmed


def mark_unverified_stores(graph: Graph) -> None:
    """Set `metadata["unverified"]` on regex-only stores and clear it from stores a
    non-regex edge confirmed. Idempotent; run once after every scan pass. A store with
    no regex edge keeps whatever its producer said (a generated artifact's unvalidated
    name stays unverified)."""
    regex_only = unverified_stores(graph)
    regex_touched = {endpoint for edge in graph.edges if edge.origin == "regex"
                     for endpoint in (edge.source, edge.target)}
    for node_id in regex_touched:
        node = graph.nodes.get(node_id)
        if node is None or node.kind not in STORE_KINDS:
            continue
        if node_id in regex_only:
            node.metadata["unverified"] = True
        else:
            node.metadata.pop("unverified", None)


def _safe_label(value: str) -> str:
    # Keep repository-controlled labels inside Mermaid string literals. Escape
    # HTML, pipes and delimiters with Mermaid's decimal entity notation.
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))[:100]
    return "".join(f"#{ord(char)};" if char in '#"<>|`{}[]\\%' else char for char in value)


def markdown_inline(value: object) -> str:
    """Repository text on one Markdown line, safe inside a backtick code span.

    Labels, paths, evidence and queries come from the scanned repository. A newline
    starts a new block (a heading, a fence) and a backtick closes the code span."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).replace("`", "'")


def markdown_cell(value: object, *, code: bool = False) -> str:
    """Repository text inside one Markdown table cell.

    A table named `"a|b`c"` split its row into extra columns and closed the code span
    around it. Backslashes are doubled first so that text ending in `\\` cannot turn the
    `\\|` escape back into a column separator. Outside a code span `<`/`>` are entities
    so a label cannot become HTML; inside one they are already literal."""
    text = markdown_inline(value).replace("\\", "\\\\").replace("|", "\\|")
    if code:
        return f"`{text}`"
    return text.replace("<", "&lt;").replace(">", "&gt;")


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
    """A Mermaid flowchart of the result, with labels escaped against injection.

    Ambiguous, heuristic and declared edges are dashed; candidate and unverified nodes
    say so in their labels; regex-only stores left out are counted in a note node."""
    lines = ["flowchart TD"]
    guesses = candidates(result)
    for node in sorted(result.nodes.values(), key=lambda item: (KIND_ORDER.get(item.kind, 9), item.label, item.id)):
        prefix, suffix = SHAPES.get(node.kind, ('["', '"]'))
        marker = "candidate " if node.id in guesses else ""
        if node.kind in STORE_KINDS and node.metadata.get("unverified"):
            marker += "unverified "
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
    left_out = Counter()
    for row in result.omitted_breakdown:
        if row.get("reason") == UNVERIFIED_REASON:
            left_out[str(row.get("type"))] += int(row.get("count", 0))
    if left_out:
        # Said inside the map, not only beside it: the .mmd file travels on its own.
        what = ", ".join(f"{count} {kind}" for kind, count in sorted(left_out.items()))
        lines.append(f'    unverified_note["{_safe_label(f"Left out, regex-only (unverified): {what}")}"]')
        lines.append("    classDef note stroke-dasharray:4 3")
        lines.append("    class unverified_note note")
    return "\n".join(lines) + "\n"


def render_markdown(result: ImpactResult) -> str:
    """The impact report as Markdown: summary, diagram, matches, review list, evidence
    edges, grouped omissions and issues grouped by code."""
    counts = Counter(result.classifications.values())
    lines = [
        f"# Impact trace: `{markdown_inline(result.query)}`",
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
        evidence = "; ".join(match.reasons + match.snippets[:1])
        lines.append(f"| {markdown_cell(node.label, code=True)} | {markdown_cell(node.kind)} | "
                     f"{markdown_cell(location, code=True)} | {match.score:.1f} | {markdown_cell(evidence)} |")

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
        lines.append(f"| {markdown_cell(action)} | {markdown_cell(node.label, code=True)} | "
                     f"{markdown_cell(node.kind)} | {markdown_cell(location, code=True)} |")

    lines.extend(["", "## Evidence edges", "", "| From | Relationship | To | Origin | Resolution | Evidence |", "|---|---|---|---|---|---|"])
    for edge in sorted(result.edges, key=lambda item: (item.kind, item.source, item.target)):
        source = result.nodes[edge.source].label
        target = result.nodes[edge.target].label
        lines.append(f"| {markdown_cell(source, code=True)} | {markdown_cell(edge.kind)} | {markdown_cell(target, code=True)} | "
                     f"{markdown_cell(edge.origin)} | {markdown_cell(edge.resolution)} | {markdown_cell(edge.evidence, code=True)} |")

    if result.omitted_breakdown:
        lines.extend([
            "", "## What was left out, and why", "",
            "Grouped rather than listed. An alphabetical cutoff tells you the answer is",
            "incomplete; this tells you the omission was deliberate and what it covered.",
            "", "| Count | File | Type | Relationship | Reason |", "|---|---|---|---|---|",
        ])
        for row in result.omitted_breakdown[:15]:
            lines.append(
                f"| {row['count']} | {markdown_cell(row['file'], code=True)} | {markdown_cell(row['type'])} | "
                f"{markdown_cell(row['relationship'])} | {markdown_cell(row['reason'])} |"
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
                f"### {markdown_inline(first.severity.upper())}: {markdown_inline(code)} ({len(issues)} in this result)", "",
                markdown_inline(first.message), "",
                f"Recommended action: {markdown_inline(first.recommendation)}", "",
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
                    lines.append(f"- `{markdown_inline(label)}` — {count} caller(s)")
                if len(names) > 10:
                    lines.append(f"- _{len(names) - 10} more unresolved names_")
                lines.append("")
            else:
                for issue in issues[:5]:
                    lines.append(f"- `{markdown_inline(issue.evidence)}`")
                if len(issues) > 5:
                    lines.append(f"- _{len(issues) - 5} more_")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ImpactResult) -> str:
    """The whole result as indented JSON: seeds, nodes, edges, issues, classifications and omissions."""
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
