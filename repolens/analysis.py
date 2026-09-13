"""Shared, read-only stack analysis for the CLI and local HTTP API."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, replace
import json
from pathlib import Path

from . import __version__
from .config import load_config
from .core.findings import Finding, ToolRun, sort_key, to_sarif
from .core import javascript
from .impact.config import Config
from .impact.model import Graph
from .impact.plugins import available, load_extractors
from .impact.query import ImpactResult, impact
from .impact.render import render_mermaid
from .impact.scanner import scan_repository
from .report.sarif import import_sarif

LIMITS = [
    "Static syntax and declared relationships do not prove runtime calls, authorization or business behavior.",
    "JavaScript/TypeScript call targets have no compiler type resolution; dynamic imports, wrappers and re-exports may remain unresolved.",
    "Next.js App Router HTTP handlers are supported; Pages Router, rewrites, middleware and server-action authorization need further adapters.",
    "FastAPI static router includes are supported; factories and runtime registration can remain unresolved.",
    "PostgreSQL references are parsed from literal SQL; no database connection, live schema, RLS enforcement or query-plan validation is performed.",
    "Built-in security/performance findings cover Python and Alembic. JS/TS security coverage requires imported SARIF from a separate analyzer.",
    "This local process is not a sandbox for hostile repositories or plugins. Target builds, installs and configured commands are not run.",
]


@dataclass
class Analysis:
    graph: Graph
    runs: list[ToolRun]
    config: Config

    @property
    def complete(self) -> bool:
        # Completeness means the requested supported analysis finished, not that
        # every behavior/language has been understood or that the code is safe.
        incomplete = {"FILE_SKIPPED", "FILE_SCAN_FAILED", "FILE_TOO_DEEPLY_NESTED", "SCAN_FILE_LIMIT",
                      "PYTHON_PARSE_ERROR", "JAVASCRIPT_PARSE_ERROR", "JAVASCRIPT_PARSER_UNAVAILABLE",
                      "SQL_PARSER_UNAVAILABLE", "SQL_PARSE_ERROR", "EXTRACTOR_FAILED", "IMPORT_CONFIG_ERROR",
                      "ARTIFACT_SCAN_FAILED", "ARTIFACT_PATH_OUTSIDE_ROOT",
                      "BAD_CANONICAL_OWNER_ARTIFACT", "BAD_ROUTER_DATASTORE_ARTIFACT",
                      "SQL_UNSUPPORTED_STATEMENT",
                      "UNRESOLVED_LOCAL_IMPORT", "UNRESOLVED_ROUTER_MOUNT", "ROUTER_MOUNT_CYCLE"}
        return not any(r.error or r.skipped for r in self.runs) and not any(i.code in incomplete for i in self.graph.issues)

    def to_dict(self) -> dict:
        graph = self.graph.to_dict()
        graph["root"] = Path(self.graph.root).name  # export no host filesystem prefix
        return {"schema_version": "1.0", "tool_version": __version__, "complete": self.complete,
                "scope": "static working-tree analysis", "limits": LIMITS,
                "coverage": dict(Counter(node.language or "unknown" for node in self.graph.nodes.values() if node.kind == "file")),
                "graph": graph,
                "tools": [{"tool": run.tool, "error": run.error, "skipped": run.skipped,
                           "finding_count": len(run.findings)} for run in self.runs],
                "findings": [finding.to_dict() for finding in sorted(
                    (f for run in self.runs for f in run.findings), key=sort_key)]}

    def view(self, query: str = "", max_nodes: int = 30) -> ImpactResult:
        if not 1 <= max_nodes <= 100:
            raise ValueError("max_nodes must be between 1 and 100")
        if query:
            # Use only the stored graph. API queries must never re-read a newer
            # working tree and mix its snippets with an older scan's relationships.
            return impact(self.graph, Path(self.graph.root), query, self.config,
                          max_nodes=max_nodes, depth=2, search_source=False)
        degree = Counter(endpoint for edge in self.graph.edges for endpoint in (edge.source, edge.target))
        ordered = sorted(self.graph.nodes.values(), key=lambda n: (
            0 if n.kind in {"endpoint", "postgres_table", "concept"} else 1,
            -degree[n.id], n.path or "", n.label, n.id))
        nodes = {n.id: n for n in ordered[:max_nodes]}
        edges = [e for e in self.graph.edges if e.source in nodes and e.target in nodes]
        return ImpactResult("Repository overview", [], nodes, edges, self.graph.issues, {},
                            max(0, len(ordered) - len(nodes)))

    def markdown(self, query: str = "", max_nodes: int = 30) -> str:
        payload = self.to_dict()
        view = self.view(query, max_nodes)
        def cell(value) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")
        lines = ["# Repository Lens analysis", "",
                 f"Repository: {cell(Path(self.graph.root).name)}. Supported analysis complete: {self.complete}.", "",
                 f"{len(self.graph.nodes)} nodes, {len(self.graph.edges)} relationships, "
                 f"{len(self.graph.issues)} analysis diagnostics, {len(payload['findings'])} findings.", "",
                 "## Linkage map", "", "```mermaid", render_mermaid(view).rstrip(), "```", "",
                 f"Diagram omits {view.omitted_nodes} nodes. Use --query to inspect one feature or module.", "",
                 "## Findings", "", "| Priority | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in payload["findings"]:
            lines.append("| " + " | ".join(cell(f[k]) for k in ("priority", "rule", "location", "message")) + " |")
        if not payload["findings"]:
            lines.append("| — | — | — | No findings from the checks that ran. |")
        lines += ["", "## Analysis diagnostics", "", "| Level | Code | Evidence | Action |", "|---|---|---|---|"]
        for issue in self.graph.issues:
            lines.append("| " + " | ".join(cell(value) for value in (issue.severity, issue.code, issue.evidence, issue.recommendation)) + " |")
        for run in self.runs:
            if run.error:
                lines += ["", f"Tool error ({cell(run.tool)}): {cell(run.error)}"]
        lines += ["", "## Coverage and limits", "", *[f"- {limit}" for limit in LIMITS], ""]
        return "\n".join(lines)


def analyze(root: Path, *, config: Config | None = None, plugins: list[str] | None = None,
            sarif_files: list[Path] | None = None) -> Analysis:
    """Analyze an existing local checkout; no network or target-code execution."""
    if not javascript.available():
        raise ValueError("The supported stack requires parser dependencies: pip install 'repolens[stack]'")
    try:
        import sqlglot  # noqa: F401
    except ImportError as exc:
        raise ValueError("PostgreSQL analysis requires: pip install 'repolens[stack]'") from exc
    root = root.resolve()
    settings = config or Config.load(root)
    graph = scan_repository(root, settings, extractors=load_extractors(plugins or []))
    from .scan.python_ast import python_files
    from .scan.settings import from_config
    from .scan import security, performance, migrations
    # Reuse the repository's scan policy (auth patterns, migration roots, and
    # admitted Python roots). The impact config above is a separate namespace.
    # Configured commands are not executed. Configured regexes remain trusted policy.
    checks = from_config(load_config(root), max_file_bytes=settings.max_file_bytes)
    configured_python = {checks.rel(path) for path in python_files(checks)}
    checks.admitted_python_files = tuple(sorted(
        n.path for n in graph.nodes.values()
        if n.kind == "file" and n.path and n.path.endswith(".py")
        and n.path in configured_python and n.metadata.get("scan_status") == "read"
    ))
    # Alembic directories are excluded from ordinary Python checks by default,
    # but still belong to migration analysis. Keep their admitted inventory separate.
    migration_checks = replace(checks, admitted_python_files=tuple(sorted(
        n.path for n in graph.nodes.values()
        if n.kind == "file" and n.path and n.path.endswith(".py")
        and n.metadata.get("scan_status") == "read"
    )))
    runs = []
    for name, scanner in (("security", security.scan), ("performance", performance.scan), ("migrations", migrations.scan)):
        try:
            runs.append(ToolRun(name, findings=scanner(migration_checks if name == "migrations" else checks)))
        except Exception as exc:
            runs.append(ToolRun(name, error=f"{type(exc).__name__}: analysis failed; review the scanner diagnostics."))
    for path in sarif_files or []:
        runs.extend(import_sarif(path, root))
    return Analysis(graph, runs, settings)


def main(argv=None, *, config=None, prog=None) -> int:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--out", type=Path, help="output directory (default .repolens/analysis)")
    parser.add_argument("--query", default="")
    parser.add_argument("--max-nodes", type=int, default=30)
    parser.add_argument("--plugin", action="append", default=[], help="explicitly enable an installed extractor")
    parser.add_argument("--sarif", type=Path, action="append", default=[])
    parser.add_argument("--list-plugins", action="store_true")
    parser.add_argument("--check", action="store_true", help="exit 1 for high-priority medium/high-confidence findings; 2 for incomplete scans")
    args = parser.parse_args(argv)
    if args.list_plugins:
        print(json.dumps(available(), indent=2))
        return 0
    if not 1 <= args.max_nodes <= 100:
        parser.error("--max-nodes must be between 1 and 100")
    root = config.root if config else Path.cwd()
    out = (args.out or root / ".repolens/analysis").resolve()
    if out == root.resolve():
        parser.error("--out must be a dedicated output directory")
    settings = Config.load(root)
    if out.is_relative_to(root.resolve()):
        settings.exclude_paths.add(out.relative_to(root.resolve()).as_posix())
    try:
        result = analyze(root, config=settings, plugins=args.plugin, sarif_files=args.sarif)
        out.mkdir(parents=True, exist_ok=True)
        (out / "analysis.json").write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
        (out / "report.md").write_text(result.markdown(args.query, args.max_nodes), encoding="utf-8")
        (out / "linkage.mmd").write_text(render_mermaid(result.view(args.query, args.max_nodes)), encoding="utf-8")
        (out / "findings.sarif").write_text(to_sarif(result.runs, __version__), encoding="utf-8")
    except (OSError, ValueError, TypeError) as exc:
        print(f"repolens analyze: {exc}")
        return 2
    print(f"Analysis complete={result.complete}; wrote {out}")
    if not result.complete:
        return 2
    if args.check and any(f.priority in {"P0", "P1"} and f.confidence != "low" for run in result.runs for f in run.findings):
        return 1
    return 0
