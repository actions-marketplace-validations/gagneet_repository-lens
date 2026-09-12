from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .config import Config
from .model import Graph
from .query import impact
from .render import render_json, render_markdown, render_mermaid
from .scanner import repository_content_sha, scan_repository


DEFAULT_INDEX = ".impact-tracer/index.json"


def _repo(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"repository directory does not exist: {value}")
    return path


def _index_path(repo: Path, value: str | None) -> Path:
    path = Path(value) if value else repo / DEFAULT_INDEX
    return path if path.is_absolute() else repo / path


def _load_or_scan(repo: Path, config: Config, index_path: Path, refresh: bool) -> Graph:
    if index_path.is_file() and not refresh:
        from .scanner import config_fingerprint

        graph = Graph.load(index_path)
        if (
            Path(graph.root).resolve() == repo
            and graph.metadata.get("content_sha256") == repository_content_sha(repo, config)
            and graph.metadata.get("config_sha256") == config_fingerprint(config)
        ):
            return graph
    graph = scan_repository(repo, config)
    graph.save(index_path)
    return graph


def _write_or_print(content: str, output: str | None) -> None:
    if not output:
        sys.stdout.write(content)
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(path)


def build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog or "impact-tracer",
        description="Read-only repository linkage and change-impact explorer.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Build a deterministic static graph index.")
    scan.add_argument("repo", type=_repo, nargs="?")
    scan.add_argument("--config", type=Path)
    scan.add_argument("--output", help=f"Index path; default {DEFAULT_INDEX}")

    query = sub.add_parser("query", help="Find a phrase/concept and render its bounded impact graph.")
    query.add_argument("query")
    query.add_argument("--repo", type=_repo)
    query.add_argument("--config", type=Path)
    query.add_argument("--index")
    query.add_argument("--refresh", action="store_true")
    query.add_argument("--depth", type=int, default=2, choices=range(0, 6))
    query.add_argument("--max-nodes", type=int, default=40)
    query.add_argument("--seed-limit", type=int, default=8)
    query.add_argument("--format", choices=("markdown", "mermaid", "json"), default="markdown")
    query.add_argument("--output")

    doctor = sub.add_parser("doctor", help="Summarize scan coverage and uncertainty.")
    doctor.add_argument("repo", type=_repo, nargs="?")
    doctor.add_argument("--config", type=Path)
    doctor.add_argument(
        "--all-issues", action="store_true",
        help="List every issue instead of a bounded per-code summary.",
    )
    doctor.add_argument(
        "--fail-on-error", action="store_true",
        help=(
            "Exit non-zero when any error-severity issue exists. OFF by default: this "
            "tool is advisory, and an advisory report that exits 1 on every run of a "
            "healthy repository is read as a broken gate and then ignored."
        ),
    )
    return parser


def main(argv: list[str] | None = None, *, config=None, prog: str | None = None) -> int:
    args = build_parser(prog).parse_args(argv)
    repo = (args.repo or (config.root if config else Path.cwd())).resolve()
    config = Config.load(repo, args.config)
    if args.command == "scan":
        graph = scan_repository(repo, config)
        output = _index_path(repo, args.output)
        graph.save(output)
        print(f"indexed {graph.metadata['file_count']} files, {len(graph.nodes)} nodes, {len(graph.edges)} edges, {len(graph.issues)} issues")
        print(output)
        return 0
    if args.command == "doctor":
        graph = scan_repository(repo, config)
        by_severity: dict[str, int] = {}
        by_code: dict[str, list] = {}
        for issue in graph.issues:
            by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
            by_code.setdefault(issue.code, []).append(issue)
        print(f"files={graph.metadata['file_count']} nodes={len(graph.nodes)} edges={len(graph.edges)}")
        print("issues=" + ", ".join(f"{key}:{value}" for key, value in sorted(by_severity.items())))
        print(f"content_sha256={graph.metadata['content_sha256']}")

        # A per-code breakdown, because a bare total of 28,755 is not a health report:
        # 88% of it was one advisory code, and the 32 findings anybody would act on
        # were arithmetically invisible inside it.
        rank = {"error": 0, "warning": 1, "info": 2}
        print("")
        print("by code (most severe first):")
        for code in sorted(by_code, key=lambda c: (rank.get(by_code[c][0].severity, 3), -len(by_code[c]), c)):
            issues = by_code[code]
            print(f"  {issues[0].severity:8} {len(issues):7}  {code}")
            if args.all_issues:
                for issue in issues:
                    print(f"      {issue.evidence or '-'}: {issue.message}")
            elif issues[0].severity != "info":
                for issue in issues[:3]:
                    print(f"      e.g. {issue.evidence or '-'}: {issue.message[:120]}")
                if len(issues) > 3:
                    print(f"      ... {len(issues) - 3} more (use --all-issues)")
        print("")
        print("Advisory. Heuristic and ambiguous relationships are never a verified "
              "dependency; use `query` to see the issues that intersect a change.")
        print("The scanner never imports or executes target repository code.")
        if args.fail_on_error:
            return 1 if by_severity.get("error", 0) else 0
        return 0

    index_path = _index_path(repo, args.index)
    graph = _load_or_scan(repo, config, index_path, args.refresh)
    result = impact(
        graph, repo, args.query, config,
        depth=args.depth, max_nodes=args.max_nodes, seed_limit=args.seed_limit,
    )
    renderer = {
        "markdown": render_markdown,
        "mermaid": render_mermaid,
        "json": render_json,
    }[args.format]
    _write_or_print(renderer(result), args.output)
    return 0 if result.seeds else 2


if __name__ == "__main__":
    raise SystemExit(main())
