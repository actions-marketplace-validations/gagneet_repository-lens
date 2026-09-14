"""Self-contained HTML report: status, findings, tool runs, analysis diagnostics, coverage.

The page is one file that opens offline in any browser. It has no scripts and loads no
fonts, styles or images, and every value from the analysed repository is escaped. Its
Content-Security-Policy forbids fetching anything, so a hostile string in a scanned file
cannot make the report load or run anything. Long groups sit in `<details>` blocks, so
a repository with thousands of diagnostics still opens at a readable summary.
"""
from __future__ import annotations

from collections import Counter
from html import escape
from typing import Iterable

from .findings import PRIORITIES, Finding, ToolRun, sort_key, summary

#: Rows shown per rule or diagnostic code; the rest are counted and left to the JSON output.
ROW_CAP = 500
#: Rows in the whole page, so a repository with thousands of diagnostics still opens.
TOTAL_ROWS = 5000
#: Characters shown per cell.
CELL_CHARS = 2000

_CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#5f5f5a;--line:#deded8;--code:#f0f0ec;
--p0:#b3261e;--p1:#c2410c;--p2:#a16207;--p3:#4d6a8a;--ok:#1f7a3f;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ecece8;--muted:#a3a39c;
--line:#34342f;--code:#262623;--p0:#f2766d;--p1:#f59e63;--p2:#e3b341;--p3:#8fb0d4;--ok:#5cc184;--bad:#f2766d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:15px;margin:20px 0 6px}
.muted{color:var(--muted)}
code,pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border-radius:4px}
code{padding:1px 4px;overflow-wrap:anywhere}pre{padding:12px;overflow-x:auto}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;color:#fff}
.pill.ok{background:var(--ok)}.pill.bad{background:var(--bad)}.pill.na{background:var(--muted)}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px}
.card b{display:block;font-size:22px}
.P0{color:var(--p0)}.P1{color:var(--p1)}.P2{color:var(--p2)}.P3{color:var(--p3)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:var(--panel);margin:6px 0}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--code);font-weight:600}
td.msg{overflow-wrap:anywhere;min-width:280px}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:6px 12px}
summary{cursor:pointer;font-weight:600}
.warning{color:var(--p1)}.error{color:var(--p0)}.info{color:var(--p3)}
ul.reasons li{margin:2px 0}
"""


def _e(value: object) -> str:
    text = str(value)
    return escape(text if len(text) <= CELL_CHARS else text[:CELL_CHARS - 1] + "…", quote=True)


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]]) -> str:
    """A table whose cells are already escaped HTML."""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(rows_cell for rows_cell in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _td(value: object, css: str = "") -> str:
    return f'<td class="{_e(css)}">{_e(value)}</td>' if css else f"<td>{_e(value)}</td>"


def _run_status(run: ToolRun) -> str:
    if run.skipped:
        return f"SKIPPED: {run.skipped}"
    if run.error:
        return f"ERROR: {run.error}"
    return f"PARTIAL: {len(run.notes)} input note(s)" if run.notes else "ran"


def _take(items: list, budget: list[int]) -> list:
    taken = items[:max(0, min(ROW_CAP, budget[0]))]
    budget[0] -= len(taken)
    return taken


def _findings_section(findings: list[Finding], baseline: bool, budget: list[int]) -> list[str]:
    parts = ['<h2 id="findings">Findings</h2>']
    if not findings:
        return parts + ['<p class="muted">No findings from the checks that ran.</p>']
    omitted = [0, 0]  # rules, findings past the row budget
    for priority in PRIORITIES:
        group = [f for f in findings if f.priority == priority]
        if not group:
            continue
        parts.append(f'<h3 class="{priority}">{priority}: {len(group)} finding(s)</h3>')
        by_rule: dict[str, list[Finding]] = {}
        for finding in group:
            by_rule.setdefault(finding.rule, []).append(finding)
        for rule, items in sorted(by_rule.items(), key=lambda kv: (-max(f.score for f in kv[1]), kv[0])):
            if budget[0] <= 0:
                # Past the budget each rule would still cost a block, and a SARIF import can
                # carry a distinct rule per finding.
                omitted[0] += 1
                omitted[1] += len(items)
                continue
            first = items[0]
            opened = " open" if priority in {"P0", "P1"} else ""
            parts.append(f"<details{opened}><summary><code>{_e(rule)}</code> · {_e(first.category)} · "
                         f"{_e(first.severity)}/{_e(first.confidence)} · {len(items)}</summary>")
            if first.remedy:
                parts.append(f"<p><b>Fix:</b> {_e(first.remedy)}</p>")
            headers = ["Location", "Finding", "Exposure"] + (["New"] if baseline else [])
            shown = _take(items, budget)
            rows = [[f"<td><code>{_e(f.location)}</code></td>", _td(f.message, "msg"), _td(f.exposure or "")]
                    + ([_td("new" if f.new else "")] if baseline else []) for f in shown]
            parts.append(_table(headers, rows))
            if len(items) > len(shown):
                parts.append(f'<p class="muted">{len(items) - len(shown)} more in the JSON output.</p>')
            parts.append("</details>")
    if omitted[0]:
        parts.append(f'<p class="muted">{omitted[0]} rule(s) not shown: {omitted[1]} more in the JSON output.</p>')
    return parts


def _diagnostics_section(diagnostics: list, budget: list[int]) -> list[str]:
    parts = ['<h2 id="diagnostics">Analysis diagnostics</h2>',
             '<p class="muted">What the scanner could not resolve or wants reviewed, grouped by code. '
             "These describe the analysis and the code's wiring; they are not ranked findings.</p>"]
    if not diagnostics:
        return parts + ['<p class="muted">None.</p>']
    order = {"error": 0, "warning": 1, "info": 2}
    groups: dict[tuple[str, str], list] = {}
    for issue in diagnostics:
        groups.setdefault((issue.severity, issue.code), []).append(issue)
    counts = sorted(groups.items(), key=lambda kv: (order.get(kv[0][0], 3), -len(kv[1]), kv[0][1]))
    parts.append(_table(["Level", "Code", "Count"],
                        [[_td(level, level), f'<td><a href="#diag-{_e(level)}-{_e(code)}"><code>{_e(code)}</code></a></td>',
                          _td(len(items))] for (level, code), items in counts]))
    omitted = [0, 0]  # codes, diagnostics past the row budget
    for (level, code), items in counts:
        if budget[0] <= 0:
            omitted[0] += 1
            omitted[1] += len(items)
            continue
        parts.append(f'<details id="diag-{_e(level)}-{_e(code)}"><summary><span class="{_e(level)}">{_e(level)}</span> '
                     f"<code>{_e(code)}</code> · {len(items)}</summary>")
        actions = Counter(issue.recommendation for issue in items if issue.recommendation)
        for action, _count in actions.most_common(3):
            parts.append(f"<p><b>Action:</b> {_e(action)}</p>")
        shown = _take(items, budget)
        parts.append(_table(["Evidence", "Message"], [[f"<td><code>{_e(issue.evidence)}</code></td>", _td(issue.message, "msg")]
                                                      for issue in shown]))
        if len(items) > len(shown):
            parts.append(f'<p class="muted">{len(items) - len(shown)} more in the JSON output.</p>')
        parts.append("</details>")
    if omitted[0]:
        parts.append(f'<p class="muted">{omitted[0]} code(s) not shown: {omitted[1]} more in the JSON output.</p>')
    return parts


def render_html(runs: list[ToolRun], *, title: str, repository: str = "", complete: bool | None = None,
                incomplete_reasons: Iterable[str] = (), build: str = "", configuration: str = "",
                diagnostics: Iterable = (), coverage: dict[str, int] | None = None,
                limits: Iterable[str] = (), linkage: str = "", facts: Iterable[str] = (),
                baseline: bool = False) -> str:
    """The whole report page.

    `complete` is None for reports that make no completeness claim. `linkage` is Mermaid
    source, shown as text because the page runs no scripts. `facts` are short lines for
    the header, such as node and relationship counts."""
    findings = sorted((f for run in runs for f in run.findings), key=sort_key)
    counts = summary(findings)
    reasons = list(incomplete_reasons)
    diagnostics = list(diagnostics)
    status = ('<span class="pill na">no completeness claim</span>' if complete is None else
              '<span class="pill ok">analysis complete</span>' if complete else
              '<span class="pill bad">analysis incomplete</span>')
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
             f"<title>{_e(title)}</title><style>{_CSS}</style></head><body><main>",
             f"<h1>{_e(title)}</h1>",
             f'<p>{"Repository <code>" + _e(repository) + "</code> · " if repository else ""}{status}</p>']
    if reasons:
        parts.append('<p><b>Why it is incomplete</b> (results below miss what these inputs hold):</p><ul class="reasons">'
                     + "".join(f"<li>{_e(reason)}</li>" for reason in reasons) + "</ul>")
    header = [*facts]
    if build:
        header.append(f"Produced by {build}")
    if configuration:
        header.append(f"Configuration {configuration}")
    if header:
        parts.append('<p class="muted">' + "<br>".join(_e(line) for line in header) + "</p>")

    parts.append('<div class="cards">' + "".join(
        f'<div class="card"><span class="{p}">{p}</span><b>{counts["by_priority"][p]}</b></div>' for p in PRIORITIES)
        + f'<div class="card">findings<b>{counts["total"]}</b></div>'
        + (f'<div class="card">new<b>{counts["new"]}</b></div>' if baseline else "")
        + f'<div class="card">diagnostics<b>{len(diagnostics)}</b></div></div>')
    parts.append('<p class="muted">Priority blends severity (how bad if real), confidence (how likely real) and '
                 "exposure (who can reach it). Low-confidence findings need triage before anyone relies on them.</p>")
    if counts["by_category"]:
        categories = sorted(counts["by_category"])
        parts.append(_table(["Priority", *categories, "Total"], [
            [f'<td class="{p}"><b>{p}</b></td>',
             *[_td(sum(1 for f in findings if f.priority == p and f.category == c)) for c in categories],
             _td(counts["by_priority"][p])] for p in PRIORITIES]))

    parts.append('<h2 id="tools">Tools</h2>')
    parts.append(_table(["Tool", "Findings", "Status"],
                        [[_td(run.tool), _td(len(run.findings)), _td(_run_status(run), "msg")] for run in runs]))
    for run in runs:
        if run.notes:
            parts.append(f"<details><summary>{_e(run.tool)}: {len(run.notes)} input note(s)</summary><ul>"
                         + "".join(f"<li>{_e(note)}</li>" for note in run.notes[:ROW_CAP])
                         + (f"<li>{len(run.notes) - ROW_CAP} more in the JSON output</li>"
                            if len(run.notes) > ROW_CAP else "") + "</ul></details>")

    budget = [TOTAL_ROWS]
    parts += _findings_section(findings, baseline, budget)
    if diagnostics or complete is not None:
        parts += _diagnostics_section(diagnostics, budget)
    if linkage:
        parts += ['<h2 id="linkage">Linkage map</h2>',
                  '<p class="muted">Mermaid source. report.md renders it as a diagram on GitHub and in most Markdown viewers.</p>',
                  f"<details><summary>Show diagram source</summary><pre>{_e(linkage)}</pre></details>"]
    if coverage:
        parts += ['<h2 id="coverage">Coverage</h2>',
                  _table(["Language", "Files"], [[_td(language), _td(count)] for language, count in sorted(coverage.items())])]
    limits = list(limits)
    if limits:
        parts += ['<h2 id="limits">Limits</h2>', "<ul>" + "".join(f"<li>{_e(limit)}</li>" for limit in limits) + "</ul>"]
    parts.append("</main></body></html>")
    return "\n".join(parts) + "\n"
