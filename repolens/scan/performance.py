"""Static performance detectors for an async Python service.

Four shapes that cost every concurrent request and pass every functional test:

  blocking-call-in-async   a blocking network/process call on the event loop stalls
                           every request the worker is serving, not just this one.
  unbounded-to-list        `.to_list(None)` materialises a whole collection; fine at ten
                           rows, a memory spike at ten thousand, and the rows grow.
  unbounded-sql-fetch      the PostgreSQL form of the same: asyncpg `fetch()` of a
                           SELECT with no LIMIT, or SQLAlchemy `.all()` / `.fetchall()`
                           on a `select()` that never gets `.limit()`. Low confidence: a
                           lookup by primary key returns one row either way.
  query-in-loop            an awaited database call inside a loop is N+1 round trips.

What this cannot see: whether an index exists, how many rows a filter matches, or what
a query costs. Those need the database (`explain()`, `$indexStats`, pg_stat_statements).
"""
from __future__ import annotations

import ast
import re

from ..core.findings import Finding
from .mounts import MountIndex
from .python_ast import (
    Mount,
    dotted,
    functions,
    last,
    parse,
    python_files,
    routes,
    walk_body,
)
from .settings import ScanSettings
from .wiring import mark_unreachable, unreachable_route_files

TOOL = "performance"
_LOOPS = (ast.For, ast.AsyncFor, ast.While, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _call_chain(call: ast.Call) -> list[ast.Call]:
    """`db.x.find(q).limit(5).to_list(None)` -> [to_list(...), limit(...), find(...)]."""
    chain = [call]
    node: ast.AST = call.func
    while isinstance(node, ast.Attribute):
        node = node.value
        if isinstance(node, ast.Call):
            chain.append(node)
            node = node.func
    return chain


def _is_unbounded_to_list(call: ast.Call) -> bool:
    if last(call.func) != "to_list":
        return False
    if call.args:
        arg = call.args[0]
    else:
        arg = next((k.value for k in call.keywords if k.arg == "length"), None)
    unbounded = arg is None or (isinstance(arg, ast.Constant) and arg.value is None)
    return unbounded and not any(_bounds(c) for c in _call_chain(call)[1:])


def _bounds(call: ast.Call) -> bool:
    """`.limit(n)` or `find(q, limit=n)` upstream of the to_list. `limit(0)` and
    `limit=0` are "no limit" to MongoDB, not a bound of zero."""
    if last(call.func) == "limit":
        return not (call.args and isinstance(call.args[0], ast.Constant) and call.args[0].value == 0)
    value = next((k.value for k in call.keywords if k.arg == "limit"), None)
    return value is not None and not (isinstance(value, ast.Constant) and value.value in (0, None))


_SELECT = re.compile(r"^\s*(?:SELECT|WITH)\b", re.IGNORECASE)
_BOUNDED = re.compile(r"\bLIMIT\b|\bFETCH\s+(?:FIRST|NEXT)\b", re.IGNORECASE)
# One row whatever the table holds: an aggregate with no GROUP BY.
_ONE_ROW = re.compile(r"^\s*SELECT\s+(?:coalesce\s*\(\s*)?(?:count|sum|min|max|avg|exists|bool_and|bool_or)\s*\(",
                      re.IGNORECASE)
_GROUP_BY = re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE)


def _sql_literal(node: ast.AST) -> str | None:
    """SQL text in a literal (`"..."`, an f-string, `text("...")`), else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    if isinstance(node, ast.Call) and last(node.func) == "text" and node.args:
        return _sql_literal(node.args[0])
    return None


def _unbounded_select(sql: str) -> bool:
    return (bool(_SELECT.search(sql)) and not _BOUNDED.search(sql)
            and not (_ONE_ROW.search(sql) and not _GROUP_BY.search(sql)))


def _assigned(fn: ast.AST, name: str) -> list[ast.AST]:
    """Every value `name` is given in the function body."""
    values: list[ast.AST] = []
    for node in walk_body(fn):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            targets = [node.target]
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            values.append(node.value)
    return values


def _receivers(call: ast.Call) -> list[ast.Call]:
    """The calls a method chain is made on, through `await`:
    `(await s.execute(q)).scalars().all()` -> [scalars(), execute(q)]."""
    out: list[ast.Call] = []
    node: ast.AST = call.func
    while True:
        if isinstance(node, (ast.Attribute, ast.Await)):
            node = node.value
        elif isinstance(node, ast.Call):
            out.append(node)
            node = node.func
        else:
            return out


def _statement_values(fn: ast.AST, stmt: ast.AST) -> list[ast.AST]:
    return _assigned(fn, stmt.id) if isinstance(stmt, ast.Name) else [stmt]


def _is_unbounded_sql_fetch(fn: ast.AST, call: ast.Call) -> bool:
    """asyncpg `conn.fetch(<SELECT with no LIMIT>)`, or SQLAlchemy `.all()`/`.fetchall()`
    on the result of executing such a SELECT or a `select()` with no `.limit()`."""
    if not isinstance(call.func, ast.Attribute):
        return False  # the builtin all() is not a query
    method = call.func.attr
    if method == "fetch" and call.args:
        texts = [_sql_literal(v) for v in _statement_values(fn, call.args[0])]
        return bool(texts) and all(t is not None and _unbounded_select(t) for t in texts)
    if method not in ("all", "fetchall") or call.args:
        return False
    executed = next((c for c in _receivers(call)
                     if last(c.func) in ("execute", "scalars") and c.args), None)
    if executed is None:
        return False
    values = _statement_values(fn, executed.args[0])
    if not values:
        return False
    texts = [_sql_literal(v) for v in values]
    if any(t is not None for t in texts):
        return all(t is None or _unbounded_select(t) for t in texts)
    built = {last(sub.func) for v in values for sub in ast.walk(v) if isinstance(sub, ast.Call)}
    return "select" in built and not built & {"limit", "fetch", "slice"}


def _per_item(loop: ast.AST) -> list[ast.AST]:
    """The parts of a loop that run once PER ITEM. A comprehension evaluates its first
    iterable once, before looping, so `[r for r in await db.t.find().to_list(9)]` is one
    query, not N; the element, the conditions and any inner iterables run per item."""
    if isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
        return list(loop.body)
    parts: list[ast.AST] = [loop.key, loop.value] if isinstance(loop, ast.DictComp) else [loop.elt]
    for index, gen in enumerate(loop.generators):
        if index:
            parts.append(gen.iter)
        parts.extend(gen.ifs)
    return parts


def _loop_awaits(fn: ast.AsyncFunctionDef, db_methods: frozenset[str]) -> list[tuple[ast.Await, str]]:
    """Awaited DB calls inside a loop body in `fn` (not in nested functions)."""
    found: dict[int, tuple[ast.Await, str]] = {}
    for loop in walk_body(fn):
        if not isinstance(loop, _LOOPS):
            continue
        stack: list[ast.AST] = _per_item(loop)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
                hit = next((last(c.func) for c in _call_chain(node.value) if last(c.func) in db_methods), None)
                if hit:
                    found[id(node)] = (node, hit)
            stack.extend(ast.iter_child_nodes(node))
    return sorted(found.values(), key=lambda pair: pair[0].lineno)


def _file_findings(s: ScanSettings, rel: str, tree: ast.Module,
                   mounts: dict[str, Mount] | None = None) -> list[Finding]:
    perf = s.performance
    exposure = "internal" if s.is_internal(rel) else ""
    route_nodes = {id(r.node): r for r in routes(tree, mounts)}
    findings: list[Finding] = []
    for fn, qualname in functions(tree):
        route = route_nodes.get(id(fn))
        where = f"{route.method} {route.path} ({qualname})" if route else f"{qualname}()"

        if isinstance(fn, ast.AsyncFunctionDef):
            for node in walk_body(fn):
                if isinstance(node, ast.Call) and dotted(node.func) in perf.blocking_calls:
                    findings.append(Finding(
                        tool=TOOL, rule="performance/blocking-call-in-async",
                        severity="high" if route else "medium", confidence="high",
                        category="performance", exposure=exposure, file=rel, line=node.lineno,
                        message=f"{where} calls {dotted(node.func)} on the event loop",
                        remedy="Await an async client (httpx.AsyncClient, aiosmtplib, "
                               "asyncio.sleep, asyncio.create_subprocess_exec), or move the "
                               "call into a sync helper run with `await asyncio.to_thread(...)`.",
                    ))
            for node, method in _loop_awaits(fn, perf.db_methods):
                findings.append(Finding(
                    tool=TOOL, rule="performance/query-in-loop",
                    severity="medium" if route else "low", confidence="medium",
                    category="performance", exposure=exposure, file=rel, line=node.lineno,
                    message=f"{where} awaits {method}() inside a loop — one round trip per item (N+1)",
                    remedy="Collect the keys and query once ({'$in': ids} / WHERE id = ANY($1)), "
                           "or use a bulk write; if the calls are independent and few, "
                           "asyncio.gather with a bounded semaphore.",
                ))

        for node in walk_body(fn):
            if isinstance(node, ast.Call) and _is_unbounded_to_list(node):
                findings.append(Finding(
                    tool=TOOL, rule="performance/unbounded-to-list",
                    severity="medium" if route else "low", confidence="medium",
                    category="performance", exposure=exposure, file=rel, line=node.lineno,
                    message=f"{where} materialises a whole result set with to_list(None)",
                    remedy="Bound it (.limit(n) / to_list(n)) and paginate, project only the "
                           "fields used, or aggregate server-side ($group/$count) when only "
                           "a total is needed.",
                ))
            elif isinstance(node, ast.Call) and _is_unbounded_sql_fetch(fn, node):
                findings.append(Finding(
                    tool=TOOL, rule="performance/unbounded-sql-fetch",
                    severity="medium" if route else "low", confidence="low",
                    category="performance", exposure=exposure, file=rel, line=node.lineno,
                    message=f"{where} fetches every row a SELECT matches: no LIMIT in the SQL "
                            "and none on the statement",
                    remedy="Bound it (LIMIT n / .limit(n)) and paginate with a keyset "
                           "(WHERE id > $last ORDER BY id), or aggregate in SQL when only a "
                           "total is needed. A table that is small today is not small next year.",
                ))
    return findings


def scan(s: ScanSettings) -> list[Finding]:
    dead = unreachable_route_files(s)
    mounts = MountIndex(s)
    findings: list[Finding] = []
    for path in python_files(s):
        tree = parse(str(path), s.max_file_bytes)
        if tree is None:
            continue
        rel = s.rel(path)
        file_findings = _file_findings(s, rel, tree, mounts.for_file(rel))
        if rel in dead:
            mark_unreachable(file_findings)
        findings.extend(file_findings)
    return findings
