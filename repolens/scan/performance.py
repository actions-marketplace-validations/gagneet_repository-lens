"""Static performance detectors for an async Python service.

Four shapes that cost every concurrent request and pass every functional test:

  blocking-call-in-async   a blocking network/process call on the event loop stalls
                           every request the worker is serving, not just this one.
  unbounded-to-list        `.to_list(None)` materialises a whole collection; fine at ten
                           rows, a memory spike at ten thousand, and the rows grow.
  unbounded-sql-fetch      the PostgreSQL form of the same: asyncpg `fetch()` of a
                           SELECT with no LIMIT, or SQLAlchemy `.all()` / `.fetchall()`
                           on a `select()` that never gets `.limit()` (also SQLModel's
                           `session.exec(select(...)).all()`, the legacy
                           `db.query(Model).all()`, and a result held in a name first:
                           `result = await session.execute(stmt)`, `result.scalars().all()`).
                           Low confidence: a lookup by primary key returns one row either way.
                           One row per group is not every row: an aggregate with no GROUP BY,
                           or a GROUP BY whose projection is only group keys, aggregates and
                           constants (SQL text, or `select(...)`/`query(...)` with
                           `.group_by(...)` and `func.*` aggregates), is not reported. A WHERE
                           comparing a `[scan.performance] scope_key_patterns` column with a
                           value lowers the severity one step and says so in the message.
  query-in-loop            a database call inside a loop is N+1 round trips: awaited in an
                           async function, or on a database-looking receiver (`db`,
                           `session`, `cur`) in a sync one, where no `await` marks I/O.

Call names are matched after import aliases are resolved: `import requests as rq`
makes `rq.get` requests.get, and `from time import sleep` makes `sleep` time.sleep.

What this cannot see: whether an index exists, how many rows a filter matches, or what
a query costs. Those need the database (`explain()`, `$indexStats`, pg_stat_statements).
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict

from ..core.findings import SCOPE_KEY_NOTE, Finding
from .mounts import mount_index
from .python_ast import (
    FunctionNode,
    Mount,
    dotted,
    functions,
    last,
    parsed_files,
    routes,
    walk_body,
)
from .security import TOO_DEEP, could_not_scan
from .settings import ScanSettings
from .wiring import mark, route_exposure

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


#: String literals (contents blanked, quotes kept) and comments (blanked), so parentheses,
#: commas and keywords inside them do not count when clauses are located.
_SQL_OPAQUE = re.compile(r"'(?:[^']|'')*'|--[^\n]*|/\*.*?\*/", re.S)
_CLAUSE = re.compile(r"\b(SELECT|FROM|WHERE|GROUP\s+BY|HAVING|WINDOW|ORDER\s+BY|LIMIT|OFFSET|FETCH|FOR|"
                     r"UNION|INTERSECT|EXCEPT|RETURNING)\b", re.IGNORECASE)
#: One value per group whatever the group holds (`coalesce(sum(x), 0)` included).
_AGGREGATE_ITEM = re.compile(
    r"(?:coalesce\s*\(\s*)?(?:count|sum|min|max|avg|array_agg|string_agg|json_agg|jsonb_agg|json_object_agg|"
    r"jsonb_object_agg|bool_and|bool_or|every|bit_and|bit_or|stddev\w*|variance|var_pop|var_samp|"
    r"percentile_cont|percentile_disc|mode)\s*\(", re.IGNORECASE)
_CONSTANT_ITEM = re.compile(r"(?:'(?:[^']|'')*'|-?\d+(?:\.\d+)?|NULL|TRUE|FALSE)(?:::\w+)?", re.IGNORECASE)
_ALIASED = re.compile(r"(.+?)\s+(?:AS\s+)?(\"?[A-Za-z_]\w*\"?)", re.IGNORECASE | re.S)
_NOT_ALIASES = frozenset({"end", "null", "true", "false", "asc", "desc"})
#: `account_id = $1`, `o.account_id IN (%s)`, `account_id = ANY(:ids)`, `account_id::text = '…'`:
#: a column compared with a value (a placeholder, an f-string hole or a literal), not a join.
_VALUE_FILTER = re.compile(
    r"\b(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)(?:::\w+)?\s*(?:(?<![<>!])=\s*(?:ANY\s*\(\s*)?|\s+IN\s*\(\s*)"
    r"(?:\$\d+|%s|%\(\w+\)s|:\w+|\?|\{\}|'|-?\d)", re.IGNORECASE)


def _top_level_clauses(sql: str) -> list[tuple[str, str]] | None:
    """(keyword, text) of each clause of the statement's outermost final SELECT, in order,
    with the text sliced from the original SQL. None for a set operation (`UNION`, ...)
    or text with no top-level SELECT: those are left to the unbounded rule as they are."""
    masked = _SQL_OPAQUE.sub(lambda m: (m.group(0)[0] + " " * (len(m.group(0)) - 2) + "'"
                                        if m.group(0)[0] == "'" else " " * len(m.group(0))), sql)
    depth, depths = 0, []
    for char in masked:
        depth -= char == ")"
        depths.append(depth)
        depth += char == "("
    clauses = [(re.sub(r"\s+", " ", m.group(1)).upper(), m.start(), m.end())
               for m in _CLAUSE.finditer(masked) if depths[m.start()] == 0]
    if any(name in ("UNION", "INTERSECT", "EXCEPT") for name, _, _ in clauses):
        return None
    start = max((i for i, (name, _, _) in enumerate(clauses) if name == "SELECT"), default=None)
    if start is None:
        return None
    tail = clauses[start:]
    return [(name, sql[end:tail[i + 1][1] if i + 1 < len(tail) else len(sql)])
            for i, (name, _, end) in enumerate(tail)]


def _split_top_level(text: str) -> list[str]:
    """`a, f(b, c), 'x,y'` -> ["a", "f(b, c)", "'x,y'"]."""
    masked = _SQL_OPAQUE.sub(lambda m: "'" + " " * (len(m.group(0)) - 2) + "'"
                             if m.group(0)[0] == "'" else " " * len(m.group(0)), text)
    items, depth, begin = [], 0, 0
    for i, char in enumerate(masked):
        depth += (char == "(") - (char == ")")
        if char == "," and depth == 0:
            items.append(text[begin:i])
            begin = i + 1
    items.append(text[begin:])
    return [item.strip() for item in items]


def _normal(expression: str) -> str:
    """Whitespace-collapsed, lower-case, and `o.status` read as `status`."""
    spelled = re.sub(r"\s+", " ", expression.strip().strip(";")).lower()
    qualified = re.fullmatch(r'"?\w+"?\."?(\w+)"?', spelled)
    return qualified.group(1) if qualified else spelled.strip('"')


def _grouped_aggregates(sql: str) -> bool:
    """A `GROUP BY` whose projection is only group keys, aggregates and constants: one row per
    group (counts per status, sums per month), not one per table row. A projection with any
    other column (`SELECT u.id, u.name, count(*) … GROUP BY u.id`) is not."""
    clauses = _top_level_clauses(sql)
    if clauses is None:
        return False
    found = dict(clauses)
    if "GROUP BY" not in found or len(found) != len(clauses):
        return False  # no grouping, or a clause twice at the top level: not read
    projection = re.sub(r"^\s*(?:ALL\s+|DISTINCT\s+(?!ON\b))", "", found["SELECT"], flags=re.IGNORECASE)
    items = _split_top_level(projection)
    keys_text = found["GROUP BY"].strip()
    if not items or not keys_text or re.match(r"(?:ROLLUP|CUBE|GROUPING\s+SETS)\s*\(", keys_text, re.IGNORECASE):
        return False
    expressions: list[tuple[str, str]] = []
    for item in items:
        aliased = _ALIASED.fullmatch(item)
        if aliased and aliased.group(2).strip('"').lower() not in _NOT_ALIASES \
                and aliased.group(1).count("(") == aliased.group(1).count(")") \
                and not re.search(r"[-+*/%<>=|&,.]\s*$|::$", aliased.group(1)):
            expressions.append((aliased.group(1), aliased.group(2).strip('"').lower()))
        else:
            expressions.append((item, ""))
    keys = set()
    for key in _split_top_level(keys_text):
        if key.isdigit() and 1 <= int(key) <= len(expressions):
            keys.add(_normal(expressions[int(key) - 1][0]))  # GROUP BY 1: the first output column
        else:
            keys.add(_normal(key))
    return all(_AGGREGATE_ITEM.match(expression.strip()) or _CONSTANT_ITEM.fullmatch(expression.strip())
               or _normal(expression) in keys or (alias and alias in keys)
               for expression, alias in expressions)


#: SQLAlchemy `func.<name>(...)` aggregates.
_ORM_AGGREGATES = frozenset({"count", "sum", "min", "max", "avg", "array_agg", "string_agg", "json_agg",
                             "jsonb_agg", "bool_and", "bool_or", "every"})


def _orm_grouped(calls: list[ast.Call]) -> bool:
    """`select(Order.status, func.count(Order.id).label("n")).group_by(Order.status)`, or the
    same through `db.query(...)`: the one selecting call takes only group keys and `func`
    aggregates. A nested second `select` (a subquery) is not read."""
    selects = [c for c in calls if last(c.func) in ("select", "query")]
    keys = {ast.dump(arg) for c in calls if last(c.func) == "group_by" for arg in c.args}
    if len(selects) != 1 or not keys or not selects[0].args:
        return False

    def grouped(node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "label":
            node = node.func.value
        return ast.dump(node) in keys or (isinstance(node, ast.Call) and last(node.func) in _ORM_AGGREGATES
                                          and "func" in dotted(node.func).split("."))

    return all(grouped(arg) for arg in selects[0].args)


def _where_columns(sql: str) -> set[str]:
    """Columns the outermost SELECT's WHERE compares with a value."""
    clauses = _top_level_clauses(sql)
    where = " ".join(text for name, text in clauses or [] if name == "WHERE")
    return {m.group(1).lower() for m in _VALUE_FILTER.finditer(where)}


def _unbounded_select(sql: str) -> bool:
    return (bool(_SELECT.search(sql)) and not _BOUNDED.search(sql)
            and not (_ONE_ROW.search(sql) and not _GROUP_BY.search(sql))
            and not _grouped_aggregates(sql))


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


#: Calls that run a statement handed to them as the first argument.
_EXECUTES = frozenset({"execute", "scalars", "exec"})
#: On the query itself, any of these bounds the rows fetched.
_ROW_BOUNDS = frozenset({"limit", "slice", "first", "one", "one_or_none", "fetchmany", "paginate"})
#: Everyday method names that are a round trip only on a database-looking receiver.
_SESSION_METHODS = frozenset({"get", "exec", "query"})


def _chain_root(call: ast.Call) -> ast.AST:
    """What a method chain starts from, through calls and awaits:
    `result.scalars().all()` -> the Name `result`."""
    node: ast.AST = call.func
    while isinstance(node, (ast.Attribute, ast.Await, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node


def _db_receiver(call: ast.Call, pattern: re.Pattern[str]) -> bool:
    """Whether a method is called on something spelled like a database handle: `db.get`,
    `self.session.exec`, `db.users.find_one`. A call's result (`x().get`) is not one."""
    if not isinstance(call.func, ast.Attribute):
        return False
    return any(pattern.search(part) for part in dotted(call.func.value).split(".")
               if part and part not in ("self", "cls"))


def _round_trip(call: ast.Call, methods: frozenset[str], pattern: re.Pattern[str], *,
                receiver_required: bool) -> bool:
    """Whether `call` is a database round trip. `session.get(Item, i)` is one;
    `request.session.get("user", None)` and `self.session.get(url)` (requests) are not:
    SQLAlchemy's get takes an entity and a key, and an entity is not a literal."""
    name = last(call.func)
    if name in _SESSION_METHODS:
        if not (call.args and _db_receiver(call, pattern)):
            return False
        return name != "get" or (len(call.args) >= 2 and not isinstance(call.args[0], ast.Constant))
    return name in methods and (not receiver_required or _db_receiver(call, pattern))


def _unbounded_chain(fn: ast.AST, chain: list[ast.Call], pattern: re.Pattern[str]) -> bool:
    """Whether the calls under a terminal `.all()` fetch every row of an unbounded query."""
    if {last(c.func) for c in chain} & _ROW_BOUNDS:
        return False
    executed = next((c for c in chain if last(c.func) in _EXECUTES and c.args), None)
    if executed is None:
        # `db.query(Item).filter(...).all()`: the chain IS the query.
        return (any(last(c.func) == "query" and c.args and _db_receiver(c, pattern) for c in chain)
                and not _orm_grouped(chain))
    values = _statement_values(fn, executed.args[0])
    if not values:
        return False
    texts = [_sql_literal(v) for v in values]
    if any(t is not None for t in texts):
        return all(t is None or _unbounded_select(t) for t in texts)
    built = {last(sub.func) for v in values for sub in ast.walk(v) if isinstance(sub, ast.Call)}
    return ("select" in built and not built & {"limit", "fetch", "slice"}
            and not all(_orm_grouped([sub for sub in ast.walk(v) if isinstance(sub, ast.Call)]) for v in values))


def _is_unbounded_sql_fetch(fn: ast.AST, call: ast.Call,
                            pattern: re.Pattern[str] | None = None) -> bool:
    """asyncpg `conn.fetch(<SELECT with no LIMIT>)`, or SQLAlchemy/SQLModel `.all()` /
    `.fetchall()` on the result of executing such a SELECT, a `select()` with no
    `.limit()`, or a `db.query(Model)` with none."""
    pattern = pattern or re.compile(r"(?!)")
    if not isinstance(call.func, ast.Attribute):
        return False  # the builtin all() is not a query
    method = call.func.attr
    if method == "fetch" and call.args:
        texts = [_sql_literal(v) for v in _statement_values(fn, call.args[0])]
        return bool(texts) and all(t is not None and _unbounded_select(t) for t in texts)
    if method not in ("all", "fetchall") or call.args:
        return False
    chain = _receivers(call)
    if any(last(c.func) in _EXECUTES and c.args or last(c.func) == "query" for c in chain):
        return _unbounded_chain(fn, chain, pattern)
    root = _chain_root(call)
    if not isinstance(root, ast.Name):
        return False
    # `result = await session.execute(stmt)` then `result.scalars().all()`: the query is
    # one statement up. Every value the name takes must be such a query.
    values = [v.value if isinstance(v, ast.Await) else v for v in _assigned(fn, root.id)]
    return bool(values) and all(
        isinstance(v, ast.Call) and _unbounded_chain(fn, [*chain, v, *_receivers(v)], pattern)
        for v in values)


def _statement_sources(fn: ast.AST, call: ast.Call) -> list[ast.AST]:
    """What an unbounded fetch runs, one entry per value it may take: SQL text, or the
    outermost call of the statement a chain builds."""
    if last(call.func) == "fetch":
        return _statement_values(fn, call.args[0])
    chains = [_receivers(call)]
    root = _chain_root(call)
    if isinstance(root, ast.Name) and not any(last(c.func) in _EXECUTES and c.args or last(c.func) == "query"
                                              for c in chains[0]):
        assigned = (v.value if isinstance(v, ast.Await) else v for v in _assigned(fn, root.id))
        chains = [[v, *_receivers(v)] for v in assigned if isinstance(v, ast.Call)]
    sources: list[ast.AST] = []
    for chain in chains:
        executed = next((c for c in chain if last(c.func) in _EXECUTES and c.args), None)
        if executed is not None:
            sources.extend(_statement_values(fn, executed.args[0]))
        elif chain:
            sources.append(chain[0])
    return sources


def _model_column(node: ast.AST) -> bool:
    """`Account.id`: another model's column, so comparing with it is a join, not a filter."""
    return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id[:1].isupper()


def _filtered_columns(source: ast.AST) -> set[str]:
    """Columns a statement's WHERE compares with a value: SQL text, or SQLAlchemy
    `.where(Model.col == x)`, `.filter(Model.col.in_(xs))` and `.filter_by(col=x)`."""
    text = _sql_literal(source)
    if text is not None:
        return _where_columns(text)
    columns: set[str] = set()
    for sub in ast.walk(source):
        if not (isinstance(sub, ast.Call) and last(sub.func) in ("where", "filter", "filter_by")):
            continue
        columns |= {k.arg for k in sub.keywords if k.arg}
        for part in (p for arg in sub.args for p in ast.walk(arg)):
            if (isinstance(part, ast.Compare) and len(part.ops) == 1 and isinstance(part.ops[0], (ast.Eq, ast.In))
                    and isinstance(part.left, ast.Attribute) and not _model_column(part.comparators[0])):
                columns.add(part.left.attr)
            elif (isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute) and part.func.attr == "in_"
                    and isinstance(part.func.value, ast.Attribute)):
                columns.add(part.func.value.attr)
    return columns


def _scope_key(fn: ast.AST, call: ast.Call, patterns: tuple[re.Pattern[str], ...]) -> str | None:
    """The `scope_key_patterns` column every statement the fetch may run filters on, else None."""
    if not patterns:
        return None
    matched = []
    for source in _statement_sources(fn, call):
        column = next((c for c in sorted(_filtered_columns(source)) if any(p.search(c) for p in patterns)), None)
        if column is None:
            return None
        matched.append(column)
    return matched[0] if matched else None


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


def _loop_round_trips(fn: FunctionNode, methods: frozenset[str],
                      pattern: re.Pattern[str]) -> list[tuple[ast.AST, str]]:
    """Database calls inside a loop body in `fn` (not in nested functions): awaited ones
    in an async function; in a sync one, calls on a database-looking receiver
    (`for i in ids: db.query(Item).filter(...).first()`), where nothing else says the
    call does I/O."""
    is_async = isinstance(fn, ast.AsyncFunctionDef)
    found: dict[int, tuple[ast.AST, str]] = {}
    for loop in walk_body(fn):
        if not isinstance(loop, _LOOPS):
            continue
        stack: list[ast.AST] = _per_item(loop)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            call = node.value if is_async and isinstance(node, ast.Await) else node if not is_async else None
            if isinstance(call, ast.Call):
                chain = _call_chain(call)
                hit = next((last(c.func) for c in chain
                            if _round_trip(c, methods, pattern, receiver_required=not is_async)), None)
                if hit:
                    found[id(node)] = (node, hit)
                    if not is_async:
                        # One chain is one round trip: only its arguments may hold another.
                        stack.extend(v for c in chain for v in [*c.args, *(k.value for k in c.keywords)])
                        continue
            stack.extend(ast.iter_child_nodes(node))
    return sorted(found.values(), key=lambda pair: pair[0].lineno)


def _import_targets(tree: ast.Module) -> dict[str, str]:
    """Local name -> the dotted name it stands for: `import requests as rq` -> rq:
    requests, `from time import sleep` -> sleep: time.sleep. A name imported from two
    places is left out, since which one a call uses depends on the line."""
    bound: dict[str, set[str]] = defaultdict(set)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound[alias.asname].add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                bound[alias.asname or alias.name].add(f"{node.module}.{alias.name}")
    return {name: next(iter(targets)) for name, targets in bound.items() if len(targets) == 1}


def _qualified(func: ast.AST, imports: dict[str, str]) -> str:
    name = dotted(func)
    head, _, rest = name.partition(".")
    target = imports.get(head)
    if not target:
        return name
    return f"{target}.{rest}" if rest else target


def _file_findings(s: ScanSettings, rel: str, tree: ast.Module,
                   mounts: dict[str, Mount] | None = None) -> list[Finding]:
    perf = s.performance
    exposure = "internal" if s.is_internal(rel) else ""
    route_nodes = {id(r.node): r for r in routes(tree, mounts)}
    imports = _import_targets(tree)
    findings: list[Finding] = []
    for fn, qualname in functions(tree):
        route = route_nodes.get(id(fn))
        where = f"{route.method} {route.path} ({qualname})" if route else f"{qualname}()"

        if isinstance(fn, ast.AsyncFunctionDef):
            for node in walk_body(fn):
                if not isinstance(node, ast.Call):
                    continue
                spelled, called = dotted(node.func), _qualified(node.func, imports)
                if spelled in perf.blocking_calls or called in perf.blocking_calls:
                    shown = spelled if spelled == called else f"{spelled} ({called})"
                    findings.append(Finding(
                        tool=TOOL, rule="performance/blocking-call-in-async",
                        severity="high" if route else "medium", confidence="high",
                        category="performance", exposure=exposure, file=rel, line=node.lineno,
                        message=f"{where} calls {shown} on the event loop",
                        remedy="Await an async client (httpx.AsyncClient, aiosmtplib, "
                               "asyncio.sleep, asyncio.create_subprocess_exec), or move the "
                               "call into a sync helper run with `await asyncio.to_thread(...)`.",
                    ))
        verb = "awaits" if isinstance(fn, ast.AsyncFunctionDef) else "calls"
        for node, method in _loop_round_trips(fn, perf.db_methods, perf.db_receiver):
            findings.append(Finding(
                tool=TOOL, rule="performance/query-in-loop",
                severity="medium" if route else "low", confidence="medium",
                category="performance", exposure=exposure, file=rel, line=node.lineno,
                message=f"{where} {verb} {method}() inside a loop — one round trip per item (N+1)",
                remedy="Collect the keys and query once ({'$in': ids} / WHERE id = ANY($1), "
                       "select(...).where(Model.id.in_(ids))), or use a bulk write; if the "
                       "calls are independent and few, asyncio.gather with a bounded semaphore.",
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
            elif isinstance(node, ast.Call) and _is_unbounded_sql_fetch(fn, node, perf.db_receiver):
                # Already low confidence, so a scope key lowers the severity by one step instead.
                scope = _scope_key(fn, node, perf.scope_keys)
                severity = ("low" if route else "info") if scope else ("medium" if route else "low")
                note = (f" [{SCOPE_KEY_NOTE} `{scope}`: it returns what one scope holds, not the whole table]"
                        if scope else "")
                findings.append(Finding(
                    tool=TOOL, rule="performance/unbounded-sql-fetch",
                    severity=severity, confidence="low",
                    category="performance", exposure=exposure, file=rel, line=node.lineno,
                    message=f"{where} fetches every row a SELECT matches: no LIMIT in the SQL "
                            f"and none on the statement{note}",
                    remedy="Bound it (LIMIT n / .limit(n)) and paginate with a keyset "
                           "(WHERE id > $last ORDER BY id), or aggregate in SQL when only a "
                           "total is needed. A table that is small today is not small next year.",
                ))
    return findings


def scan(s: ScanSettings) -> list[Finding]:
    """Performance findings for every scanned Python file, demoted by reachability.

    A file that cannot be analysed yields a could-not-scan finding instead."""
    reach = route_exposure(s)
    mounts = mount_index(s)
    findings: list[Finding] = []
    for path, tree in parsed_files(s):
        rel = s.rel(path)
        try:
            file_findings = _file_findings(s, rel, tree, mounts.for_file(rel))
        except RecursionError:
            findings.append(could_not_scan(TOOL, rel, TOO_DEEP))
            continue
        mark(file_findings, rel, reach)
        findings.extend(file_findings)
    return findings
