"""Column existence: SQL column references checked against the schema a project declares.

The check is built for precision. A reference is recorded only when it names exactly
one physical table, and it is reported only when that table's column set is known
from a Prisma model the project uses or from `CREATE TABLE` DDL. Anything the reader
cannot attribute (CTEs, derived tables, several FROM items for an unqualified name,
an ignored model, a table altered by an ORM or dynamic DDL) is left unchecked.

Facts are recorded while each file is scanned (`record_*`, called from `postgres.py`)
and checked once every schema source has been read (`check_columns`)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..core.files import TEST_DIRS, is_test_path  # noqa: F401
from .model import Graph, Issue

#: System columns every PostgreSQL table has.
SYSTEM_COLUMNS = frozenset({"ctid", "xmin", "xmax", "cmin", "cmax", "oid", "tableoid"})
# Words the parser may hand back as a bare column that PostgreSQL resolves as something
# else: SQL-standard functions without parentheses, `DEFAULT`, trigger/RETURNING rows.
_NOT_COLUMNS = SYSTEM_COLUMNS | {
    "current_user", "session_user", "user", "current_role", "current_schema", "current_catalog",
    "default", "excluded", "new", "old", "true", "false", "null", "localtime", "localtimestamp",
    "current_date", "current_time", "current_timestamp",
}
_PRISMA_SCALARS = frozenset({"String", "Boolean", "Int", "BigInt", "Float", "Decimal", "DateTime", "Json", "Bytes"})
#: Prisma datasource providers that speak PostgreSQL (CockroachDB is wire- and SQL-compatible).
#: `scanner._scan_prisma_schemas` maps accessors with the same set.
POSTGRES_PRISMA_PROVIDERS = frozenset({"postgresql", "postgres", "cockroachdb"})
_POSTGRES_PROVIDERS = POSTGRES_PRISMA_PROVIDERS
_MIGRATION_DIRS = frozenset({"migrations", "migration", "migrate"})


@dataclass(slots=True, frozen=True)
class ColumnRef:
    """One SQL column reference attributed to a single physical table, kept for `check_columns`."""
    source: str
    location: str
    #: Relation name parts as PostgreSQL folds them, schema first when written.
    table: tuple[str, ...]
    #: Column name as PostgreSQL folds it.
    column: str
    #: The identifier exactly as written, quotes included.
    written: str
    #: Outer-query relations an unqualified name in a subquery could also mean.
    #: `None` is an outer FROM item whose columns cannot be known.
    fallbacks: tuple[tuple[str, ...] | None, ...] = ()


@dataclass(slots=True)
class SqlFacts:
    """Column references and DDL gathered across a scan, checked after every schema source is read."""
    refs: list[ColumnRef] = field(default_factory=list)
    #: Each entry ends with the file path it came from:
    #: ("create", table, columns | None, path), ("add", table, column, path),
    #: ("unknown", table, path) for a table created where its columns cannot be read, and
    #: ("reshaped", table, path) for one renamed or altered by DDL built at run time.
    ddl: list[tuple] = field(default_factory=list)
    #: Files that run DDL assembled at run time whose target table cannot be read
    #: (`EXECUTE format('ALTER TABLE %I ADD …', t)`): no declared column set in the
    #: repository can be trusted as complete. An identifiable target is "reshaped".
    dynamic_ddl: set[str] = field(default_factory=set)
    #: File path -> tables that file creates or alters. A script that changes a table's
    #: shape and then uses it is written against the shape it makes, not the declared one.
    ddl_files: dict[str, set[tuple[str, ...]]] = field(default_factory=dict)
    #: Files whose SQL sets `search_path` ("" when a role or database default does, which
    #: applies everywhere): an unqualified name there may be another schema's table.
    search_path: set[str] = field(default_factory=set)


def _path(location: str) -> str:
    return location.rsplit(":", 1)[0] if re.search(r":\d+$", location) else location


def _touched(graph: Graph, location: str, parts: tuple[str, ...]) -> None:
    if location:
        facts(graph).ddl_files.setdefault(_path(location), set()).add(parts)


# `SET search_path`, `SET SCHEMA 'app'`, `set_config('search_path', …)`, `-c search_path=app`.
_SEARCH_PATH = re.compile(r"""\bsearch_path\s*(?:=|\bTO\b)|\bset_config\s*\(\s*['"]search_path['"]|\bSET\s+(?:SESSION\s+|LOCAL\s+)?SCHEMA\s+['"]""", re.I)
_DEFAULT_SEARCH_PATH = re.compile(r"\bALTER\s+(?:ROLE|USER|DATABASE)\b[^;]*?\bSET\s+search_path\b", re.I | re.S)


_ROUTINE_DEFINITION = re.compile(r"(?:CREATE\s+(?:OR\s+REPLACE\s+)?|ALTER\s+)(?:FUNCTION|PROCEDURE|ROUTINE)\b", re.I)


def record_search_path(graph: Graph, text: str, location: str = "") -> None:
    """Note SQL that changes `search_path`: in its own file, or everywhere for a role or
    database default. Unqualified references it could redirect are then not checked.

    Only the statement's own words count: not a string literal or comment that mentions
    it, and not the `SET search_path` clause of a function or procedure definition, which
    applies inside that routine only."""
    try:
        if not isinstance(text, str) or "search_path" not in text.lower() and "schema" not in text.lower():
            return
        from .postgres import _mask, _strip_leading
        if _ROUTINE_DEFINITION.match(_strip_leading(text)):
            return
        masked = _mask(text)

        def spoken(pattern: re.Pattern[str]) -> bool:
            return any(masked[m.start()] == text[m.start()] for m in pattern.finditer(text))
        if spoken(_DEFAULT_SEARCH_PATH):
            facts(graph).search_path.add("")
        elif location and spoken(_SEARCH_PATH):
            facts(graph).search_path.add(_path(location))
    except Exception:  # noqa: BLE001 - advisory
        return


# A string literal (`s`) or comment (`c`) in Python or JS/TS source.
_CODE_LEXEMES = {
    "py": re.compile(r"(?P<c>#[^\n]*)|(?P<s>\"\"\".*?\"\"\"|'\'\'.*?'\'\'|\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')", re.S),
    "js": re.compile(r"(?P<c>//[^\n]*|/\*.*?\*/)|(?P<s>\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)", re.S),
}
# Inside a string: a SQL statement (`SET search_path TO app`, upper or lower case, possibly
# after another statement), `set_config('search_path', …)`, or a connection option (`-c search_path=app`).
_CODE_SEARCH_PATH = re.compile(r"(?:^|;)\s*(?-i:SET|set)\s+(?:(?:SESSION|LOCAL)\s+)?(?:search_path\b|SCHEMA\s)"
                               r"|\bset_config\s*\(\s*['\"]search_path['\"]|(?:^|\s)-c\s*search_path\s*=", re.I)


def _code_sets_search_path(text: str, language: str) -> bool:
    """Does Python or JS/TS source set `search_path` in a SQL string or connection option?
    A comment or UI copy that mentions it ("Set search_path to app in psql") does not."""
    for match in _CODE_LEXEMES[language].finditer(text):
        if match.group("s") is not None and "search_path" in match.group("s") \
                and _CODE_SEARCH_PATH.search(match.group("s").strip("\"'`")):
            return True
    return False


def facts(graph: Graph) -> SqlFacts:
    """The graph's `SqlFacts`, created on first use."""
    if graph.sql_facts is None:
        graph.sql_facts = SqlFacts()
    return graph.sql_facts


# ── identifiers ──────────────────────────────────────────────────────────────────
def _fold(identifier) -> str:
    """PostgreSQL folds unquoted identifiers to lower case; quoted ones keep their case."""
    return identifier.name if identifier.args.get("quoted") else identifier.name.lower()


def _table_parts(table) -> tuple[str, ...] | None:
    from sqlglot import exp
    if not isinstance(table, exp.Table) or not isinstance(table.this, exp.Identifier):
        return None
    parts = table.parts
    if not all(isinstance(p, exp.Identifier) for p in parts):
        return None
    return tuple(_fold(p) for p in parts)


_NAME = r'(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)'
_IDENT = rf"{_NAME}(?:\s*\.\s*{_NAME}){{0,2}}"


def _lexical_parts(identifier: str) -> tuple[str, ...]:
    parts = re.findall(r'"((?:[^"]|"")+)"|([A-Za-z_][\w$]*)', identifier)
    return tuple(quoted.replace('""', '"') if quoted else bare.lower() for quoted, bare in parts)


def _display(parts: tuple[str, ...]) -> str:
    return ".".join(_quote(part) for part in parts)


def _quote(name: str) -> str:
    return name if re.fullmatch(r"[a-z_][a-z0-9_$]*", name) else '"' + name.replace('"', '""') + '"'


# ── recording column references ──────────────────────────────────────────────────
class _Level:
    """The FROM items one query level makes visible, by the name a reference uses."""
    __slots__ = ("conflict", "outputs", "sources")

    def __init__(self) -> None:
        self.sources: dict[str, tuple[str, ...] | None] = {}
        self.conflict = False
        self.outputs: set[str] = set()

    def add(self, name: str | None, table: tuple[str, ...] | None) -> None:
        if name is None:
            # An unnamed FROM item still counts: an unqualified name may come from it.
            name = f"\0{len(self.sources)}"
        if name in self.sources:
            self.conflict = True
        self.sources[name] = table


def _output_names(select) -> set[str]:
    """Names a select list exposes, including PostgreSQL's implied ones (`count(*)` is
    `count`), lower-cased. ORDER BY and GROUP BY may use them without a table."""
    from sqlglot import exp
    names: set[str] = set()
    for projection in select.expressions:
        if projection.alias_or_name:
            names.add(projection.alias_or_name.lower())
        inner = projection.unalias()
        if isinstance(inner, exp.Case):
            names.add("case")
        if isinstance(inner, exp.Func):
            names.add(inner.sql_name().lower())
            if isinstance(inner, exp.Anonymous):
                names.add(str(inner.this).lower())
        with_name = re.match(r"\s*([A-Za-z_]\w*)\s*\(", inner.sql(dialect="postgres"))
        if with_name:
            names.add(with_name.group(1).lower())
    return names


def _in_output_clause(column) -> bool:
    from sqlglot import exp
    node = column.parent
    while node is not None and not isinstance(node, (exp.Query, exp.Insert, exp.Update, exp.Delete, exp.Merge)):
        if isinstance(node, (exp.Order, exp.Group, exp.Distinct)):
            return True
        node = node.parent
    return False


def _column_refs(expression) -> list[tuple[tuple[str, ...], str, str, tuple]]:
    """`(table, column, written, fallbacks)` for each column reference that names exactly
    one physical table. Everything else is left out, never guessed."""
    from sqlglot import exp

    out: list[tuple[int, tuple[tuple[str, ...], str, str, tuple]]] = []
    ctes = {cte.alias_or_name.lower() for cte in expression.find_all(exp.CTE)}

    def physical(table) -> tuple[str, ...] | None:
        parts = _table_parts(table)
        if parts is None:
            return None
        if len(parts) == 1 and parts[0].lower() in ctes:
            return None
        alias = table.args.get("alias")
        if alias is not None and alias.args.get("columns"):
            return None  # `FROM t AS a(x, y)` renames the columns
        return parts

    def visible_name(item) -> str | None:
        alias = item.args.get("alias")
        if alias is not None and isinstance(alias.this, exp.Identifier):
            return _fold(alias.this)
        if isinstance(item, exp.Table) and isinstance(item.this, exp.Identifier):
            return _fold(item.this)
        return None

    def record(table: tuple[str, ...] | None, identifier, fallbacks: tuple = ()) -> None:
        if table is None or not isinstance(identifier, exp.Identifier):
            return
        if identifier.name.lower() in _NOT_COLUMNS:
            return
        # Source position keeps reports in the order the SQL is written, not walk order.
        position = (identifier.meta or {}).get("start", 1 << 30) if hasattr(identifier, "meta") else 1 << 30
        out.append((position, (table, _fold(identifier), identifier.sql(dialect="postgres"), fallbacks)))

    def resolve(column, env: list[_Level], *, unqualified: bool = True) -> None:
        if not isinstance(column.this, exp.Identifier):
            return  # `t.*`
        if column.args.get("db") or column.args.get("catalog"):
            return
        qualifier = column.args.get("table")
        if qualifier is not None:
            if not isinstance(qualifier, exp.Identifier):
                return
            name = _fold(qualifier)
            for level in reversed(env):
                if name in level.sources:
                    if not level.conflict:
                        record(level.sources[name], column.this)
                    return
            return
        if not unqualified or not env:
            return
        level = env[-1]
        if level.conflict or len(level.sources) != 1:
            return
        (table,) = level.sources.values()
        lower = column.this.name.lower()
        if table is None or lower in ctes:
            return
        if lower in level.outputs and _in_output_clause(column):
            return  # ORDER BY / GROUP BY may name an output column instead
        fallbacks: list[tuple[str, ...] | None] = []
        for scope in env:
            if any(lower == name.lower() for name in scope.sources):
                return  # a whole-row reference to a FROM item
            if scope is not level:
                if scope.conflict:
                    return
                fallbacks.extend(scope.sources.values())
        record(table, column.this, tuple(fallbacks))

    def own(node, skip: set[int]):
        """Columns and nested queries that belong to this level, not to a nested one."""
        stack = list(node.iter_expressions())
        while stack:
            child = stack.pop()
            if id(child) in skip:
                continue
            if isinstance(child, (exp.Query, exp.Insert, exp.Update, exp.Delete, exp.Merge)):
                yield "query", child
            elif isinstance(child, exp.Column):
                yield "column", child
            elif not isinstance(child, (exp.With, exp.CTE)):
                stack.extend(child.iter_expressions())

    def from_items(node, level: _Level, env: list[_Level], skip: set[int]) -> None:
        items = []
        if (source := node.args.get("from_")) is not None:
            items.append(source.this)
        items.extend(join.this for join in node.args.get("joins") or ())
        if isinstance(node, exp.Delete):
            items.extend(node.args.get("using") or ())
        for item in items:
            skip.add(id(item))
            if isinstance(item, exp.Table):
                level.add(visible_name(item), physical(item))
            elif isinstance(item, exp.Lateral):
                level.add(visible_name(item), None)
                visit(item.this, [*env, level])
            elif isinstance(item, exp.Subquery):
                level.add(visible_name(item), None)
                visit(item.this, env)
            else:
                level.add(visible_name(item), None)

    def walk(node, level: _Level, env: list[_Level], skip: set[int], *, unqualified: bool = True) -> None:
        scoped = [*env, level]
        for kind, child in own(node, skip):
            if kind == "query":
                visit(child, scoped)
            else:
                resolve(child, scoped, unqualified=unqualified)

    def ctes_of(node, env: list[_Level]) -> None:
        with_ = node.args.get("with_")
        for cte in with_.expressions if with_ is not None else ():
            visit(cte.this, env)

    def target_level(target) -> tuple[_Level, tuple[str, ...] | None]:
        level = _Level()
        parts = _table_parts(target)
        if parts is not None and len(parts) == 1 and parts[0].lower() in ctes:
            parts = None
        level.add(visible_name(target), parts)
        return level, parts

    def visit(node, env: list[_Level]) -> None:
        if isinstance(node, exp.Subquery):
            visit(node.this, env)
        elif isinstance(node, exp.SetOperation):
            ctes_of(node, env)
            visit(node.left, env)
            visit(node.right, env)
            # A set operation's own ORDER BY names output columns: not checked.
        elif isinstance(node, exp.Select):
            ctes_of(node, env)
            level = _Level()
            skip: set[int] = set()
            from_items(node, level, env, skip)
            level.outputs = _output_names(node)
            walk(node, level, env, skip)
        elif isinstance(node, exp.Insert):
            ctes_of(node, env)
            target = node.this.this if isinstance(node.this, exp.Schema) else node.this
            if not isinstance(target, exp.Table):
                return
            level, parts = target_level(target)
            names = list(node.this.expressions) if isinstance(node.this, exp.Schema) else []
            alias = target.args.get("alias")
            if alias is not None:
                names.extend(alias.args.get("columns") or ())  # `INSERT INTO t AS a (x)`
            for name in names:
                record(parts, name)
            if node.expression is not None:
                visit(node.expression, env)
            conflict = node.args.get("conflict")
            if conflict is not None:
                for key in conflict.args.get("conflict_keys") or ():
                    record(parts, key if isinstance(key, exp.Identifier) else getattr(key, "this", None))
                skip = set()
                for assignment in conflict.expressions:
                    if isinstance(assignment, exp.EQ) and isinstance(assignment.this, exp.Column) \
                            and assignment.this.args.get("table") is None:
                        record(parts, assignment.this.this)
                        skip.add(id(assignment.this))
                # Only `target.col` on the right-hand side: `excluded.col` is not the table.
                walk(conflict, level, env, skip, unqualified=False)
            returning = node.args.get("returning")
            if returning is not None:
                walk(returning, level, env, set())
        elif isinstance(node, exp.Update):
            ctes_of(node, env)
            if not isinstance(node.this, exp.Table):
                return
            level, parts = target_level(node.this)
            skip = {id(node.this)}
            for assignment in node.expressions:
                if isinstance(assignment, exp.EQ) and isinstance(assignment.this, exp.Column) \
                        and assignment.this.args.get("table") is None:
                    record(parts, assignment.this.this)
                    skip.add(id(assignment.this))
            from_items(node, level, env, skip)
            walk(node, level, env, skip)
        elif isinstance(node, exp.Delete):
            ctes_of(node, env)
            if not isinstance(node.this, exp.Table):
                return
            level, _ = target_level(node.this)
            skip = {id(node.this)}
            from_items(node, level, env, skip)
            walk(node, level, env, skip)
        elif isinstance(node, exp.Merge):
            ctes_of(node, env)
            if not isinstance(node.this, exp.Table):
                return
            level, parts = target_level(node.this)
            skip = {id(node.this)}
            using = node.args.get("using")
            if using is not None:
                skip.add(id(using))
                if isinstance(using, exp.Table):
                    level.add(visible_name(using), physical(using))
                else:
                    level.add(visible_name(using), None)
                    visit(using.this if isinstance(using, exp.Subquery) else using, env)
            for when in node.find_all(exp.When):
                then = when.args.get("then")
                if isinstance(then, exp.Update):
                    for assignment in then.expressions:
                        if isinstance(assignment, exp.EQ) and isinstance(assignment.this, exp.Column) \
                                and assignment.this.args.get("table") is None:
                            record(parts, assignment.this.this)
                            skip.add(id(assignment.this))
                elif isinstance(then, exp.Insert) and isinstance(then.this, exp.Tuple):
                    for column in then.this.expressions:
                        if isinstance(column, exp.Column) and column.args.get("table") is None:
                            record(parts, column.this)
                        skip.add(id(column))
            # WHEN clauses are not nested queries here; only qualified names resolve.
            for column in node.find_all(exp.Column):
                if id(column) not in skip and not column.find_ancestor(exp.Subquery):
                    resolve(column, [*env, level], unqualified=False)

    visit(expression, [])
    return [ref for _, ref in sorted(out, key=lambda item: item[0])]


def record_statement(graph: Graph, source: str, location: str, expression) -> None:
    """Column references and DDL from one parsed statement. Never raises: this is an
    advisory check layered over table extraction, and a statement it cannot read is
    simply not checked."""
    from sqlglot import exp
    try:
        _record_ddl(graph, expression, location)
        if isinstance(expression, (exp.Query, exp.Insert, exp.Update, exp.Delete, exp.Merge)):
            state = facts(graph)
            for table, column, written, fallbacks in _column_refs(expression):
                state.refs.append(ColumnRef(source, location, table, column, written, fallbacks))
    except Exception:  # noqa: BLE001 - see docstring; RecursionError included
        return


# ── recording DDL ────────────────────────────────────────────────────────────────
_LEX_CREATE = re.compile(rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL|TEMP|TEMPORARY|UNLOGGED|FOREIGN|MATERIALIZED)\s+)*"
                         rf"(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<t>{_IDENT})", re.I)
_LEX_ALTER = re.compile(rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<t>{_IDENT})\s*\*?(?P<rest>[^;]*)", re.I | re.S)
_LEX_ADD = re.compile(rf"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?P<c>{_NAME})", re.I)
_LEX_RENAME = re.compile(rf"\bRENAME\s+(?:COLUMN\s+)?(?P<old>{_NAME})\s+TO\s+(?P<new>{_NAME})", re.I)
_NOT_COLUMN_ADD = frozenset({"constraint", "primary", "unique", "foreign", "check", "exclude", "generated", "column"})

# ── DDL built at run time ────────────────────────────────────────────────────────
_LITERAL = re.compile(r"(?P<q>'(?:[^']|'')*')|\$(?P<tag>(?:[A-Za-z_]\w*)?)\$(?P<d>.*?)\$(?P=tag)\$", re.S)
_CODE_BODY = re.compile(r"\$(?P<tag>(?:[A-Za-z_]\w*)?)\$(?P<d>.*?)\$(?P=tag)\$", re.S)
_FORMAT = re.compile(r"\bformat\s*\(\s*(?P<f>'(?:[^']|'')*')", re.I)
_HOLE = "\x00"
_DYNAMIC_TARGET = re.compile(rf"\b(?P<verb>ALTER|CREATE)\s+(?:(?:GLOBAL|LOCAL|TEMP|TEMPORARY|UNLOGGED)\s+)*TABLE\s+"
                             rf"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?(?P<t>{_IDENT}(?=[\s(*;]|$)|\S*)", re.I)


def _format_args(text: str, start: int) -> tuple[list[str], int]:
    """Top-level comma-separated arguments from `start` to the closing `)`, and its end."""
    args, depth, current, i = [], 0, start, start
    while i < len(text):
        char = text[i]
        if char == "'":
            end = i + 1
            while end < len(text) and not (text[end] == "'" and not text.startswith("''", end)):
                end += 2 if text.startswith("''", end) else 1
            i = end + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                args.append(text[current:i])
                return [a.strip() for a in args if a.strip()], i + 1
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[current:i])
            current = i + 1
        i += 1
    return [a.strip() for a in args if a.strip()], len(text)


def _formatted(segment: str) -> str:
    """`format('ALTER TABLE %I …', 'orders')` as the literal it builds; a non-literal argument is a hole."""
    match = _FORMAT.search(segment)
    if not match:
        return segment
    args, end = _format_args(segment, match.end())
    values = iter(args)
    literal = re.compile(r"'((?:[^']|'')*)'")

    def fill(spec: re.Match) -> str:
        if spec.group(0) == "%%":
            return "%"
        if "$" in spec.group(0):
            return _HOLE  # positional arguments are not followed
        value = literal.fullmatch(next(values, "") or "")
        return value.group(1).replace("''", "'") if value else _HOLE
    built = re.sub(r"%%|%(?:\d+\$)?-?\d*[sIL]", fill, match.group("f")[1:-1].replace("''", "'"))
    return segment[:match.start()] + "'" + built.replace("'", "''") + "'" + segment[end:]


def _built_text(segment: str) -> str:
    """The SQL text a PL/pgSQL expression assembles: literal pieces joined, anything computed a hole."""
    segment = _formatted(segment)
    pieces, last = [], 0
    for match in _LITERAL.finditer(segment):
        if segment[last:match.start()].strip() not in {"", "||"}:
            pieces.append(_HOLE)
        pieces.append(match.group("q")[1:-1].replace("''", "'") if match.group("q") is not None else match.group("d"))
        last = match.end()
    if segment[last:].strip() not in {"", "||"}:
        pieces.append(_HOLE)
    return "".join(pieces)


def _record_dynamic_ddl(state: SqlFacts, text: str, path: str) -> None:
    """DDL in string literals of code that runs `EXECUTE`: the named table is reshaped; an
    `ALTER TABLE` whose target is computed (`%I`, `|| t ||`) taints every declared column set."""
    # A dollar-quoted body holding `;` is code (a DO block or function), not a value.
    code = _CODE_BODY.sub(lambda m: " " + m.group("d") + " " if ";" in m.group("d") else m.group(0), text)
    masked = _LITERAL.sub(lambda m: re.sub(r"[^\n]", "_", m.group(0)), code)
    if not re.search(r"\bEXECUTE\b", masked, re.I):
        return
    start = 0
    for end in [m.start() for m in re.finditer(";", masked)] + [len(code)]:
        segment = code[start:end]
        start = end + 1
        if not re.search(r"\b(?:ALTER|CREATE)\b", segment, re.I) or not _LITERAL.search(segment):
            continue
        for match in _DYNAMIC_TARGET.finditer(_built_text(segment)):
            target = match.group("t")
            if target and _HOLE not in target and "%" not in target and re.fullmatch(_IDENT, target):
                parts = _lexical_parts(target)
                state.ddl.append(("reshaped" if match.group("verb").upper() == "ALTER" else "unknown", parts, path))
            elif match.group("verb").upper() == "ALTER":
                state.dynamic_ddl.add(path)


def _record_ddl(graph: Graph, expression, location: str = "") -> None:
    from sqlglot import exp
    ddl = None
    path = _path(location)
    if isinstance(expression, exp.Create):
        kind = str(expression.args.get("kind") or "").upper()
        if kind in {"FUNCTION", "PROCEDURE"}:
            body = expression.expression
            record_text(graph, body.name if isinstance(body, exp.Expression) else str(body or ""), location)
            return
        if kind not in {"TABLE", "VIEW"}:
            return
        schema = expression.this
        table = schema.this if isinstance(schema, exp.Schema) else schema
        parts = _table_parts(table)
        if parts is None:
            return
        ddl = facts(graph).ddl
        if kind == "TABLE":
            _touched(graph, location, parts)
            if len(parts) == 1 and path in facts(graph).search_path:
                # `SET search_path TO app; CREATE TABLE t (…)` creates app.t. Statements are
                # recorded in file order, so only a CREATE after the file's SET is redirected.
                ddl.append(("create", parts, None, path))
                return
        properties = expression.args.get("properties")
        derived = (kind != "TABLE" or not isinstance(schema, exp.Schema) or expression.expression is not None
                   or (properties is not None and any(isinstance(p, (exp.InheritsProperty, exp.PartitionedOfProperty, exp.LikeProperty))
                                                      for p in properties.expressions))
                   or any(isinstance(item, exp.LikeProperty) for item in schema.expressions))
        if derived:
            ddl.append(("create", parts, None, path))
            return
        columns = []
        for item in schema.expressions:
            if isinstance(item, exp.ColumnDef) and isinstance(item.this, exp.Identifier):
                columns.append(_fold(item.this))
        ddl.append(("create", parts, frozenset(columns), path))
    elif isinstance(expression, exp.Alter):
        if str(expression.args.get("kind") or "").upper() != "TABLE":
            return
        parts = _table_parts(expression.this)
        if parts is None:
            return
        ddl = facts(graph).ddl
        _touched(graph, location, parts)
        for action in expression.args.get("actions") or ():
            if isinstance(action, exp.ColumnDef) and isinstance(action.this, exp.Identifier):
                ddl.append(("add", parts, _fold(action.this), path))
            elif isinstance(action, exp.RenameColumn):
                renamed = action.args.get("to")
                renamed = renamed.this if isinstance(renamed, exp.Column) else renamed
                if isinstance(renamed, exp.Identifier):
                    ddl.append(("add", parts, _fold(renamed), path))
                else:
                    ddl.append(("reshaped", parts, path))
            elif isinstance(action, exp.AlterRename):
                ddl.append(("reshaped", parts, path))
                if (renamed := _table_parts(action.this)) is not None:
                    ddl.append(("reshaped", renamed, path))


def record_text(graph: Graph, text: str, location: str = "") -> None:
    """DDL read lexically: a statement the parser kept as text (`ALTER TABLE t ADD COLUMN
    IF NOT EXISTS x`), a DO block or a function body. A table created there is unknown;
    added and renamed columns are kept, since keeping them can only prevent a report."""
    try:
        if not text:
            return
        state = facts(graph)
        path = _path(location)
        _record_dynamic_ddl(state, text, path)
        for match in _LEX_CREATE.finditer(text):
            state.ddl.append(("unknown", _lexical_parts(match.group("t")), path))
            _touched(graph, location, _lexical_parts(match.group("t")))
        for match in _LEX_ALTER.finditer(text):
            parts = _lexical_parts(match.group("t"))
            _touched(graph, location, parts)
            rest = match.group("rest")
            for add in _LEX_ADD.finditer(rest):
                name = _lexical_parts(add.group("c"))[0]
                if name.lower() not in _NOT_COLUMN_ADD or add.group("c").startswith('"'):
                    state.ddl.append(("add", parts, name, path))
            for rename in _LEX_RENAME.finditer(rest):
                state.ddl.append(("add", parts, _lexical_parts(rename.group("new"))[0], path))
            if re.search(r"\bRENAME\s+TO\b", rest, re.I):
                state.ddl.append(("reshaped", parts, path))
    except Exception:  # noqa: BLE001 - advisory
        return


# ── the schema a project declares ────────────────────────────────────────────────
@dataclass(slots=True)
class _Table:
    columns: frozenset[str] | None
    origin: str  # "prisma" or "sql"
    model: str = ""
    #: Prisma field name -> column.
    fields: dict[str, str] = field(default_factory=dict)


_PRISMA_BLOCK = re.compile(r"^[ \t]*(model|view|enum|type)\s+(\w+)\s*\{(.*?)^[ \t]*\}", re.S | re.M)
_PRISMA_PROVIDER = re.compile(r'datasource\s+\w+\s*\{[^}]*?\bprovider\s*=\s*"([\w-]+)"', re.S)
_PRISMA_FIELD = re.compile(r"^\s*(\w+)\s+(Unsupported\s*\([^)]*\)|\w+)\s*(\[\])?\s*(\?)?(.*)$")
_PRISMA_MAP = re.compile(r'@map\(\s*(?:name\s*:\s*)?"([^"]+)"')
_PRISMA_COMMENT = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.S)


def strip_prisma_comments(text: str) -> str:
    """Prisma schema text with `//` comments blanked; strings, offsets and newlines kept.

    Prisma has only `//` and `///` line comments. `/* … */` is not Prisma syntax (the
    formatter rejects it); it is blanked too, which can only hide text that is not a
    valid declaration anyway."""
    return _PRISMA_COMMENT.sub(lambda m: m.group(0) if m.group(0).startswith('"') else re.sub(r"[^\n]", " ", m.group(0)), text)


_strip_prisma_comments = strip_prisma_comments

# ── scope: packages and test code ────────────────────────────────────────────────
_PACKAGE_MARKERS = ("package.json", "pyproject.toml", "setup.cfg")
_TEST_DIRS = TEST_DIRS  # the shared rule, `core.files.is_test_path`


class PackageRoots:
    """File path -> nearest ancestor directory holding package.json, pyproject.toml or
    setup.cfg ("" for the repository root). A monorepo's packages keep separate schemas."""

    def __init__(self, state) -> None:
        self._root = state.root
        self._cache: dict[str, str] = {}

    def of(self, path: str) -> str:
        parent = PurePosixPath(path).parent.as_posix()
        return self._directory("" if parent == "." else parent)

    def _directory(self, directory: str) -> str:
        if directory in self._cache:
            return self._cache[directory]
        if not directory:
            found = ""
        elif any((self._root / directory / marker).is_file() for marker in _PACKAGE_MARKERS):
            found = directory
        else:
            parent = PurePosixPath(directory).parent.as_posix()
            found = self._directory("" if parent == "." else parent)
        self._cache[directory] = found
        return found


def prisma_schema_sets(state, roots: PackageRoots | None = None) -> dict[str, tuple[list[str], bool]]:
    """Package root -> (the Prisma schema files that package uses, whether no selection
    rule matched and every schema file there is used). Test fixtures are never used."""
    roots = roots or PackageRoots(state)
    groups: dict[str, dict[str, str]] = {}
    for rel, text in state.prisma_schemas:
        if not is_test_path(rel):
            groups.setdefault(roots.of(rel), {})[rel] = text
    sets = {}
    for root, schemas in sorted(groups.items()):
        selected = _schema_selection(state, schemas, root, roots)
        sets[root] = (sorted(schemas), True) if selected is None else (selected, False)
    return sets


def _schema_selection(state, schemas: dict[str, str], package: str = "", roots: PackageRoots | None = None) -> list[str] | None:
    """The Prisma schema files one package uses, or None when no rule identifies them."""
    from .source import read_source

    def under(base: str, target: str) -> list[str]:
        path = PurePosixPath(base, target).as_posix() if base else PurePosixPath(target).as_posix()
        path = re.sub(r"(^|/)\./", r"\1", path).rstrip("/")
        return [rel for rel in schemas if rel == path or rel.startswith(path + "/")]

    declared: list[str] = []
    configs = sorted(rel for rel in state.admitted_paths
                     if PurePosixPath(rel).name in {"package.json", "prisma.config.ts", "prisma.config.mts",
                                                    "prisma.config.js", "prisma.config.mjs", "prisma.config.cjs"}
                     and (roots is None or roots.of(rel) == package))
    for rel in configs:
        source = read_source(state.root, state.root / rel, state.config.max_file_bytes)
        if source.text is None:
            continue
        base = PurePosixPath(rel).parent.as_posix()
        base = "" if base == "." else base
        target = None
        if rel.endswith("package.json"):
            try:
                prisma = json.loads(source.text).get("prisma")
            except (ValueError, AttributeError):
                prisma = None
            if isinstance(prisma, dict) and isinstance(prisma.get("schema"), str):
                target = prisma["schema"]
        elif match := re.search(r"\bschema\s*:\s*(['\"`])([^'\"`$]+)\1", source.text):
            target = match.group(2)
        if target and not PurePosixPath(target).is_absolute() and ".." not in PurePosixPath(target).parts:
            declared.extend(under(base, target))
    if declared:
        return sorted(set(declared))
    conventional = [rel for rel in schemas if PurePosixPath(rel).name == "schema.prisma"
                    and PurePosixPath(rel).parent.name != "schema"]
    if conventional:
        return conventional
    folders = [rel for rel in schemas if PurePosixPath(rel).parent.name == "schema"
               and PurePosixPath(rel).parent.parent.name == "prisma"]
    return folders or None


def _prisma_tables(schemas: dict[str, str], files: list[str]) -> dict[tuple[str | None, str], _Table]:
    """Tables the given Prisma schema files declare; a table they disagree on has unknown columns."""
    if not files:
        return {}
    providers = {m.group(1) for rel in files for m in _PRISMA_PROVIDER.finditer(_strip_prisma_comments(schemas[rel]))}
    if not providers or not providers <= _POSTGRES_PROVIDERS:
        return {}
    blocks = [(match.group(1), match.group(2), match.group(3))
              for rel in files for match in _PRISMA_BLOCK.finditer(_strip_prisma_comments(schemas[rel]))]
    models = {name for kind, name, _ in blocks if kind in {"model", "view", "type"}}
    enums = {name for kind, name, _ in blocks if kind == "enum"}
    tables: dict[tuple[str | None, str], _Table] = {}
    conflicted: set[tuple[str | None, str]] = set()
    for kind, name, body in blocks:
        if kind not in {"model", "view"}:
            continue
        mapped = re.search(r'@@map\(\s*(?:name\s*:\s*)?"([^"]+)"', body)
        schema = re.search(r'@@schema\(\s*"([^"]+)"', body)
        # No `@@schema` is the datasource's default schema; `public` is spelled the same way.
        key = (schema.group(1) if schema and schema.group(1) != "public" else None, mapped.group(1) if mapped else name)
        fields: dict[str, str] = {}
        known = "@@ignore" not in body
        for line in body.splitlines():
            if not line.strip() or line.strip().startswith("@@"):
                continue
            match = _PRISMA_FIELD.match(line)
            if not match:
                continue
            field_name, type_name, _, _, attributes = match.groups()
            if type_name in models or "@relation" in attributes:
                continue  # a relation, not a column
            if not (type_name in _PRISMA_SCALARS or type_name in enums or type_name.startswith("Unsupported")):
                known = False  # a type this reader cannot place: do not guess the columns
            column = _PRISMA_MAP.search(attributes)
            # `@ignore` hides a field from the client; the column still exists.
            fields[field_name] = column.group(1) if column else field_name
        # A view's columns come from its SQL definition, which Prisma does not own: the
        # block lists what the client maps, not what the view returns.
        known = known and kind == "model"
        table = _Table(frozenset(fields.values()) if known else None, "prisma", name, fields)
        if key in tables:
            if tables[key].columns != table.columns:
                conflicted.add(key)
            continue
        tables[key] = table
    for key in conflicted:
        tables[key] = _Table(None, "prisma")
    return tables


def _key(parts: tuple[str, ...]) -> tuple[str | None, str] | None:
    if len(parts) == 1:
        return (None, parts[0])
    if len(parts) == 2:
        return (None if parts[0] == "public" else parts[0], parts[1])
    return None


_Key = tuple[str | None, str]


def _orm_declared(graph: Graph, declared_elsewhere: set[str]) -> set[_Key]:
    """Tables an ORM, Alembic or another extractor also declares. They may carry columns
    this reader never sees (`op.add_column`), so no declared column set is trusted."""
    elsewhere = {graph.nodes[edge.target].label for edge in graph.edges
                 if edge.kind == "TOUCHES_STORE" and edge.origin not in {"sqlglot", "prisma_schema"}
                 and "declares" in (edge.detail or "") and edge.target in graph.nodes
                 and graph.nodes[edge.target].kind == "postgres_table"}
    keys = set()
    for label in elsewhere | declared_elsewhere:
        if (k := _key(_lexical_parts(label) if '"' in label else tuple(label.split(".")))) is not None:
            keys.add(k)
    return keys


def _catalogs(state, recorded: SqlFacts, roots: PackageRoots, orm: set[_Key]) -> dict[str, dict[_Key, _Table]]:
    """Package root -> table key -> declared columns, from Prisma and SQL DDL in that package.

    DDL in test code and fixtures does not declare anything. Prisma wins over CREATE TABLE
    for the same table, but columns ALTER TABLE adds (a Prisma migration's raw SQL) are
    added to the model's. A table renamed or altered by run-time DDL, declared by another
    ORM, or in a repository with run-time DDL whose target cannot be read, is unknown.

    Only what CREATE declares is per package. Packages of one repository often share a
    database, so an ALTER TABLE, a run-time reshape or untargeted dynamic DDL anywhere
    applies to every package: each of those can only suppress a report, never add one."""
    created: dict[str, dict[_Key, set[str] | None]] = {}
    added: dict[_Key, set[str]] = {}
    unknown: dict[str, set[_Key]] = {}
    reshaped: set[_Key] = set()
    for entry in recorded.ddl:
        kind, k, path = entry[0], _key(entry[1]), entry[-1]
        if k is None:
            continue
        root = roots.of(path)
        if kind == "create" and not is_test_path(path):
            # An unqualified CREATE under a role or database default search_path does not
            # declare the default schema's table (a file's own SET is applied as it is recorded).
            redirected = len(entry[1]) == 1 and "" in recorded.search_path
            if redirected or entry[2] is None or created.get(root, {}).get(k, set()) is None:
                created.setdefault(root, {})[k] = None
            else:
                created.setdefault(root, {}).setdefault(k, set()).update(entry[2])
        elif kind == "add" and not is_test_path(path):
            added.setdefault(k, set()).add(entry[2])
        elif kind == "unknown":
            unknown.setdefault(root, set()).add(k)
        elif kind == "reshaped":
            reshaped.add(k)
    # Run-time DDL whose target cannot be read, anywhere but test code (which declares nothing).
    tainted = any(not is_test_path(path) for path in recorded.dynamic_ddl)

    def untrusted(k: _Key) -> bool:
        return tainted or k in orm or k in reshaped

    catalogs: dict[str, dict[_Key, _Table]] = {}
    for root, tables in created.items():
        for k, columns in tables.items():
            known = columns is not None and k not in unknown.get(root, ()) and not untrusted(k)
            catalogs.setdefault(root, {})[k] = _Table(frozenset(columns | added.get(k, set())) if known else None, "sql")
    schemas = dict(state.prisma_schemas)
    for root, (files, _) in prisma_schema_sets(state, roots).items():
        for k, table in _prisma_tables(schemas, files).items():
            if table.columns is not None:
                columns = None if untrusted(k) else table.columns | added.get(k, set())
                table = _Table(columns, "prisma", table.model, table.fields)
            catalogs.setdefault(root, {})[k] = table
    return catalogs


def _lookup(catalog: dict[_Key, _Table], parts: tuple[str, ...]) -> _Table | None:
    """The table a reference names. An unqualified name is the default schema's table only:
    `pg_schemas` lists schemas the project uses, not the connection's search_path."""
    table = catalog.get(_key(parts)) if len(parts) <= 2 else None
    return table if table is not None and table.columns is not None else None


# ── tables other ORMs and migration tools reshape, read lexically ────────────────
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_QUOTED_TABLE = r"""(?P<q>['"`])(?P<t>[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)(?P=q)"""
_ORM_DDL = {
    "js": [re.compile(pattern) for pattern in (
        # Knex `schema.createTable/alterTable/table('t')`, Sequelize and TypeORM
        # `addColumn('t', …)`, `renameColumn`, `changeColumn`, `createTable('t')`.
        rf"\b(?:alterTable|createTable|createTableIfNotExists|createTableLike|renameTable|addColumns?|changeColumn|"
        rf"renameColumn|removeColumn)\s*\(\s*(?:\{{[^{{}}]*?\btableName\s*:\s*)?{_QUOTED_TABLE}",
        rf"\bschema\s*(?:\.\s*withSchema\s*\([^)]*\)\s*)?\.\s*table\s*\(\s*{_QUOTED_TABLE}",
        rf"\bnew\s+Table\s*\(\s*\{{[^{{}}]*?\bname\s*:\s*{_QUOTED_TABLE}",
        rf"\btableName\s*:\s*{_QUOTED_TABLE}",
    )],
    # Django `class Meta: db_table = "t"`.
    "py": [re.compile(rf"\bdb_table\s*=\s*[rRuU]?{_QUOTED_TABLE}")],
}
_ORM_DDL_WORDS = {"js": ("Table", "Column", "tableName", "table("), "py": ("db_table",)}


def _orm_ddl_tables(state) -> tuple[set[str], bool]:
    """Bare table names (lower case) that Knex, Sequelize, TypeORM or Django code creates,
    alters or maps, and whether any JS/Python file sets `search_path` (a connection hook
    or `-c search_path=` option applies to every query, so it is not per file)."""
    from .source import read_source
    names: set[str] = set()
    search_path = False
    for rel in sorted(state.admitted_paths):
        suffix = PurePosixPath(rel).suffix.lower()
        language = "js" if suffix in _JS_SUFFIXES else "py" if suffix == ".py" else None
        if language is None:
            continue
        try:
            text = read_source(state.root, state.root / rel, state.config.max_file_bytes).text
        except OSError:
            continue
        if not text:
            continue
        if not search_path and not is_test_path(rel) and "search_path" in text and _code_sets_search_path(text, language):
            search_path = True
        if not any(word in text for word in _ORM_DDL_WORDS[language]):
            continue
        for pattern in _ORM_DDL[language]:
            names.update(match.group("t").rsplit(".", 1)[-1].lower() for match in pattern.finditer(text))
    return names, search_path


# ── schema changes in languages this scanner does not read ───────────────────────
# Rails, Laravel, EF Core, Ecto, goose/Flyway Java and Go migrations, Liquibase changelogs:
# a CREATE TABLE catalog read from SQL is incomplete when one of these reshapes the table.
_FOREIGN_CODE_SUFFIXES = frozenset({".rb", ".go", ".rs", ".java", ".kt", ".kts", ".scala", ".groovy", ".cs", ".fs",
                                    ".php", ".ex", ".exs", ".clj", ".swift", ".dart", ".lua", ".pl", ".pm"})
_FOREIGN_DATA_SUFFIXES = frozenset({".xml", ".yaml", ".yml", ".json"})
_CHANGELOG_PATH = re.compile(r"changelog|changeset|liquibase|flyway|migrat", re.I)
_FOREIGN_SIGNAL = re.compile(
    r"\b(?:ALTER|CREATE)\s+TABLE\b|\bADD\s+COLUMN\b|\b(?:add_column|rename_column|change_column|add_reference|add_belongs_to|"
    r"add_timestamps|change_table|create_table|rename_table)\b|Schema::(?:table|create|rename)\b|"
    r"\bmigrationBuilder\b|\b(?:alter|create|create_if_not_exists)\s+table\s*\(|\b(?:addColumn|renameColumn|createTable)\b", re.I)
_FOREIGN_SQL_TARGET = re.compile(r"\b(?:ALTER|CREATE)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?"
                                 r"(?:[`\"\[]?[A-Za-z_][\w$]*[`\"\]]?\s*\.\s*)?[`\"\[]?(?P<t>[A-Za-z_][\w$]*)?", re.I)
# What follows `ALTER TABLE ` when the name is computed: a format placeholder, an
# interpolation, or the end of a string literal joined to a value.
_COMPUTED_TARGET = re.compile(r"""\s*(?:%[sIiv]|\$?\{|#\{|\\\(|\$[A-Za-z_]|\?|[`"']?\s*(?:\+|\.\s|\|\||&|,))""")
_STRICT_CHANGELOG_PATH = re.compile(r"changelog|changeset|liquibase|flyway", re.I)
_FOREIGN_NAMES = [re.compile(pattern) for pattern in (
    r"\b(?:add_column|remove_column|rename_column|change_column(?:_default|_null)?|add_reference|add_belongs_to|"
    r"add_timestamps|remove_timestamps|change_table|create_table|rename_table|add_index)\s*\(?\s*[:\"'](?P<t>[A-Za-z_]\w*)",
    r"Schema::(?:table|create|rename)\s*\(\s*['\"](?P<t>[A-Za-z_]\w*)",
    r"\b(?:table|name)\s*:\s*\"(?P<t>[A-Za-z_]\w*)\"",
    r"\b(?:alter|create|create_if_not_exists|rename)\s+table\s*\(\s*[:\"](?P<t>[A-Za-z_]\w*)",
    r"\btableName\s*[=:]\s*[\"']?(?P<t>[A-Za-z_]\w*)",
)]


def _foreign_ddl_tables(state) -> set[str] | None:
    """Bare table names (lower case) that source this scanner does not parse creates or
    alters, or None when such a file changes a table whose name cannot be read (a
    computed `ALTER TABLE %s`, an unreadable migration, a migration or changelog whose
    table is not named literally): then no DDL catalog is trusted. A signal word with no
    readable table outside a migration (UI copy, a comment, a query builder) is ignored.

    Lexical and bounded: files by suffix under the scan's own exclusions, at most
    `max_files` of them, each read up to `max_file_bytes`."""
    from dataclasses import replace
    from itertools import islice

    from .scanner import iter_source_files
    from .source import read_source
    config = replace(state.config, extensions=set(_FOREIGN_CODE_SUFFIXES | _FOREIGN_DATA_SUFFIXES))
    names: set[str] = set()
    for path in islice(iter_source_files(state.root, config), state.config.max_files):
        rel = path.relative_to(state.root).as_posix()
        suffix = path.suffix.lower()
        if is_test_path(rel) or (suffix in _FOREIGN_DATA_SUFFIXES and not _CHANGELOG_PATH.search(rel)):
            continue
        try:
            text = read_source(state.root, path, state.config.max_file_bytes).text
        except OSError:
            text = None
        if text is None:
            if is_migration_path(rel) or _CHANGELOG_PATH.search(rel):
                return None  # a migration that could not be read
            continue
        if not _FOREIGN_SIGNAL.search(text):
            continue
        found: set[str] = set()
        for match in _FOREIGN_SQL_TARGET.finditer(text):
            if match.group("t"):
                found.add(match.group("t").lower())
            elif match.group(0).lstrip()[:5].upper() == "ALTER" and _COMPUTED_TARGET.match(text, match.end()):
                return None  # `ALTER TABLE %s`, `ALTER TABLE " + name`: any table may change
            # Otherwise prose ("Create table" on a button) or a computed CREATE, which makes a
            # new table and changes no declared one.
        for pattern in _FOREIGN_NAMES:
            found.update(match.group("t").lower() for match in pattern.finditer(text))
        if not found and (is_migration_path(rel) or _STRICT_CHANGELOG_PATH.search(rel)):
            return None  # a migration whose table cannot be read (`create_table table_name`)
        names |= found
    return names


def is_migration_path(path: str) -> bool:
    """True for a file under a migrations directory or an Alembic-style `versions/` directory.

    `check_columns` does not report column references from these files."""
    parts = [part.lower() for part in PurePosixPath(path).parts[:-1]]
    if any(part in _MIGRATION_DIRS for part in parts):
        return True
    return "versions" in parts and any("alembic" in part or "migration" in part for part in parts)


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()


def _hint(table: _Table, written: str, column: str) -> tuple[str, str | None]:
    """`(kind, column)`: the declared column the reference most likely means, and why."""
    bare = written[1:-1].replace('""', '"') if written.startswith('"') else written
    if table.origin == "prisma":
        for exact in (True, False):
            for field_name, mapped in table.fields.items():
                if (field_name == bare if exact else field_name.lower() == bare.lower()) and mapped != column:
                    return "prisma", mapped
    columns = table.columns or frozenset()
    exact_case = [c for c in columns if c.lower() == column.lower() and c != column]
    if len(exact_case) == 1:
        return "case", exact_case[0]
    snake = [c for c in columns if c == _snake(bare) or _snake(c) == _snake(bare)]
    if len(snake) == 1 and snake[0] != column:
        return "similar", snake[0]
    return "", None


_MAX_NAMES = 5
_MAX_TABLES = 3


def _segment(table_name: str, table: _Table, refs: list[ColumnRef], first: bool) -> tuple[str, list[str]]:
    """One table's part of the message, and the declared columns it points to."""
    hints = [_hint(table, ref.written, ref.column) for ref in refs]
    names = [ref.written for ref in refs]
    kinds = {kind for kind, _ in hints}
    uniform = len(kinds) == 1 and "" not in kinds
    shown = []
    for name, (kind, better) in list(zip(names, hints, strict=True))[:_MAX_NAMES]:
        if better and not uniform:
            name = f"{name} ({_quote(better)}{'?' if kind == 'similar' else ''})"
        shown.append(name)
    if len(names) > _MAX_NAMES:
        shown.append(f"and {len(names) - _MAX_NAMES} more")
    many = len(names) > 1
    noun = ("Columns" if many else "Column") if first else ("columns" if many else "column")
    text = f"{noun} {', '.join(shown)} {'do' if many else 'does'} not exist on {table_name}"
    betters = [better for _, better in hints if better]
    if uniform:
        joined = ", ".join(_quote(b) for b in betters[:_MAX_NAMES]) + (", …" if len(betters) > _MAX_NAMES else "")
        text += {"prisma": f" (Prisma maps {'them' if many else 'it'} to {joined})",
                 "case": f" (declared as {joined}; quoted names are case-sensitive)",
                 "similar": f" (did you mean {joined}?)"}[kinds.pop()]
    elif not betters:
        text += " (per the Prisma schema)" if table.origin == "prisma" else " (per CREATE TABLE DDL)"
    return text, betters


def check_columns(state) -> None:
    """Report SQL column references that the declared schema says do not exist: one
    issue per SQL location, listing every unknown column it references."""
    graph = state.graph
    recorded = graph.sql_facts
    if recorded is None or not recorded.refs:
        return
    # ORM models resolved after this pass are known by name already.
    models = {model[1] for model in state.py_models.values() if model and model[0] == "postgres_table"}
    models |= {getattr(model, "name", "") for model in state.js_models.values()
               if getattr(model, "kind", "") == "postgres_table"}
    roots = PackageRoots(state)
    catalogs = _catalogs(state, recorded, roots, _orm_declared(graph, models))
    if not catalogs:
        return
    reshaped = {path: {_key(parts) for parts in tables} for path, tables in recorded.ddl_files.items()}
    candidates: list[tuple[ColumnRef, _Table]] = []
    for ref in recorded.refs:
        path = _path(ref.location)
        if is_migration_path(path) or is_test_path(path) or ref.column in SYSTEM_COLUMNS:
            continue  # a test may build its own tables, or assert that a column is missing
        if _key(ref.table) in reshaped.get(path, ()):
            continue  # this file creates or alters the table itself
        catalog = catalogs.get(roots.of(path))
        if not catalog:
            continue  # a schema declared in another package is not this package's
        table = _lookup(catalog, ref.table)
        if table is None or ref.column in table.columns:
            continue
        if any(outer is None or (other := _lookup(catalog, outer)) is None or ref.column in other.columns
               for outer in ref.fallbacks):
            continue
        candidates.append((ref, table))
    if not candidates:
        return
    # Read only when there is something to report: other ORMs' DDL is found lexically.
    reshaped_by_code, code_search_path = _orm_ddl_tables(state)
    foreign = _foreign_ddl_tables(state) if any(table.origin == "sql" for _, table in candidates) else set()
    search_path = code_search_path or "" in recorded.search_path

    def redirected(ref: ColumnRef) -> bool:
        """Could `search_path` make an unqualified name in this reference another table?"""
        if len(ref.table) > 1 and all(outer is None or len(outer) > 1 for outer in ref.fallbacks):
            return False
        return search_path or _path(ref.location) in recorded.search_path
    # location -> table display -> (table, refs); insertion order is scan order.
    grouped: dict[str, dict[str, tuple[_Table, list[ColumnRef]]]] = {}
    sources: dict[str, list[str]] = {}
    for ref, table in candidates:
        if ref.table[-1].lower() in reshaped_by_code or redirected(ref):
            continue
        if table.origin == "sql" and (foreign is None or ref.table[-1].lower() in foreign):
            continue  # a migration in a language this scanner does not read may add the column
        tables = grouped.setdefault(ref.location, {})
        _, refs = tables.setdefault(_display(ref.table), (table, []))
        if all(existing.column != ref.column for existing in refs):
            refs.append(ref)
        if ref.source not in sources.setdefault(ref.location, []):
            sources[ref.location].append(ref.source)
    for location, tables in grouped.items():
        parts, betters, subjects = [], [], []
        for index, (name, (table, refs)) in enumerate(tables.items()):
            if index == _MAX_TABLES:
                parts.append(f"and {len(tables) - _MAX_TABLES} more tables")
                break
            text, found = _segment(name, table, refs, index == 0)
            parts.append(text)
            betters.extend(found)
        for name, (_, refs) in tables.items():
            subjects.extend(f"{name}.{ref.column}" for ref in refs)
        folded = next((ref for _, refs in tables.values() for ref in refs
                       if not ref.written.startswith('"') and ref.written != ref.column), None)
        message = "; ".join(parts) + "."
        if folded is not None:
            message += f" Unquoted names fold to lower case ({folded.written} is {folded.column})."
        origins = {table.origin for table, _ in tables.values()}
        declared = "the Prisma schema" if origins == {"prisma"} else "the declared schema"
        unique = list(dict.fromkeys(betters))
        listed = ", ".join(_quote(b) for b in unique[:_MAX_NAMES]) + (", …" if len(unique) > _MAX_NAMES else "")
        recommendation = (f"Use the database column names ({listed}); "
                          "model field names are not column names." if betters
                          else f"Check the columns against {declared}, or update the schema if it is stale.")
        graph.issues.append(Issue("SQL_UNKNOWN_COLUMN", "warning", message, sources[location], location,
                                  recommendation, subject=", ".join(subjects)))
